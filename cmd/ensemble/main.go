// Command ensemble serves the Harbor Pluggable Scanner Adapter API backed
// by several scanning engines at once. It runs every configured engine in
// parallel and merges their findings into one deterministic report, so
// Harbor sees a single scanner while the gate covers the union of what
// all engines find.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/api"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/config"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/engine"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/grype"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/harbor"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/job"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/merge"
	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/trivy"
)

// ensembleEnv is os.Getenv with one changed default: this binary exists to
// run several engines, so an unset SCANNER_ENGINES means both of them
// rather than the toolkit's single-engine default.
func ensembleEnv(key string) string {
	v := os.Getenv(key)
	if key == "SCANNER_ENGINES" && v == "" {
		return "grype,trivy"
	}
	return v
}

func main() {
	cfg, err := config.Load(ensembleEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	logger.Info("starting", "addr", cfg.Addr, "grype", cfg.GrypePath, "log_level", cfg.LogLevel)

	store := job.NewMemoryStore()
	mapperOpts := grype.MapperOptions{PreferCVE: cfg.PreferCVE}
	runner := grype.NewCLIRunner(grype.CLIOptions{
		MapperOptions:   &mapperOpts,
		Path:            cfg.GrypePath,
		Timeout:         cfg.ScanTimeout,
		InsecureSkipTLS: cfg.InsecureSkipTLS,
		UseHTTP:         cfg.UseHTTP,
		DBAutoUpdate:    cfg.DBAutoUpdate,
	})

	// The registry holds every driver the adapter can run; SCANNER_ENGINES
	// selects which of them scan. With a single engine the server keeps
	// the legacy single-runner path (byte-identical reports, no
	// provenance prefixes); with two or more it runs engine.RunAll and
	// folds the results with merge.Merge.
	registry := engine.NewRegistry()
	if err := registry.Register("grype", runner); err != nil {
		fmt.Fprintf(os.Stderr, "register grype: %v\n", err)
		os.Exit(1)
	}
	trivyDriver := trivy.New(trivy.Options{
		Path:        cfg.TrivyPath,
		Timeout:     cfg.EngineTimeout,
		InsecureTLS: cfg.InsecureSkipTLS,
		UseHTTP:     cfg.UseHTTP,
	})
	if err := registry.Register("trivy", trivyDriver); err != nil {
		fmt.Fprintf(os.Stderr, "register trivy: %v\n", err)
		os.Exit(1)
	}
	selected, err := registry.Select(cfg.Engines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	var engines []engine.Named
	if cfg.UseEnginePath() {
		engines = selected
	}

	scanner := harbor.Scanner{Name: "Grype", Vendor: "Anchore"}
	if len(engines) > 0 {
		scanner.Name = api.ScannerName(cfg.Engines)
		scanner.Vendor = "Anchore, Aqua Security"
	}

	var dbUpdatedAt func() time.Time
	if hasEngine(cfg.Engines, "grype") {
		version, dbBuilt, err := runner.Version(context.Background())
		if err != nil {
			logger.Warn("grype version unavailable", "error", err.Error())
		} else {
			scanner.Version = version
			logger.Info("grype ready", "version", version, "db_built_at", dbBuilt.UTC().Format(time.RFC3339))
			if !dbBuilt.IsZero() {
				dbUpdatedAt = func() time.Time { return dbBuilt }
			}
		}
	}

	handler := api.New(api.Options{
		Scanner:       scanner,
		RefreshAfter:  15,
		DBUpdatedAt:   dbUpdatedAt,
		MapperOptions: mapperOpts,
		Logger:        logger,
		Engines:       engines,
		EngineTimeout: cfg.EngineTimeout,
		AllowPartial:  cfg.AllowPartial,
		MergeOptions:  mergeOptions(cfg.ProvenancePrefix),
	}, store, runner)

	if cfg.JobTTL > 0 && cfg.CleanupInterval > 0 {
		go runCleanupTicker(cfg.CleanupInterval, func() int { return store.Cleanup(cfg.JobTTL) }, logger)
	}

	server := &http.Server{Addr: cfg.Addr, Handler: handler}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed; forcing close", "error", err.Error())
			_ = server.Close()
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err.Error())
			os.Exit(1)
		}
	}
	logger.Info("stopped")
}

// logLevel maps SCANNER_LOG_LEVEL (validated by config) to a slog level.
func logLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// hasEngine reports whether names contains name.
func hasEngine(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// mergeOptions returns the merge options for the multi-engine path.
func mergeOptions(provenancePrefix bool) merge.Options {
	opts := merge.NewOptions()
	opts.ProvenancePrefix = provenancePrefix
	return opts
}

// runCleanupTicker removes expired Finished/Failed jobs every interval.
func runCleanupTicker(interval time.Duration, cleanup func() int, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if removed := cleanup(); removed > 0 {
			log.Info("cleaned up jobs", "removed", removed)
		}
	}
}
