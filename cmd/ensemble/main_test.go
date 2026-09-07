package main

import (
	"os"
	"strings"
	"testing"

	"github.com/TechPrototyper/harbor-scanner-toolkit/pkg/config"
)

// This binary exists to run several engines. An operator who deploys it
// without setting SCANNER_ENGINES must get the ensemble, not the
// toolkit's single-engine default.
func TestDefaultsToBothEngines(t *testing.T) {
	t.Setenv("SCANNER_ENGINES", "")
	cfg, err := config.Load(ensembleEnv)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Engines, ","); got != "grype,trivy" {
		t.Fatalf("default engines = %q, want grype,trivy", got)
	}
	if !cfg.UseEnginePath() {
		t.Error("the ensemble must always take the multi-engine path")
	}
}

func TestExplicitEnginesWin(t *testing.T) {
	t.Setenv("SCANNER_ENGINES", "trivy")
	cfg, err := config.Load(ensembleEnv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Engines, ",") != "trivy" {
		t.Fatalf("explicit configuration must win, got %v", cfg.Engines)
	}
	if !cfg.UseEnginePath() {
		t.Error("a single non-grype engine must still use the engine path")
	}
}

func TestOtherKeysUntouched(t *testing.T) {
	t.Setenv("SCANNER_LOG_LEVEL", "debug")
	if ensembleEnv("SCANNER_LOG_LEVEL") != "debug" {
		t.Error("ensembleEnv must pass every other key through unchanged")
	}
	if ensembleEnv("SCANNER_API_ADDR") != os.Getenv("SCANNER_API_ADDR") {
		t.Error("unset keys must stay unset")
	}
}
