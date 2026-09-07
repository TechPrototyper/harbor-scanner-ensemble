# Work packages are gated by Go build tags listed in .wp (space separated).
TAGS ?= $(shell cat .wp 2>/dev/null)

.PHONY: test vet build lint-chart docker

test: ## run the Go suite for the enabled work packages (what coderplus runs via pytest)
	go test -tags "$(TAGS)" ./...

vet:
	go vet -tags "$(TAGS)" ./...

build:
	CGO_ENABLED=0 go build -o bin/ensemble ./cmd/ensemble

lint-chart:
	helm lint charts/harbor-scanner-ensemble

docker:
	docker build -t harbor-scanner-ensemble:dev .
