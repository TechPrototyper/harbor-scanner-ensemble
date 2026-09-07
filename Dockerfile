# syntax=docker/dockerfile:1

# Stage 1: build the ensemble binary. CGO_ENABLED=0 produces a static
# binary; the only dependency is our own toolkit module.
# golang:1.27: the adapter binary is itself scanned, and the previous
# builder carried 66 findings, one of them critical (CVE-2026-27143,
# fixed in 1.25.9).
FROM golang:1.27 AS builder
# TARGETOS/TARGETARCH are supplied by BuildKit; default to the classic
# builder's linux/amd64 when they are not.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
# The shared implementation lives in harbor-scanner-toolkit, so the module
# cache is the first layer: it only changes when go.mod/go.sum do.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ensemble ./cmd/ensemble

# Stage 2: minimal runtime. Both engine binaries ship verbatim from the
# official images so engine upgrades are image rebuilds only. The init
# containers that pre-warm the vulnerability databases run from this same
# image, so it must carry both binaries.
FROM gcr.io/distroless/static
# the official image keeps the binary at /grype (ENTRYPOINT ["/grype"])
COPY --from=anchore/grype:v0.118.0 /grype /usr/bin/grype
# the official image keeps the binary at /usr/local/bin/trivy
COPY --from=aquasec/trivy:0.74.0 /usr/local/bin/trivy /usr/bin/trivy
COPY --from=builder /out/ensemble /ensemble
ENV SCANNER_GRYPE_PATH=/usr/bin/grype
ENV SCANNER_TRIVY_PATH=/usr/bin/trivy
USER 65532
ENTRYPOINT ["/ensemble"]
