#!/bin/bash
# Build the adapter image IN the cluster (Kaniko, namespace harbor) and push it
# to Harbor:  deploy/kaniko-build.sh <tag>   ->  10.1.0.243/platform/harbor-scanner-ensemble:<tag>
# Context = go.mod, cmd/, internal/, pkg/, Dockerfile as tar.gz in a ConfigMap (limit 1 MiB).
# Requires: secret harbor-scanner-ensemble-kaniko-docker-config in ns harbor (robot account).
set -euo pipefail
TAG="${1:?tag missing, e.g. v$(date +%Y.%m.%d)-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
SAFE=$(echo "$TAG" | tr '.' '-' | tr '[:upper:]' '[:lower:]')
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
tar --exclude='*_test.go' --exclude='testdata' -czf "$TMP/context.tar.gz" go.mod go.sum Dockerfile cmd
echo "context: $(du -h "$TMP/context.tar.gz" | cut -f1)"
kubectl -n harbor create configmap harbor-scanner-ensemble-build-context --from-file=context.tar.gz="$TMP/context.tar.gz" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n harbor delete job "harbor-scanner-ensemble-build-$SAFE" --ignore-not-found >/dev/null
sed -e "s#__TAG__#$TAG#g" -e "s#__TAG_SAFE__#$SAFE#g" deploy/kaniko-job.yaml | kubectl apply -f - >/dev/null
echo "job harbor-scanner-ensemble-build-$SAFE started, waiting..."
if kubectl -n harbor wait --for=condition=complete "job/harbor-scanner-ensemble-build-$SAFE" --timeout=1800s >/dev/null 2>&1; then
  echo "BUILD OK: 10.1.0.243/platform/harbor-scanner-ensemble:$TAG"
else
  echo "BUILD FAILED"; kubectl -n harbor logs "job/harbor-scanner-ensemble-build-$SAFE" -c kaniko --tail=60; exit 1
fi
echo "$TAG" > deploy/IMAGE_TAG
