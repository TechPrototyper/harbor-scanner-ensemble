# Building the image

The published image is built by CI (`.github/workflows/release.yml`) and
pushed to `ghcr.io/techprototyper/harbor-scanner-ensemble`.

To build it yourself:

```bash
docker build -t harbor-scanner-ensemble:dev .
```

The Dockerfile pins both engines to a version and copies their binaries out
of the official images, so upgrading an engine is a rebuild, never a
surprise at runtime:

```dockerfile
COPY --from=anchore/grype:v0.118.0        /grype               /usr/bin/grype
COPY --from=aquasec/trivy:0.74.0          /usr/local/bin/trivy /usr/bin/trivy
```

Both paths are asserted by the chart tests. They differ between the two
projects and have moved before; a wrong path produces an image that builds
fine and fails at startup.

## Building inside a cluster

If your build hosts have no Docker daemon, the same Dockerfile builds with
[Kaniko](https://github.com/GoogleContainerTools/kaniko) as a Job: pack
`go.mod`, `go.sum`, `Dockerfile` and `cmd/` into a ConfigMap, mount it, and
point Kaniko at `dir:///workspace`. Push credentials come from a registry
robot account in a `docker-config` secret.
