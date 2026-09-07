# harbor-scanner-ensemble

A [Harbor](https://goharbor.io) scanner adapter that runs **Grype and Trivy
at once** and merges their findings into a single report.

Harbor allows exactly one scanner per project. This adapter works with that
limit instead of against it: Harbor sees one scanner, the gate blocks on the
union of what both engines find, and one CVE allowlist entry covers both.

Findings carry their origin. In Harbor's UI, as a prefix on the description:

```
(*) A malicious SSH peer could send unsolicited …     ← both engines
(G) Improper certificate validation in …              ← Grype only
(T) Denial of service in …                            ← Trivy only
```

Same repository as the single-engine
[harbor-scanner-grype](https://github.com/TechPrototyper/harbor-scanner-grype)?
No — both are thin wirings around
[harbor-scanner-toolkit](https://github.com/TechPrototyper/harbor-scanner-toolkit),
which holds the shared implementation. Use the grype adapter if you want one
engine, this one if you want several.

## Why run two scanners

The same image, scanned twice on the same day:

| | Both engines | Grype only | Trivy only |
|---|---|---|---|
| Grype 0.112, older databases | 94 | 21 | 0 |
| Grype 0.118, current databases | 58 | 1 | 40 |

In the morning Trivy added nothing. In the afternoon it contributed 40
findings Grype missed. **Which scanner sees more is a property of the
database state, not of the scanner** — so picking one and trusting it is a
bet that expires. Running both and taking the union does not.

Severity works the same way. Of 94 findings both engines agreed on, 19 had a
different severity. The merge takes the highest, which is the only safe
direction for a gate:

| CVE | Package | Grype | Trivy | Reported |
|---|---|---|---|---|
| CVE-2026-39834 | golang.org/x/crypto | Critical | Medium | **Critical** |
| CVE-2026-25681 | golang.org/x/net | Medium | High | **High** |

A threshold of "block at Critical" would have let the first one through with
Trivy alone.

## Install

```bash
helm install harbor-scanner-ensemble \
  oci://ghcr.io/techprototyper/charts/harbor-scanner-ensemble \
  --namespace harbor
```

Then register it in Harbor under **Administration → Interrogation Services →
New Scanner**:

* Endpoint: `http://harbor-scanner-ensemble.harbor.svc:8080`
* **Tick "Use internal registry address".** Without it Harbor hands out its
  external address, and Grype refuses the resulting token realm with
  `invalid realm in www-authenticate: … is a private or link-local address`.

A scanner alone blocks nothing. Per project you also want **auto scan on
push**, **prevent vulnerable images from running**, and a severity
threshold. The CVE allowlist is then your exception mechanism, and it now
applies to both engines at once.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_ENGINES` | `grype,trivy` | active engines, comma separated |
| `SCANNER_ENGINE_TIMEOUT` | `5m` | timeout per engine; they run in parallel, so a scan costs the slowest, not the sum |
| `SCANNER_ALLOW_PARTIAL` | `false` | keep a scan successful when an engine fails |
| `SCANNER_PROVENANCE_PREFIX` | `true` | the `(*)`, `(G)`, `(T)` markers |
| `SCANNER_PREFER_CVE` | `true` | report GHSA-only findings under their CVE, so allowlists match |
| `SCANNER_GRYPE_PATH` | `/usr/bin/grype` | Grype binary |
| `SCANNER_TRIVY_PATH` | `/usr/bin/trivy` | Trivy binary |
| `SCANNER_REGISTRY_USE_HTTP` | `false` | plain HTTP to the registry |
| `SCANNER_LOG_LEVEL` | `info` | debug, info, warn, error |

`SCANNER_ALLOW_PARTIAL=false` is deliberate: a gate that silently drops an
engine is worse than one that visibly fails. Turn it on only if you would
rather scan with one engine than not at all.

## Adding a third engine

Implement the toolkit's `Driver` interface and register it. Nothing in the
merge, the provenance markers or the report assumes two engines — the
registry only insists that no two engine names start with the same letter,
since that letter is the marker.

## License

Apache 2.0.
