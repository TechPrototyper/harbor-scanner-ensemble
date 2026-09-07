# Deploying on Kubernetes: what actually went wrong

The chart in this repository works. It works because three separate
deployments failed first, each for a reason that neither `helm lint` nor
`helm template` reports. If you write your own manifests, or adapt this
chart, these are the three you will meet.

Every one of them is now covered by a check in CI, so they cannot ship
again from this repository.

## 1. Two `HOME` entries in one container

**Symptom.** The HelmRelease fails at apply time. The API server rejects
the Deployment; nothing is rolled out and no pod is ever created, so
there are no logs to read.

**Cause.** Both engines need `HOME` pointed at a writable directory, and
the chart had a per-engine env helper for each. With `engines=grype,trivy`
both helpers fired and the adapter container got `HOME` twice.

**Why the usual tools miss it.** `helm lint` checks the chart, not the
object. `helm template` renders the duplicate happily. Only the API
server enforces the constraint that env names are unique per container.

**Fix.** Each container gets exactly one `HOME`, rendered once, pointing
at the writable volume. CI parses the rendered Deployment for *both*
engine configurations and fails on any duplicate env key in any container,
init containers included.

**Rule of thumb.** Before committing a chart change, run `helm template`
with the values your HelmRelease actually sets and read the object, not
the diff. A rendered manifest that a human never looks at is a manifest
the API server reviews for you, at release time.

## 2. The node had no CPU left to give

**Symptom.** The pod sits in `Pending`. `kubectl describe` says
`0/N nodes are available: Insufficient cpu`.

**Cause.** The target node was at 23949m of 24000m in CPU *requests*:
99.8% committed. Actual utilisation was low. Requests are a scheduling
reservation, not a measurement, and the scheduler only looks at the
reservation.

**Fix.** The chart requests `cpu: "0"`. That is not a trick to sneak past
the scheduler. The adapter is idle between scans and the engines are
short bursts; a reservation would claim capacity that is genuinely not
needed, on a cluster where the reservations are already the scarce
resource. Limits still apply. The in-cluster Kaniko build jobs use the
same pattern for the same reason.

**Rule of thumb.** On a cluster that schedules by request, check
`kubectl describe node` for *Allocated resources* before assuming a
Pending pod means the node is busy. Committed and used are different
numbers, and they can be far apart.

## 3. A read-only root filesystem has no `/tmp`

**Symptom.** The `grype-db` init container crashloops:

```
unable to create listing temp file: open /tmp/grype-db-listing977908185: read-only file system
```

Trivy fails the same way, verified against `aquasec/trivy:0.74.0` in the
same pod spec:

```
failed to create a temp dir: mkdir /tmp/trivy-3552432684: read-only file system
```

**Cause.** `readOnlyRootFilesystem: true` is right for this workload, and
both engines download a vulnerability database at startup. Both write a
temp file next to the download, and both take the location from `TMPDIR`,
falling back to `/tmp` — which is on the read-only root.

**Fix.** Every container sets `TMPDIR` to the same writable emptyDir it
uses for its database cache. CI asserts that `HOME` *and* `TMPDIR` are
set in every container, for every engine configuration.

**Rule of thumb.** `readOnlyRootFilesystem` plus a tool that downloads
anything means you owe it two settings, not one. The cache directory is
the obvious one and is usually documented. The temp directory is the one
that bites, because the tool never mentions it until it fails.

## What the CI checks are

In `.github/workflows/ci.yml`, job `chart`:

* the chart renders for `engines=grype` and for `engines=grype,trivy`,
  and the rendered output contains the engine-specific settings each
  configuration needs;
* the rendered Deployment has no duplicate env key in any container,
  init containers included (hurdle 1);
* `HOME` and `TMPDIR` are set in every container, for both engine
  configurations (hurdle 3);
* `replicaCount > 1` fails to render, because the job store is in memory
  and Harbor must poll the instance that ran the scan.

Hurdle 2 is a property of the cluster, not of the chart, so it is not
something CI can assert. The chart's default of `cpu: "0"` is the
mitigation, and the reasoning is in `values.yaml` next to the value.

## Harbor registration

One more thing that is not a Kubernetes problem but shows up at the same
moment: when you add the scanner in Harbor, tick **Use internal registry
address**. Without it Harbor hands the adapter its external address, and
Grype rejects the resulting token realm:

```
invalid realm in www-authenticate: … is a private or link-local address
```
