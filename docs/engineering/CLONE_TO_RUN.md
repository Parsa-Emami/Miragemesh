# MirageMesh: clone to run

For end-user workflows, operational quotas, and step-by-step incident triage, see the comprehensive [User Guide](../release/USER_GUIDE.md).

The [service/privacy policy](../release/SERVICE_POLICY.md) records actual data
locations, export/deletion limits and backup/recovery. The
[maintenance policy](../release/MAINTENANCE.md) defines the supported reference
platform and best-effort support; other host examples below need their own full
workflow evidence before being advertised as supported.

## Runnable today

Use Linux amd64 with Git, Node 24.19.0, npm CLI 11.9.0, an installed Go command (1.21+ for toolchain selection) and rootless Podman 4.9.3 (Ubuntu 24.04 reference package 4.9.3+ds1-1ubuntu0.2), then:

```sh
git clone https://github.com/Parsa-Emami/Miragemesh.git
cd Miragemesh
npx --yes --package=npm@11.9.0 --call 'npm run setup'
npx --yes --package=npm@11.9.0 --call 'npm start'
```

Open http://127.0.0.1:4173. Setup checks Go and rootless Podman, installs the committed web lockfile with lifecycle scripts disabled, and builds the web and Go runtime. The official Go toolchain mechanism selects/downloads and verifies Go 1.27.2 without replacing the system Go. No database or cloud account is required. The workspace previews JSON locally and browses the roadmap. The Sensors page can read a durable C05 snapshot when the engine starts with explicit storage quotas and C10 verifier policy; otherwise it reports that local status is unavailable. See `docs/architecture/SENSOR_STATUS.md` for all required `npm start` options and the raw public-key file format. The separate local --validate-event command validates a v1 event without ingesting or storing it (see contracts/README.md). The Incidents page supports source-backed replay and durable local triage when explicit existing-store, segment and rate-policy options are supplied; see `docs/architecture/INCIDENT_REPLAY.md`. The full reference workflow is proved from a clone by `npm run test:clone`; `npm start` alone does not create sensor state, so the domain pages stay unavailable until the engine is launched with explicit local state options.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `npm run doctor` reports tool/provider versions, built runtime version and web/core state; Go resolution may require a download if its cache is missing. `npm run release:check` deliberately exits 2 until full evidence is ready. Ctrl+C stops both web and the owned engine process. Ports can be selected with `npm start -- --port 4301` when running multiple projects.

## Source build alternative

A fresh operator can build and verify the complete distribution entirely from source without pre-compiled artifacts:

```sh
# 1. Clean build of web frontend and Go runtime:
npm run build

# 2. Package into reproducible distribution archives:
npm run package

# 3. Verify artifact checksums, SBOM, and provenance:
npm run verify:artifact
```

This generates `dist/release/` containing the compiled binary, web assets, source tarball, SBOM, and `SHA256SUMS.txt`. All compilation occurs offline once dependencies are fetched into local caches.

## Full-product contract to implement

The same clone/setup/start sequence must prepare and supervise the actual Go engine and required self-hosted open-source resources by C30. No second undocumented terminal, paid account, sibling clone or owned public domain. C03 supplies local lifecycle/health and C31 supplies verified convenience artifacts plus a documented source-build alternative. Downloads may be needed to prepare resources; user payloads are not sent to a compulsory proprietary service. No global runtime install, system trust change or user data deletion occurs implicitly.

Local resources: rootless Podman for isolated decoys. Hardware target: 2 vCPU / 2048 MiB RAM / 10240 MiB free disk plus real dataset/provider/backup space. C28 measured a sustained target of 8 events/s with 5 sensors under an enforced 2 vCPU / 2048 MiB user-scope cgroup on the recorded host; the earlier 20 events/s planning number was not sustained and is no longer published. The free-disk figure remains a planning budget, not a measurement. Full engine support initially targets Linux x86_64; other hosts require their own actual C30/C33 evidence. Rootless workloads need Linux or a tested Linux/WSL2 host.

The isolated decoy of C13 runs in a rootless container and needs the pinned image of `docs/engineering/toolchain-lock.json` in the local image store:

```sh
podman pull docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62
```

The provider never pulls an image itself, so the operator prepares it once. The rootless runtime must be able to apply the memory limit; a runtime without cgroup delegation fails the isolation verification instead of reporting the limit as held.

The engine starts the isolated decoy and reports the typed outcome:

```sh
miragemesh --decoy-isolation \
  --decoy-image docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62 \
  --decoy-artifact "$HOME/.local/lib/miragemesh/decoy" \
  --decoy-state "$HOME/.local/state/miragemesh" \
  --decoy-memory-bytes 67108864 --decoy-pids-limit 32
```

The command verifies one isolated decoy: it starts the container, verifies the
isolation, reports the typed outcome and removes the container again. The state
directory is created when it is missing and must be a private directory of the
operator (mode `0700`), because the durable store of the decoy requires it. The
decoy artifact is mounted read-only and receives the paths of its own namespace
through the environment. See `docs/architecture/DECOY_ISOLATION.md`.

`local-demo` uses synthetic fixtures and isolated development providers; `local-private` requires real identity/permission, provider durability, revocation and restore evidence before sensitive use. A development provider mode never becomes a production vault/gateway by relabeling it.

## Checks

```sh
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

`test:clone` performs a real local Git clone of the staged/committed source, runs setup, Go vet and uncached race tests with required-test discovery, executes the C30 reference workflow from `tests/scenarios/clone-to-value.json`, checks engine/storage/provider readiness and restart/restore against the accepted state, then runs `tests/browser/clone-to-value.spec.ts` in Chromium. Install the Playwright Chromium build once before the clone check. The older unified-startup, health and disabled-admission proof remains reported separately as `webOnly` in the command output. See ENGINE_TESTS.md for engine test discovery and ENGINE_LAUNCH.md for lifecycle tests. Optional hosting, network boundaries and package operations remain in WEB_RUNBOOK.md and `infra/deployment.md`.

## C32 network boundaries and optional private hosting

Local operation requires no owned public domain. Loopback bindings (`127.0.0.1` and `::1`), origin checks and cache boundaries are verified by `tests/web/network-boundaries.test.mjs`. For optional private hosting behind a TLS reverse proxy (e.g. Nginx with `ops/web/nginx.conf.template`), see [deployment.md](../../infra/deployment.md). External egress is absent by default, and core engine endpoints remain unexposed to public interfaces.

## C30 local reference workflow

The versioned fixtures under `tests/fixtures/miragemesh/C30/` drive the real C08 enrollment, C09 mTLS guard, C10/C11 signed configuration, C16 batch ingest, C14/C15 offline spool and explicit loss, C19/C20 incident view and triage, C23 non-destructive retention preview, and C17/C18 segment projection. The seed command writes `outcome.json` and `runtime.json` for the supported read surfaces:

```sh
go run ./tests/fixtures/miragemesh/C30/seed /path/to/private-state
```

The seed rejects an existing state directory, validates fixture licenses/provenance, runs the six declared negative cases and restores an independent copy of the accepted store and segments. `npm run test:clone` is the supported clean-clone proof; it also starts the web shell with the seeded C05/segment/certificate options and verifies `/readyz` and the read APIs before and after a restart.

## C28 local workload measurement

The target and over-limit workloads run against the real C05/C16 ingest and C17/C18 segment projection paths with synthetic C28 fixtures:

```sh
node scripts/benchmark-local.mjs --require-constraints
```

`--require-constraints` refuses to publish measured limits unless a systemd user scope actually enforces 2 vCPU / 2048 MiB (`MemorySwapMax=0`). `--constraint taskset|none` exists for diagnosis and records the weaker enforcement instead of implying it. The command writes `docs/evidence/performance.json` with the host, source, fixture and toolchain identities, the 30-second steady window, the bounded backlog, restart checks, latency percentiles, peak RSS, disk bytes, cancellation and the over-limit results. A rate probe that cannot keep up is recorded as saturation evidence; it is not published as capacity. The workload is a bounded local profile, not a retention or multi-day claim.

## C23 local retention

The engine provides explicit standalone `--expire-segments` preview, with deletion only when `--retention-apply` is supplied. Stop the supervisor to release its segment lock. Supply the existing private directory, past cutoff, reason, idempotency key and actual segment limits. See [EVENT_RETENTION.md](../architecture/EVENT_RETENTION.md). It expires segment copies only; C05 data and quota remain unchanged.

## Certificate rotation and status

C24 provides standalone `--rotate-certificates` operator actions and opt-in read-only `--certificate-status`. The supervisor accepts the complete `--rotation-*` status policy, with no issuer private key. Open `#certificates` to inspect actual sensor revisions, cutoff and recovery. Stop the supervisor before operator mutations of its locked C05 store. Commands, secure file handling and the offline provisioning path are in [CERTIFICATE_ROTATION.md](../architecture/CERTIFICATE_ROTATION.md).

## C25 local update verification

Stop the supervisor for `--verify-update` operator actions. Accept signed metadata, verify a local candidate and restart with the complete `--update-*` common options to read the Updates tab. No private signing key, automatic download or installation is involved. [SENSOR_UPDATES.md](../architecture/SENSOR_UPDATES.md) documents exact signed formats, key provisioning, limits, recovery and commands.

## Independent onboarding check (C36)

After the prerequisites, pinned image pull and Chromium preparation above, run:

```sh
npm run test:clone
```

For a proposed source change, stage its files first with `git add <changed-paths>`; the runner tests the index. It creates a fresh transport clone with no build or Node dependency directories, runs the public `npm run setup` procedure there and performs two independent fresh-state reference-workflow runs. Runtime and browser probes execute the code, assets and engine inside that clone. Each run verifies real readiness, explicit provider failure, restart/restore and the domain pages; missing prerequisites and malformed fixtures must fail explicitly. Prepared system compiler, Podman image and browser caches remain host prerequisites.

Read `dist/ci/onboarding.json` for source/guide/fixture identities, tool versions, measured command durations, exits and both outcomes; full logs are in `dist/ci/onboarding-logs/`. A failure exits nonzero and leaves a failed report. Fix the stated prerequisite and rerun; the check cleans only its temporary synthetic state. See [Onboarding Results](../product/ONBOARDING_RESULTS.md) for the evidence scope. GitHub Actions retains these observations as an artifact, including failures.
