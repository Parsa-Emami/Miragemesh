# MirageMesh local readiness and diagnostics

C29 separates four readiness scopes for the loopback profile:

| Component | Required | Probe |
| --- | --- | --- |
| `web` | always | `dist/web/index.html` exists and is a file |
| `engine` | when a loopback engine is attached | valid `GET /healthz` (`engine-runtime`, version, toolchain) |
| `storage` | when the supervisor enables a storage-backed surface | validated snapshot from that surface (`/api/v1/sensors`, `/api/v1/incidents`, `/api/v1/certificates` or `/api/v1/updates`) |
| `provider:certificates` | when certificate status is enabled | validated `/api/v1/certificates` snapshot |
| `provider:updates` | when update status is enabled | validated `/api/v1/updates` snapshot |

`GET /healthz` is web-shell liveness only: it never claims engine, storage or provider readiness. `GET /readyz` probes the configured components on every request. It returns `200` when every required component is ready, `200` with `status: "degraded"` when only optional components fail, and `503` with `status: "not_ready"` when a required component fails:

```json
{
  "status": "not_ready",
  "scope": "web-shell",
  "engineReady": false,
  "storageReady": false,
  "providersReady": false,
  "components": [
    { "name": "web", "required": true, "ready": true, "code": null },
    { "name": "engine", "required": true, "ready": false, "code": "engine_unavailable" },
    { "name": "storage", "required": true, "ready": false, "code": "storage_unavailable" }
  ]
}
```

`GET /api/diagnostics` always returns `200` so an operator can read a failing state. It repeats the components, adds `generated_at`, the bounded log ring and the active limits:

```json
{
  "schema_version": 1,
  "scope": "web-shell",
  "generated_at": "2026-10-24T00:00:00.000Z",
  "status": "not_ready",
  "components": [],
  "logs": {
    "entries": [{ "at": "...", "level": "error", "code": "engine_unavailable", "message": "Engine runtime readiness probe failed." }],
    "dropped": 0,
    "max_entries": 32,
    "max_bytes": 8192,
    "max_message_chars": 256
  },
  "limits": { "probe_timeout_ms": 1500, "max_log_entries": 32, "max_log_bytes": 8192, "max_message_chars": 256 }
}
```

## Failure and log rules

- Each probe is bounded to 1500 ms and only targets the validated `127.0.0.1:<port>` engine address. There is no outbound network path and no redirect following.
- A failure is converted to a fixed typed code (`engine_unavailable`, `storage_unavailable`, `provider_certificates_unavailable`, `provider_updates_unavailable`, `web_assets_unavailable`); response bodies, URLs, request headers and query strings are never copied into logs.
- Entries are written on readiness transitions only: the first observation of a failure, a required failure at `error` level, an optional failure at `warn`, and a recovery at `info`. Repeated probes of an unchanged state add nothing, so frequent scraping cannot flood the ring.
- Log messages pass a redactor that removes `Authorization`, `Cookie`, `token`, `secret`, `password` and `api_key` values and `Bearer` credentials, collapses whitespace and truncates to 256 characters.
- The ring holds at most 32 entries and 8192 bytes; older entries are dropped and counted in `dropped`, so memory stays constant under repeated failures.
- A recovery adds exactly one `component_recovered` entry; a later failure adds a new typed entry. Logs are per web-server instance and are empty after a restart.

## Requiredness and unsupported providers

`scripts/start-local.mjs` marks storage and provider components required only when the matching supervisor options are enabled. A plain `npm start` therefore reports `storage` as `not_configured` and remains `degraded`, not falsely ready. Running `scripts/serve-web.mjs` without an engine reports the web shell only.

Rootless Podman and the isolated decoy are engine CLI surfaces, not part of the web supervisor. They are not probed or claimed here; declaring `podman` as a readiness provider is rejected as an explicit configuration error instead of reporting placeholder success.

## Verification

```sh
node --test tests/web/engine-readiness.test.mjs
npm run check
```

The C29 fixtures in `tests/fixtures/miragemesh/C29/` describe the component model, expected statuses, redaction sentinels and log bounds. The tests exercise a real Go engine with a real C05-backed sensor store, unreachable and malformed engines, failing required and optional providers, sentinel strings in request metadata and upstream bodies, log overflow, missing web assets and restart.

## Local artifact diagnostics

Check a packaged artifact before starting it:

```sh
sha256sum -c SHA256SUMS.txt
dist/engine/miragemesh --version
node --version
```

`sha256sum -c` must cover every regular file except `SHA256SUMS.txt` itself. A failure
means the tree was modified after packaging; do not run it. `provenance.json` records the
source identity, toolchain, archive digest and SBOM digest; `source/provenance.json` is
the same record kept beside the source archive.

Startup failures:

- `Missing or unconfined web index` means `dist/web/index.html` is absent or the root
  option points outside the artifact. Re-extract the immutable artifact.
- `Engine exited unexpectedly` means the packaged engine cannot bind owned loopback or
  the host rejected execution. Check `file dist/engine/miragemesh` and the architecture.
- `readyz` failing while `healthz` passes means the web process is alive but runtime
  configuration or built assets are invalid. Compare `ops/web/runtime-config.json` with
  the copy in `dist/web/runtime-config.json`.
- A 503 from a domain route is expected in this release. The public engineEnabled flag
  stays false and unsupported routes must remain unavailable.

The full decoy workflow additionally requires rootless Podman 4.9.3 and the pinned
`docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62`
image. Those host prerequisites are inventoried in `sbom.cdx.json` and
`docs/engineering/toolchain-lock.json`; they are not redistributed in this artifact.
Pulling that image is the only expected network operation, and only when the operator
chooses the decoy workflow. The local reference workflow itself performs no egress.

No login, telemetry, hosted database or cloud account is included. Do not expose the
loopback listener; use the supplied Nginx template only after reviewing its deny-all
admission rule.
