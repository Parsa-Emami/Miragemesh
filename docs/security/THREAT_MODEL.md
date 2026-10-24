# MirageMesh threat model — local Linux profile

Status: current for the source recorded in `docs/evidence/C27.json`. This model
covers the open-source local profile only. It is not a certification and does
not describe a hosted, multi-tenant or public-ingress deployment. The executable
surface-to-proof mapping is `tests/release/security-matrix.md`; reporting policy
is `SECURITY.md`.

## System and trust boundaries

```
 operator ──CLI──▶ local keys/files        browser ──loopback HTTP──▶ web shell
    │                                          │
    └──engine files/state◀──engine HTTP───────┘
                                  │
 collector ──mTLS (local CA/CRL)──▶ ingest guard
                                  │
                            C05 storage / segments
                                  │
                            rootless Podman decoy
```

- **Browser ↔ web server**: loopback only, no authentication token, one local
  user. The browser is treated as able to run hostile stored content, not as a
  trusted operator.
- **Web server ↔ engine**: both bind loopback; the engine accepts only its own
  loopback authority and same-origin writes. No shared secret.
- **Collector ↔ engine**: TLS 1.3 with mandatory client verification,
  operator-configured fingerprint-to-sensor mapping, one signed CRL with
  fail-closed staleness. No public listener.
- **Engine ↔ filesystem**: C05 objects and segments are local files with
  hash-checked canonical records and a single writer.
- **Engine ↔ container provider**: rootless Podman; ownership and run markers
  are recorded before the engine may remove a container.
- **Operator ↔ supply chain**: signed update metadata, pinned resources and
  exact digests; no automatic installation.

## Assets

Accepted sensor events and their exact bytes; event segments and the rebuilt
index; triage history; signed per-sensor configuration; enrollment tokens;
mTLS identity material and the CRL; certificate rotation state; update
authority, recovery grants and verified artifact digests; local key files;
spool loss and retention audit; the web shell and its configuration.

## Actors and capabilities

| Actor | Capability assumed |
| --- | --- |
| Local operator | Full authority over local files, keys, CLIs and process lifecycle |
| Malicious web content | Controls text stored in events, triage reasons, update strings or metadata, and can attempt scripts, external fetches and form posts |
| Malicious or compromised sensor | Can send malformed events, replay sequences, exceed quotas, attempt identity replay or scope confusion |
| Local unprivileged process | Can reach loopback ports and read world-readable files; cannot assume the operator's authority |
| Network attacker | Cannot reach any listener directly; may attempt DNS rebinding or cross-origin browser requests |
| Container adversary | Controls code inside the decoy container; has no network capability by policy |
| Supply-chain attacker | May alter downloaded artifacts, image digests or signed metadata |

## Threats and controls

| ID | Threat | Primary controls | Proof |
| --- | --- | --- | --- |
| T1 | Cross-site request forgery or DNS rebinding triggers a triage write | Loopback Host and Origin equality at web and engine; same-origin re-check before write; exact object path regex; typed 403 before body handling | `tests/browser/security.spec.ts`; `tests/web/local-launch.test.mjs`; `cmd/miragemesh/incidents_test.go` |
| T2 | Stored XSS through event paths, triage reasons, update or certificate strings | React text rendering only; no `innerHTML`/`eval`; CSP `script-src 'self'` with no inline script and `connect-src 'self'` | `tests/browser/security.spec.ts`; `apps/web/tests/incidents.spec.ts`; `apps/web/tests/updates.spec.ts` |
| T3 | Import or asset path escapes the served root | Exact path allowlist, dot-segment and backslash rejection, `realpath` containment, symlink rejection | `tests/web/foundation.test.mjs`; `tests/browser/security.spec.ts` |
| T4 | Hostile JSON import exhausts memory, pollutes prototypes or executes markup | 1 MiB pre-read bound, object-root, node/depth limits, `__proto__`/`prototype`/`constructor` rejection, text-only rendering, no upload | `tests/web/foundation.test.mjs`; `tests/browser/security.spec.ts` |
| T5 | Replayed, expired or revoked collector identity authenticates | TLS 1.3, mandatory client verification, direct-issuance restriction, fingerprint scope, signed CRL with fail-closed staleness, revocation checked before side effects | `tests/mtls_test.go` anchors |
| T6 | Object or scope confusion authorizes another sensor, incident, release or certificate | Sensor-scoped tokens/configuration, exact release identity, incident object lookup, per-sensor revision floors | `tests/triage_test.go`; `tests/update_test.go`; `tests/rotation_test.go`; `tests/enrollment_test.go` |
| T7 | Provider removes or inspects an unrelated container | Ownership and run markers; typed reconciliation; foreign containers preserved | `tests/egress_workflow_test.go`; `tests/browser/security.spec.ts` (no unrelated authority) |
| T8 | Default profile egresses to the Internet or a private network | Exact import allowlists (no `net*`/`os/exec`), container `--network=none`, CSP `connect-src 'self'`, no external assets | `tests/egress_test.go`; `tests/rebuild_test.go`; `tests/triage_test.go`; `tests/browser/security.spec.ts` |
| T9 | Secret or private path leaks through HTTP, logs or status views | Public-only snapshots, bounded responses, `no-store`, no key material in the repository or browser assets | `cmd/miragemesh/main_test.go`; `apps/web/tests/certificates.spec.ts`; `apps/web/tests/updates.spec.ts` |
| T10 | Forged, tampered, rolled-back or expired update/rotation authority is accepted | Publisher and separate recovery keys, exact-byte signatures, immutable digests, durable revision/revocation/high-water floors, single-use scoped recovery | `tests/update_test.go`; `tests/rotation_test.go`; `tests/engineering/*-cli.test.mjs` |
| T11 | Disabled surface answers like a successful empty result | Typed 503 with a specific error and explicit UI unavailable/disabled states | `cmd/miragemesh/*_test.go`; `tests/browser/security.spec.ts`; `apps/web/tests/*.spec.ts` |
| T12 | Quota or crash turns a rejected write into partial success | Single-writer transactions, hash-checked records, typed recovery, durable ACKs before success | `tests/storage_test.go`; `tests/spool_test.go`; `tests/replay_test.go` |

## Residual risks and explicit limits

- The local operator is trusted. Any process running as that user can read
  operator files and call loopback APIs; MirageMesh does not separate users on
  one host.
- Physical access, OS compromise, malicious kernel/driver behaviour and
  container-runtime compromise are out of scope.
- Rootless containers are an isolation layer for synthetic decoys, not a public
  multi-tenant trust boundary (ADR-0003).
- There is no public ingress, hosted identity provider, CORS-enabled API,
  multi-tenant authorization model, audit trail for reads or rate limit on read
  APIs.
- Update verification records a file digest; it does not install or execute an
  artifact and does not measure the installed software.
- HTTP between browser and engine is loopback without TLS; an optional TLS
  reverse proxy is a separate, later validated extension.
- No clean-host full workflow (C30), hardware/power-loss measurement (C28) or
  published artifact proof (C40) is implied.

## Maintenance

Any new route, CLI mode, stored field or rendered surface must add a row to
`tests/release/security-matrix.md` with an executed proof, or be marked
unsupported. Changing a trust boundary requires updating this document and the
ADR-0003 scope before the code.
