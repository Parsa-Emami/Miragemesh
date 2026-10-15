# MirageMesh — product implementation roadmap

Web application delivery is tracked separately in [WEB_ROADMAP.md](WEB_ROADMAP.md). Engine milestones remain pending unless backed by their own evidence.

## C01 — `docs(product): confirm personal use acceptance and demand hypotheses`

Stage: foundation. Dependencies: None. Requirements: N01.

Deliverables: `docs/product/VALIDATION_LOG.md`.

- Choose one owned real task, identify current workaround and record measured baseline; public demand remains unvalidated.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C01.json.

Evidence: `docs/evidence/C01.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C02 — `chore(toolchain): verify supported versions and lock dependencies`

Stage: foundation. Dependencies: C01. Requirements: N02.

Deliverables: `docs/engineering/toolchain-lock.json`.

- Official support/release URLs and verification date exist for each selected dependency; no future or assumed version pin.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C02.json.

Evidence: `docs/evidence/C02.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C03 — `chore(app): initialize selected minimal runtime`

Stage: foundation. Dependencies: C02. Requirements: N03.

Deliverables: `docs/engineering/BOOTSTRAP_EVIDENCE.md`, `go.mod`, `go.sum`, `cmd/miragemesh/main.go`, `package.json`, `package-lock.json`, `apps/web/src/main.tsx`, `docs/engineering/WEB_RUNBOOK.md`.

- Fresh checkout boots minimal CLI or local UI; do not run legacy Laravel/PostgreSQL bootstrap.
- Web entry point is mandatory. W01-W05 supply the tested shell; complete engine obligations before verifying C03.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C03.json.

Evidence: `docs/evidence/C03.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C04 — `feat(contracts): freeze typed local and transport contracts`

Stage: foundation. Dependencies: C03. Requirements: N04.

Deliverables: `contracts/README.md`, `contracts/input.schema.json`, `contracts/result.schema.json`.

- Inputs, errors, output, schema versions, timeout and compatibility behavior are typed with positive/negative fixtures.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C04.json.

Evidence: `docs/evidence/C04.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C05 — `feat(storage): implement minimal authoritative storage adapter`

Stage: foundation. Dependencies: C04. Requirements: N05.

Deliverables: `docs/architecture/STORAGE_PROOF.md`, `internal/storage/adapter.go`, `tests/storage_test.go`.

- Authority, atomic write boundary and recovery mechanism match selected profile; storage loss test has actionable result.

Verification: tests/storage_test.go.

Evidence: `docs/evidence/C05.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C06 — `ci(checks): run actual runtime build and foundational tests`

Stage: foundation. Dependencies: C05. Requirements: N06.

Deliverables: `.github/workflows/runtime.yml`.

- Clean-checkout build, formatting and contract/invariant tests pass; plan validation is never reported as application testing.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C06.json.

Evidence: `docs/evidence/C06.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C07 — `feat(sensor): define identity sequence and event contract`

Stage: domain. Dependencies: C06. Requirements: F01.

Deliverables: `internal/sensor/event.go`, `tests/event_test.go`.

- Event IDs and monotonic sequence survive restart and validate payload limits.

Verification: tests/event_test.go.

Evidence: `docs/evidence/C07.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C08 — `feat(enrollment): consume expiring one time tokens`

Stage: domain. Dependencies: C07. Requirements: F02.

Deliverables: `internal/enrollment/service.go`, `tests/enrollment_test.go`.

- Replay and zero/overlong TTL fail; tokens are stored hashed.

Verification: tests/enrollment_test.go.

Evidence: `docs/evidence/C08.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C09 — `feat(pki): authenticate collector traffic with mtls`

Stage: domain. Dependencies: C08. Requirements: F03.

Deliverables: `internal/pki/identity.go`, `tests/mtls_test.go`.

- Expired, untrusted and revoked certificates cannot ingest events.

Verification: tests/mtls_test.go.

Evidence: `docs/evidence/C09.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C10 — `feat(config): sign versioned desired state`

Stage: domain. Dependencies: C09. Requirements: F04.

Deliverables: `internal/config/sign.go`, `tests/config_signature_test.go`.

- Unsigned or stale desired state fails without replacing active config.

Verification: tests/config_signature_test.go.

Evidence: `docs/evidence/C10.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C11 — `feat(apply): reconcile observed and desired sensor state`

Stage: domain. Dependencies: C10. Requirements: F05.

Deliverables: `internal/sensor/apply.go`, `tests/apply_test.go`.

- Crash during config apply converges with recorded applied revision.

Verification: tests/apply_test.go.

Evidence: `docs/evidence/C11.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C12 — `feat(decoy): implement limited metadata only http decoy`

Stage: domain. Dependencies: C11. Requirements: F06.

Deliverables: `internal/decoy/http.go`, `tests/decoy_test.go`.

- No command execution or sensitive response echo occurs and request size is bounded.

Verification: tests/decoy_test.go.

Evidence: `docs/evidence/C12.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C13 — `feat(isolation): enforce decoy egress and runtime limits`

Stage: domain. Dependencies: C12. Requirements: F07.

Deliverables: `internal/decoy/isolation.go`, `tests/egress_test.go`.

- Decoy cannot call Internet or operational private subnets; PID and memory limits hold.

Verification: tests/egress_test.go.

Evidence: `docs/evidence/C13.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C14 — `feat(spool): persist bounded offline events`

Stage: domain. Dependencies: C13. Requirements: F08.

Deliverables: `internal/spool/store.go`, `tests/spool_test.go`.

- Disconnect and restart retain accepted events up to configured bound.

Verification: tests/spool_test.go.

Evidence: `docs/evidence/C14.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C15 — `feat(overflow): expose controlled event loss counters`

Stage: domain. Dependencies: C14. Requirements: F09.

Deliverables: `internal/spool/overflow.go`, `tests/overflow_test.go`.

- Full spool follows documented drop policy with gap marker and cannot fill host disk.

Verification: tests/overflow_test.go.

Evidence: `docs/evidence/C15.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C16 — `feat(replay): upload batches with durable acknowledgements`

Stage: domain. Dependencies: C15. Requirements: F10.

Deliverables: `internal/collector/ingest.go`, `tests/replay_test.go`.

- Lost ACK may replay but cannot create duplicate incident observations.

Verification: tests/replay_test.go.

Evidence: `docs/evidence/C16.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C17 — `feat(segments): rotate immutable event segments`

Stage: domain. Dependencies: C16. Requirements: F11.

Deliverables: `internal/events/segments.go`, `tests/rotation_test.go`.

- Crash at rotation preserves valid records and marks incomplete final record explicitly.

Verification: tests/rotation_test.go.

Evidence: `docs/evidence/C17.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C18 — `feat(index): rebuild event indexes and dedup checkpoints`

Stage: domain. Dependencies: C17. Requirements: F12.

Deliverables: `internal/events/index.go`, `tests/rebuild_test.go`.

- Index loss rebuilds from committed segments without claiming missing events as ingested.

Verification: tests/rebuild_test.go.

Evidence: `docs/evidence/C18.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C19 — `feat(alerts): derive explainable rate and interaction alerts`

Stage: domain. Dependencies: C18. Requirements: F13.

Deliverables: `internal/alerts/rules.go`, `tests/alerts_test.go`.

- Alert references source events and distinguishes sensor-health problems from attacks.

Verification: tests/alerts_test.go.

Evidence: `docs/evidence/C19.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C20 — `feat(triage): persist incident rationale and status`

Stage: domain. Dependencies: C19. Requirements: F14.

Deliverables: `internal/incidents/service.go`, `tests/triage_test.go`.

- Triage cannot silently alter observed source event content.

Verification: tests/triage_test.go.

Evidence: `docs/evidence/C20.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C21 — `feat(ui): show sensor health and spool pressure`

Stage: domain. Dependencies: C20. Requirements: F15.

Deliverables: `apps/web/src/pages/Sensors.tsx`, `apps/web/tests/sensors.spec.ts`.

- Offline sensor, stale applied config and dropped-event count are visible.

Verification: apps/web/tests/sensors.spec.ts.

Evidence: `docs/evidence/C21.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C22 — `feat(ui): render incident replay and triage`

Stage: domain. Dependencies: C21. Requirements: F16.

Deliverables: `apps/web/src/pages/Incidents.tsx`, `apps/web/tests/incidents.spec.ts`.

- Events are escaped and every alert can be traced to source segment.

Verification: apps/web/tests/incidents.spec.ts.

Evidence: `docs/evidence/C22.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C23 — `feat(retention): expire event segments with audit`

Stage: domain. Dependencies: C22. Requirements: F17.

Deliverables: `internal/events/retention.go`, `tests/retention_test.go`.

- Deletion updates indexes and retains explicit retention gap metadata.

Verification: tests/retention_test.go.

Evidence: `docs/evidence/C23.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C24 — `feat(rotation): rotate certificates with overlap window`

Stage: domain. Dependencies: C23. Requirements: F18.

Deliverables: `internal/pki/rotate.go`, `tests/rotation_test.go`.

- Old cert fails after documented overlap; offline sensor has recovery path.

Verification: tests/rotation_test.go.

Evidence: `docs/evidence/C24.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C25 — `feat(update): verify signed sensor update metadata`

Stage: domain. Dependencies: C24. Requirements: F19.

Deliverables: `internal/update/verify.go`, `tests/update_test.go`.

- Wrong signer, revoked version and rollback outside explicit recovery policy are rejected.

Verification: tests/update_test.go.

Evidence: `docs/evidence/C25.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C26 — `test(resilience): replay crash offline and isolation scenarios`

Stage: domain. Dependencies: C25. Requirements: F20.

Deliverables: `tests/resilience_test.go`, `docs/evidence/sensor-template.md`.

- Bounded spool, duplicate batches, collector restart and egress tests pass together.

Verification: tests/resilience_test.go.

Evidence: `docs/evidence/C26.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C27 — `test(security): close abuse and authorization release gaps`

Stage: private-release. Dependencies: C26. Requirements: N27.

Deliverables: `tests/release/security-matrix.md`.

- Run project-specific negative UAT plus XSS/import/auth checks for enabled surfaces; document unsupported attack surface and unresolved findings.

Verification: tests/release/security-matrix.md.

Evidence: `docs/evidence/C27.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C28 — `perf(budgets): measure target workload and overload behavior`

Stage: private-release. Dependencies: C27. Requirements: N28.

Deliverables: `docs/evidence/performance.json`.

- Record hardware, OS, source digest, workload, p50/p95/p99 where meaningful, CPU, RSS, storage growth, cancellation and saturation; lower supported limits if targets fail.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C28.json.

Evidence: `docs/evidence/C28.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C29 — `feat(operations): expose health diagnostics and bounded logs`

Stage: private-release. Dependencies: C28. Requirements: N29.

Deliverables: `ops/diagnostics.md`.

- Local health/status path identifies storage/job/provider failure; sensitive content is absent from synthetic log sentinel test.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C29.json.

Evidence: `docs/evidence/C29.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C30 — `test(recovery): prove personal backup restore and private install`

Stage: private-release. Dependencies: C29. Requirements: N30.

Deliverables: `docs/evidence/private-install.json`.

- Fresh machine/browser install and restore completes project UAT; personal deployment remains private until its relevant safety gates pass.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C30.json.

Evidence: `docs/evidence/C30.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C31 — `build(packaging): create versioned installable artifacts`

Stage: public-release. Dependencies: C30. Requirements: N31.

Deliverables: `scripts/package.sh`, `docs/release/ARTIFACTS.md`, `ops/web/nginx.conf.template`, `ops/web/service.systemd`, `docs/engineering/WEB_RUNBOOK.md`.

- Static/CLI/container artifact matches chosen distribution; SBOM, licenses, checksums and provenance truthfully reflect what is built.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C31.json.

Evidence: `docs/evidence/C31.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C32 — `feat(web): configure domain tls and isolated public demo`

Stage: public-release. Dependencies: C31. Requirements: N32.

Deliverables: `infra/deployment.md`, `docs/evidence/domain.json`.

- Domain/HTTPS/cookies/CSP and private-origin policy are checked; public demo contains synthetic data only and dangerous runtime features are disabled.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C32.json.

Evidence: `docs/evidence/C32.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C33 — `test(ux): verify accessibility mobile and update behavior`

Stage: public-release. Dependencies: C32. Requirements: N33.

Deliverables: `docs/evidence/ux.json`.

- Keyboard/table alternative, 360px through 1440px layouts, empty/error/offline states and N-1 data upgrade fixtures work on documented supported platforms.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C33.json.

Evidence: `docs/evidence/C33.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C34 — `docs(release): publish english usage limits and support contract`

Stage: public-release. Dependencies: C33. Requirements: N34.

Deliverables: `docs/release/USER_GUIDE.md`, `SECURITY.md`.

- New user completes one documented task; English install/use/privacy/limits/support pages include owner contact supplied by maintainer and actual evidence links.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C34.json.

Evidence: `docs/evidence/C34.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C35 — `test(release): exercise signed artifact and clean upgrade paths`

Stage: public-release. Dependencies: C34. Requirements: N35.

Deliverables: `docs/evidence/release-verification.json`.

- Install artifact from clean environment; verify signer with independently trusted key/identity; supported upgrade and rollback preserve latest valid data.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C35.json.

Evidence: `docs/evidence/C35.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C36 — `docs(beta): record independent pilot feedback and beta gate`

Stage: public-release. Dependencies: C35. Requirements: N36.

Deliverables: `docs/product/PILOT_RESULTS.md`.

- Target: 5 relevant trials, 3 complete core task and 2 return for real repeat use; if unavailable continue personal release and mark demand unvalidated rather than inventing pilots.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C36.json.

Evidence: `docs/evidence/C36.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C37 — `fix(beta): resolve evidence backed pilot blockers`

Stage: public-release. Dependencies: C36. Requirements: N37.

Deliverables: `docs/product/BETA_FIXES.md`.

- Fix observed failures, re-run affected checks, record remaining limitations; if no pilots, use observed personal UAT issues and retain unvalidated market label.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C37.json.

Evidence: `docs/evidence/C37.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C38 — `docs(service): freeze retention portability quotas and support policy`

Stage: public-release. Dependencies: C37. Requirements: N38.

Deliverables: `docs/release/SERVICE_POLICY.md`.

- For public service state data location, deletion/export rules, quotas, expected support and outage behavior; paid billing and SLA are not enabled without separate ADR.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C38.json.

Evidence: `docs/evidence/C38.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C39 — `ci(release): verify v1 gate from clean source tree`

Stage: public-release. Dependencies: C38. Requirements: N39.

Deliverables: `docs/evidence/v1-gate.json`.

- Every mandatory requirement has actual passed evidence; no critical open security/recovery issue; release profile and demand status are explicit.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C39.json.

Evidence: `docs/evidence/C39.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.

## C40 — `chore(release): publish v1 artifacts and monitor first use`

Stage: public-release. Dependencies: C39. Requirements: N40.

Deliverables: `docs/evidence/launch.json`, `plans/progress.json`.

- Release only verified profile artifacts, run installed smoke test, record actual version/source digest and follow up support/rollback; never publish fabricated claims.

Verification: Run the actual project checks relevant to this task and record results in docs/evidence/C40.json.

Evidence: `docs/evidence/C40.json`.

Rollback: Before release: revert isolated code change with tests. For persisted data: preserve exports/backup and last compatible reader; use forward repair after new writes. Do not restore a stale snapshot over newer data.
