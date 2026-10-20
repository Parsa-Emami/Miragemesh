# C08 implementation report

Completed the owner-approved internal Go enrollment service over the existing C05
file adapter. Issuance/consumption enforce explicit bounded TTL, sensor scope,
hashed tokens, durable once-only publication and restart-safe replay denial.
No enrollment HTTP/UI/CLI, certificate issuance or mTLS was added.

## Validation

- Go: 140 test run/pass events, no failures; uncached race run and ordinary run.
- Discovery guard: 4 required suites, 16 executed anchors.
- npm: 39 tests passed; TypeScript, web build and real Go engine build passed.
- Browser: 3 Chromium tests passed.
- Python: 6 source-integrity regressions; repository/plan validators passed.
- Real clean clone: setup, Go vet/race/guard, event validation and web/engine lifecycle passed.
- Go format/vet, dependency/resource validation and package checksums passed.
- Focused enrollment test binary: zero network syscalls under strace.
- Security review: malformed/unknown tokens, forged stored identity, scope, expiry,
  replay, quota, cancellation, corruption, 12 concurrent consumers (one success),
  9 injected syscall failures and 5 SIGKILL publication boundaries are covered.

One test invocation failed because packaging deleted an output directory while
Go enumerated packages. The failure log is retained; serial repetition passed.
No product defect remained from that invocation. Expected TDD failures are also
retained separately. No standalone JavaScript lint script is configured.

## Source and delivery

- Source identity: `sha256:b8125962f740bae3a98ebcd4cab0a91a4a6be11eef047b703d828e67c553641d`.
- Implementation base: `2ff5f42d49a3d904f13f59c09fcce95f622dd513`.
- Verification used isolated temporary snapshot objects without changing delivery refs.
  C08 is delivered in the local commit containing this report, with subject
  `feat(enrollment): consume expiring one time tokens`. No push or publication.
- Progress: C08 verified locally; next task C09; coreReady remains false.

## Changed files

No task files were deleted. This list includes implementation, tests, fixtures,
documentation/status, and the complete evidence inventory:

- `apps/web/src/generated/project.json`
- `docs/ROADMAP_FA.md`
- `docs/agents/SESSION_HANDOFF.json`
- `docs/architecture/ENROLLMENT.md`
- `docs/architecture/STORAGE_PROOF.md`
- `docs/engineering/ENGINE_TESTS.md`
- `docs/evidence/C08.json`
- `docs/evidence/C08/REPORT.md`
- `docs/evidence/C08/browser.log`
- `docs/evidence/C08/check.log`
- `docs/evidence/C08/clone-before-metadata.log`
- `docs/evidence/C08/clone.log`
- `docs/evidence/C08/diff-check-before-normalization.log`
- `docs/evidence/C08/diff-check.log`
- `docs/evidence/C08/discovery.log`
- `docs/evidence/C08/engine-tests-packaging-race.jsonl`
- `docs/evidence/C08/engine-tests.jsonl`
- `docs/evidence/C08/environment.json`
- `docs/evidence/C08/gofmt.log`
- `docs/evidence/C08/install.log`
- `docs/evidence/C08/network-check.log`
- `docs/evidence/C08/network-tests.log`
- `docs/evidence/C08/network.trace`
- `docs/evidence/C08/next-task.log`
- `docs/evidence/C08/official-api.log`
- `docs/evidence/C08/package-checksums.log`
- `docs/evidence/C08/package.log`
- `docs/evidence/C08/plan-metadata.log`
- `docs/evidence/C08/plan.log`
- `docs/evidence/C08/python-tests.log`
- `docs/evidence/C08/red-behavior.log`
- `docs/evidence/C08/red-clock.log`
- `docs/evidence/C08/red.log`
- `docs/evidence/C08/repository.log`
- `docs/evidence/C08/resources.log`
- `docs/evidence/C08/snapshot.json`
- `docs/evidence/C08/source-files.json`
- `docs/evidence/C08/standard-tests.log`
- `docs/evidence/C08/vet.log`
- `internal/contracts/enrollment.go`
- `internal/contracts/enrollment_test.go`
- `internal/enrollment/service.go`
- `internal/sensor/event.go`
- `internal/storage/adapter.go`
- `internal/storage/recovery_test.go`
- `plans/commits/C08.md`
- `plans/progress.json`
- `plans/project-state.json`
- `plans/roadmap.json`
- `scripts/verify-engine-tests.mjs`
- `tests/engineering/engine-tests.test.mjs`
- `tests/enrollment_test.go`
- `tests/fixtures/miragemesh/C08/expected-output.json`
- `tests/fixtures/miragemesh/C08/invalid.json`
- `tests/fixtures/miragemesh/C08/positive.json`
- `tests/web/oss-tooling.test.mjs`

## Limits and recovery

Remote GitHub Actions are unverified. HTTP enrollment, PKI/mTLS, physical
power-loss durability, C28 capacity and C30/C40 readiness remain outside this
proof. A trusted wall clock is required. Older event-only binaries may reject
new enrollment objects: retain a compatible reader and repair forward; do not
overwrite newer accepted state. SQL schemas, migrations, environment files,
Dockerfiles and dependency/toolchain locks were not changed.
