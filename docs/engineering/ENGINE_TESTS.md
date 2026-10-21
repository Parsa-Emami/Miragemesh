# Engine tests (C06 / N06)

The owner-approved C06 scope is dedicated CI and test discovery for the existing
C03 runtime, C04 typed validation and C05 local storage. The generic signer,
revision, sensor-fixture, browser-write and egress requirements in the planning
card do not introduce those product features here. C07 owns sensor identity and
sequence, C08 enrollment, C09 mTLS, C10 signed desired state, C12/C13 decoy
isolation, and C25 signed updates. No API or storage format changes are needed.

## Prerequisites and local commands

Use Linux amd64, Node 24.19.0 and Go 1.27.2, as locked in
`docs/engineering/toolchain-lock.json` and `go.mod`. The official Go toolchain
mechanism verifies the selected compiler with the Go checksum database. Initial
toolchain/dependency preparation needs network access; these CI instructions do
not claim a network sandbox. Go uses only its standard library. The engine tests
use loopback sockets, child processes and real temporary filesystem storage;
they do not require Podman, a container image, a database or a cloud account.
The full application setup still checks the existing Podman prerequisite.

Run from the repository root:

```sh
export GOTOOLCHAIN=go1.27.2
export GOSUMDB=sum.golang.org
export GOPROXY='https://proxy.golang.org|direct'
go version
test "$(go env GOVERSION)" = go1.27.2
formatting=$("$(go env GOROOT)/bin/gofmt" -l cmd internal tests)
test -z "$formatting"
go vet ./...
mkdir -p dist/engine dist/ci
go build -trimpath -o dist/engine/miragemesh ./cmd/miragemesh
node --test tests/engineering/engine-tests.test.mjs
go test -race -count=1 -json ./... > dist/ci/engine-tests.jsonl
node scripts/verify-engine-tests.mjs dist/ci/engine-tests.jsonl
```

Run each command with failure stopping subsequent commands, as in the workflow's
Bash steps. `-count=1` disables test-result caching; `-race` requires the supported
Linux C compiler/runtime. For human-readable output use `go test -count=1 -v ./...`.
Inspect the JSONL artifact when an engine test fails; the Go command's failure
must never be hidden by a pipe or by running the guard alone on an old file.

## Discovery and regression coverage

`go test ./...` discovers every current and future Go package under the root
module. Existing files and fixtures remain unchanged by C06.

| Package | Existing tests | Required execution anchor |
| --- | --- | --- |
| `cmd/miragemesh` | `main_test.go`: real loopback health, shutdown, unsafe/occupied address rejection | `TestLifecycle` |
| `internal/contracts` | `event_test.go`: v1/legacy fixtures, malformed inputs, exact numbers, limits, read failure and cancellation | `TestValidAndIncompatibleFixtures` |
| `internal/storage` | `recovery_test.go`: injected filesystem failures, actual SIGKILL, reopen/replay and orphan handling | `TestStorageSIGKILLAtPublicationBoundaries`, `TestStorageSyscallFailuresPreserveRecoverableState` |
| `tests` | `storage_test.go`: real adapter, exact bytes, quotas, locking, concurrency, corruption and hostile metadata; `event_test.go`: persistent per-sensor sequence, exact retry and invalid input | `TestStorageExactBytesReplayAndReopen`, `TestSensorSequenceReplayAndRestart`, `TestSensorRejectsInvalidAndConflictingEvents` |

The guard reads Go's JSON events and requires a `run` followed by `pass` for each
anchor, completed required packages, and no failure or unfinished package. Empty
discovery, missing suites/anchors, skipped anchors, malformed input and truncated
streams fail. Its synthetic log regressions test discovery only; the Go tests
provide the actual runtime/storage proof. If a required test is intentionally
renamed, update the guard, its regressions and this table together. Future Go
packages remain covered by `./...`; new required anchors belong to their task.

## CI and evidence limits

`.github/workflows/runtime.yml` runs on pull requests, main pushes and manual
dispatch using Ubuntu 24.04. It uses the existing full-SHA action pins, read-only
contents permission, disabled persisted checkout credentials and no application
secrets. It builds/vets the real engine and uploads JSON test output even after
failure. Existing web, plan and source-integrity workflows remain required.

For those local regressions use the pinned npm CLI 11.9.0 with `npm run check`,
`npm run test:browser`, `npm run test:clone` and `npm run package:web`, plus the
Python commands in the contracts/plan workflows. `npm run check` includes the
TypeScript check, build and Node tests, including the discovery guard. There is
no standalone lint script; Go format and vet are the available engine checks.

`test:clone` verifies the Git index, prepares a clean clone, then runs Go vet,
uncached race tests and the same discovery guard before the existing lifecycle
and contract smoke checks. Use a separate candidate index to include
uncommitted task files without changing the user's staging area. Exact source
integrity must be checked in a clean snapshot with its real ancestry; a dirty
working tree cannot satisfy that check. Local command results do not certify a
remote Actions run, full domain workflow, physical power-loss recovery, C30
usability or C40 release. Source-bound C06 evidence records these limits.

Official references: [Go test JSON events](https://pkg.go.dev/cmd/test2json#hdr-Output_Format),
[Go toolchain selection](https://go.dev/doc/toolchain),
[GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

## C08 required anchors

C08 adds `TestEnrollmentRecordValidation` in `internal/contracts`;
`TestEnrollmentSyscallFailuresPreserveRecoverableState` and
`TestEnrollmentSIGKILLAtPublicationBoundaries` in `internal/storage`; and
`TestEnrollmentIssueConsumeAndRestart`,
`TestEnrollmentRejectsInvalidExpiredAndScopedTokens`,
`TestEnrollmentConcurrentConsumptionAndSensorCompatibility`,
`TestEnrollmentStorageFailuresAndCancellation`, and
`TestEnrollmentRechecksClockBeforePublication` and
`TestEnrollmentRejectsForgedStoredIdentity` in `tests`. The discovery guard
and its regressions require all of them alongside the C03-C07 anchors.
Fixtures are repository-authored Apache-2.0 data under the C08 fixture directory.
These tests certify the internal service and real local storage boundary only;
HTTP enrollment and PKI/mTLS remain outside the approved C08 scope.

## C09 required anchors

C09 adds six `tests` anchors behind one real loopback mTLS boundary:
`TestMTLSTrustedCollectorAcceptsEvents` proves a trusted collector whose
fingerprint is operator-mapped to a sensor ingests the unchanged C07 event
bytes through the real sensor/store pipeline and produces a durable receipt;
`TestMTLSRejectsUntrustedExpiredWrongEKUAndRevokedIdentity` proves missing,
unanchored, expired, server-only-EKU, revoked and intermediate-issued (the
`[leaf, intermediate, anchor]` chain passes x509 verification but fails the
guard's direct-issuance rule with typed `ErrUntrusted`) client certificates cannot
ingest events and leave the manifest unchanged;
`TestMTLSTypedVerdictsUseRealHandshakeTranscripts` re-evaluates captured real
 ConnectionState values from completed handshakes through typed guard
verdicts including an authority update that revokes a previously trusted
serial and a scope mismatch that must fail before any storage side effect;
`TestMTLSRejectsIssuersWithoutRevocationCoverage` proves the guard carries
exactly one locally delivered CRL and authenticates only issuers it can
revoke: on a dual-anchor configuration with only the primary anchor's CRL, a
secondary-issued certificate whose serial appears on that CRL is rejected
with typed `ErrUntrusted` (coverage-based, never serial-based), the
covered primary-issued collector still authenticates and ingests through the
real sensor/store pipeline, and the primary-issued certificate with the same
serial stays revoked with zero new receipts;
`TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects` proves a
replayed collector identity cannot ingest after its revocation is configured;
`TestMTLSRejectsInvalidLocalIdentityConfigurations` drives 15 fixture rows of
malformed local identity configurations through `pki.New`. The discovery
guard and its regressions require all of them alongside the earlier anchors.
Fixtures are repository-authored Apache-2.0 synthetic identity material under
the C09 fixture directory; revocation is a locally delivered signed CRL with
fail-closed staleness handling, and no OCSP or other network service is
consulted.
