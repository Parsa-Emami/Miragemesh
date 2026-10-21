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

## C10 required anchors

C10 adds thirteen `tests` anchors over the real internal desired-state service:
`TestConfigSignedDesiredStateBecomesActive` proves a signed version 1 document
becomes the active configuration, that the active payload is the exact
submitted bytes, that a higher revision replaces it and that the exact
redelivery of the active revision is an idempotent no-op;
`TestConfigRejectsUnsignedDesiredState` proves a missing signature fails with
the typed `ErrUnsigned` and leaves the active configuration byte-identical;
`TestConfigRejectsStaleDesiredStateWithoutReplacingActiveConfig` proves a
stale revision, an expired document, a not-yet-valid document and a
conflicting revision are rejected with their typed errors without replacing
the active configuration;
`TestConfigRejectsInvalidDesiredStateDocuments` drives the 18 fixture rows of
malformed, unknown-member, duplicated-member, wrong-version, wrong-revision,
wrong-timestamp, inverted-window, out-of-policy, incoherent-settings and
oversized documents through the service;
`TestConfigSignatureCoversExactPayloadBytes` proves the signature covers the
exact payload bytes: a re-serialized variant of a signed document and a
single-byte change both fail with `ErrInvalidSignature`;
`TestConfigRejectsMissingPrerequisites` proves incomplete configuration,
short signing keys, an invalid document, a missing service and a cancelled
context fail explicitly without a panic or a placeholder success;
`TestConfigRejectsDesiredStateSensorQuota` proves a desired state for a sensor
beyond the configured bound fails with `ErrQuota` and leaves the tracked
active configuration untouched;
`TestConfigAppliedPayloadCannotMutateActiveState` proves the result of
`Apply` never aliases the stored active configuration, so mutating the
returned payload cannot change the active signed bytes;
`TestConfigTrustedKeyIsCopiedAtConstruction` proves the verification key is
copied into service-owned memory, so overwriting the caller's key slice
cannot change which signer the service trusts;
`TestConfigExpiryIsRecheckedAtAcceptanceTime` proves the validity window is
judged again under the state lock, so a document that expires while the
service waits for that lock is rejected and never becomes active; and
`TestConfigSettingsBoundsAreDeploymentPolicy` proves the accepted range of
the settings is explicit deployment policy: the engine ships no limit of its
own, a deployment with tighter bounds rejects a document that a deployment
with wider bounds accepts; and
`TestConfigRejectsIncoherentDesiredStateSettings` proves the settings must
agree with each other, so an event batch larger than the spool it has to fit
into is rejected as an internally inconsistent document.
`TestConfigFreshServiceHasNoRememberedActiveState` proves a restarted service
owns no remembered applied revision, so the documented recovery outcome is that
the operator re-applies the latest signed desired state. The discovery guard
and its regressions require all of them alongside the earlier anchors.
Fixtures are repository-authored Apache-2.0 synthetic desired-state documents
under the C10 fixture directory and contain no key material: every test signs
with one ephemeral in-memory Ed25519 key pair. C10 changes no storage format,
no API and no UI.

## C11 required anchors

C11 requires `TestAppliedConfigRecordValidation` in `internal/contracts`;
`TestApplySIGKILLAtPublicationBoundaries` and
`TestApplySyscallFailuresPreserveRecoverableState` in `internal/storage`; and
`TestApplyDurableRevisionAndRestart`,
`TestApplyRejectsInvalidDesiredStateWithoutDurableChanges`,
`TestApplyConcurrentReconcilersAndReplay`,
`TestApplyPrerequisitesQuotaAndCancellation`,
`TestApplyRecoveryRejectsForgedHistory`, `TestApplyPreservesMaximumExactPayload`,
and `TestApplyRechecksClockAndCancellationInsideWriterLock` in `tests`.

The external storage tests run the actual sensor applier with the existing
filesystem seam exposed only in `_test.go`. Five SIGKILL phases cover staged
bytes, object rename, before manifest, manifest rename and before acknowledgement;
nine injected write/sync/rename failures cover ENOSPC, short writes and EIO.
Ephemeral signing keys cross an anonymous child-process pipe and never enter
fixtures, argv, environment or disk. These are local process-crash and injected
filesystem-error proofs, not physical power-loss or remote-runner results.

## C12 required anchors

C12 requires `TestDecoyRecordsMetadataOnlyInteraction`,
`TestDecoyNeverEchoesRequestContent`, `TestDecoyBoundsRequestSize`,
`TestDecoyRejectsUnsupportedMethodAndInvalidPath`,
`TestDecoyFailsClosedOnMissingPrerequisites`,
`TestDecoyObservationsSurviveRestart` and
`TestDecoyNeverExecutesCommandsOrEgresses` in `tests`.

The decoy tests drive the real handler against the real C05 store: an accepted
request commits one version 1 observation, a rejected request commits nothing
and answers with its fixed status, and the recorded observation survives a
store reopen with the next sequence. The last anchor parses every file of the
decoy package: it requires the exact import set, resolves the local name of the
`net/http` import from its declaration, rejects a dot import and checks every
identifier the package takes from `net/http`, so only the handler API is
allowed and a client call such as `http.DefaultClient.Do` or an aliased
`web.DefaultClient.Do` fails the anchor. The fixtures under
`tests/fixtures/miragemesh/C12/` are repository-authored Apache-2.0 synthetic
requests and expectations; the marker value exists only to prove that request
content is never echoed or recorded. C12 adds no listener, no container and no
network provider, so these are local component proofs and not isolation,
egress-denial or remote-runner results.

## C13 required anchors

C13 requires `TestDecoyIsolationDeniesInternetAndPrivateSubnets`,
`TestDecoyIsolationEnforcesPIDAndMemoryLimits`,
`TestDecoyIsolationReconcilesAfterRestart`,
`TestDecoyIsolationProviderFailuresAreExplicit`,
`TestDecoyIsolationPolicyRejectsUnsafeConfiguration`,
`TestDecoyIsolationStopsAndRemovesItsContainer`,
`TestDecoyIsolationAdapterRunsOnlyTheContainerRuntime`,
`TestDecoyIsolationRejectsWeakRuntimeControls`,
`TestDecoyIsolationReportsCleanupFailure`,
`TestDecoyIsolationPolicyIsImmutable`,
`TestDecoyIsolationAdapterBoundsRuntimeOutput`,
`TestDecoyIsolationAdapterHonorsCancellation`,
`TestDecoyIsolationWorkflowReportsTypedOutcome` and
`TestDecoyIsolationWorkflowReportsMissingPrerequisites` in `tests`.

The isolation anchors need the real rootless container provider and the
pinned image of `docs/engineering/toolchain-lock.json`. The provider is
Podman 4.9.3 and the image is
`docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62`;
a missing provider, a runtime that is not rootless and a missing image are
explicit failures, never a skipped test. The runtime must be able to apply the
memory limit: a rootless runtime without cgroup delegation fails the
verification instead of reporting the limit as held.

The decoy inside the container is the real C12 handler, served by the test only
host `tests/decoyhost`. The host is a test fixture and not a product listener:
it exists so that the C12 handler itself runs under the isolation policy and so
that the probes measure the isolation from inside the container. The probes
cover the outbound attempt to the Internet and to the private address space,
the process limit, the memory limit, the effective capabilities, the cgroup
limits and the route table.

The isolation adapter is the only package that may run another program. Its
import set and the identifiers it takes from `os`, `os/exec` and `syscall` are
checked separately: it may resolve the runtime, run it, read the temporary
directory and the bookkeeping of the container it started, and nothing else.
It may not use a network client or a shell. The C12 rules of the decoy
package itself are unchanged: the handler still cannot egress, run a command
or read a file.

The workflow regressions run the engine binary with `--decoy-isolation` and
compare its typed outcome, so the isolation is proved through the supported
engine workflow and not only through the package. The expected outcomes of
the integration run are read from the versioned fixture
`tests/fixtures/miragemesh/C13/expected-output.json` and compared with the
observed results, so the fixture cannot drift.

## C14 required anchors

The `tests` package now requires `TestSpoolDurableBoundedReplayAndRestart`,
`TestSpoolRejectsInvalidAndUnconfiguredEvents`,
`TestSpoolCapacityIsAtomicAndPerSensor`,
`TestSpoolUsesLatestAppliedBoundWithoutDropping`,
`TestSpoolStorageQuotaAndRecoveryFailures` and
`TestSpoolRejectsForgedAppliedConfiguration`. They exercise the internal Go
queue against real C05 state and ephemeral C11 signing keys. No collector or
network connectivity is needed for the queue.

`internal/storage/spool_recovery_test.go` reuses C11's existing test-only
filesystem seam and crash-boundary harness to call the real `spool.Enqueue`.
`TestSpoolSIGKILLAtPublicationBoundaries` covers staged bytes, object rename,
before/after manifest publication and before acknowledgement;
`TestSpoolSyscallFailuresPreserveRecoverableState` covers the nine filesystem
failures. Both anchors are required by the discovery guard. Repeated recovery
and exact retry retain one event and return its original receipt.
