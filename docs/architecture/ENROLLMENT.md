# C08: internal durable enrollment tokens

The owner-approved C08/F02 scope is an internal Go service over the existing
C05 file adapter. It issues and consumes sensor-scoped expiring one-time tokens.
There is no HTTP/UI/CLI enrollment entry point, operator account model,
certificate issuance, or authenticated event admission. A successful consumption
is a durable enrollment outcome, not a certificate or permission to ingest.
C09 owns PKI/mTLS, C10/C11 desired/applied configuration, C14-C16 spool/ACKs,
C24 certificate recovery/rotation, and C27 checks every enabled external surface.

## Trusted in-process interface

```go
service, err := enrollment.New(store, maxTTL, time.Now)
issued, err := service.Issue(ctx, sensorID, ttl)
result, err := service.Consume(ctx, issued.Token, sensorID)
```

The caller owns the existing `*storage.Store` and its Close/Open lifecycle.
`maxTTL` must be positive and explicit; it is a deployment policy, with no hidden
numeric default. A token's TTL must be positive and no greater than this bound.
The clock is trusted application configuration, never a field supplied by an
untrusted enrollment request. Tests pass controlled clocks; production passes
`time.Now`. Time checks use UTC and reject zero/unrepresentable times and clocks
before issuance. Expiry is exclusive (`now >= expires_at` fails) and is rechecked
under the writer lock immediately before filesystem work. This is a wall-clock
policy; it does not establish independently trusted time against host rollback.

Sensor IDs follow C04's nonempty valid UTF-8/128-code-point bound and remain
opaque text, never paths. Tokens contain 32 bytes from Go `crypto/rand.Read`,
encoded as exactly 43 canonical unpadded Base64URL characters. Only SHA-256 of
that encoded token is persisted. The raw token is returned only after the issue
record commits; `IssuedToken.Token` is excluded from generic JSON marshaling.
Neither the service nor its errors log token contents. Callers must also keep
returned credentials out of their own logs and diagnostics.

Errors distinguish `ErrInvalidInput`, `ErrInvalidTTL`, `ErrInvalidToken`,
`ErrExpired`, `ErrReplay`, and `ErrScope`. Context and storage errors propagate.
An unknown token and an invalid token both fail with `ErrInvalidToken`; a valid
but differently scoped token fails without consuming it. A consumed token never
returns a second successful result, including after restart. Multiple tokens
may be issued independently for the same sensor; no new fleet/tenant policy is
inferred. The configured maximum controls new issuance, not previously issued
records from another trusted configuration.

## One storage authority

Canonical internal `contracts.EnrollmentRecord` objects use schema version `1`,
`kind` (`enrollment.issue` or `enrollment.consume`), `sensor_id`, `token_hash`,
`issued_at`, `expires_at`, and (only for consumption) `consumed_at`. Unknown,
noncanonical, duplicate, invalid-version, oversized, invalid-hash and invalid-time
records fail validation. The 8192-byte object cap remains shared with C04.
These are internal file records, not a new public event/HTTP contract.

Operation IDs are `enrollment/issue/<hash>` and `enrollment/consume/<hash>`.
Objects, quotas, SHA-256 receipts, writer lock, manifest shape/version, staging,
atomic publication and directory synchronization all reuse C05. Both issuance
and consumption use `CommitOnceChecked`: an existing operation is a conflict,
even with identical bytes. Consumption verifies the issued record under the
same writer lock before publishing. The service maps an existing consumption
to `ErrReplay`. This avoids a check-then-write race across service instances.
There is no second database, sidecar authority, mutable token file or cache of
consumed state. Token lifecycle history counts against the existing explicit
operation/byte/manifest quotas; C08 adds no cleanup/retention policy.

C04 `DecodeEvent`, public event/result formats and event-byte receipts are
unchanged. The adapter additionally decodes enrollment records on load/reopen
and while validating recognized orphan objects. C07 ignores enrollment records
when checking per-sensor sequences and event IDs. Existing event-only fixtures
remain readable, with identical original receipts.

## Failure and recovery

Before publication, failures expose no partial enrollment outcome. After
filesystem work begins, the existing poisoned-handle rule requires Close/Open.
A manifest-directory-sync failure has an uncertain caller-visible outcome;
reopen validates the committed generation. If consumption became visible,
retry fails with replay; if it did not, retry may consume the still-valid token.
No API returns a successful credential twice to recover a lost acknowledgement.
If issuance committed but the caller lost the raw token, it cannot be recovered
from its hash; the trusted operator may issue a new independent token subject
to quotas. Reopen never promises rollback of an already published operation.

Old event-only binaries may reject enrollment objects. After such records are
accepted, retain this compatible reader and repair forward; do not downgrade the
reader or overwrite newer accepted state with a historical backup. No SQL schema,
migration, environment file, Dockerfile, dependency or provider pin changes.

## Verification and limits

`tests/enrollment_test.go` uses the actual filesystem adapter for issuance,
consumption, restart, scope, TTL, redaction, quota, corruption, cancellation and
cross-instance concurrency. The existing C05 syscall/SIGKILL harness additionally
runs canonical issue/consume records through the once-only storage path; it
verifies prior/new visibility and rejects repeated published consumption.
Those storage fault tests do not substitute a mocked identity provider.
The Go discovery guard requires the C08 service, parser and recovery anchors.

No external identity provider, header-based authorization or network admission
is enabled in C08; their generic card negatives are not claimed as completed
PKI/API tests. Missing storage fails closed. A focused syscall network trace
checks the enrollment test binary; it does not certify decoy isolation (C13),
all-project egress, physical power-loss durability, remote Actions, or C30/C40.
Exact commands and observations belong to `docs/evidence/C08.json`.

Official standard-library sources: [secure random bytes](https://pkg.go.dev/crypto/rand#Read),
[SHA-256](https://pkg.go.dev/crypto/sha256#Sum256),
[strict Base64 decoding](https://pkg.go.dev/encoding/base64#Encoding.Strict),
[UTC timestamps](https://pkg.go.dev/time#Time.Format).
Implementation is checked against the repository-locked Go 1.27.2 source.

## C24 recovery claim

A `certificate.recover` record can atomically claim an issued enrollment token while publishing the replacement client certificate in the same C05 commit. Ordinary enrollment consumption recognizes that claim under the shared writer lock; recovery and consumption cannot both win. Scope, original issue, expiry and replay are checked. See [CERTIFICATE_ROTATION.md](CERTIFICATE_ROTATION.md).
