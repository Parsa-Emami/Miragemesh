# C05: bounded local storage proof

C05 implements an internal Go file adapter under ADR-0003. It persists validated
C04 v1 event bytes and an operation receipt. It does not enroll or authenticate
sensors, authorize operators, ingest collector traffic, advance ACKs/sequences,
or implement spool/retention/segments. Runtime HTTP remains health-only, with
`coreReady: false`; no CLI or browser write path is enabled.

The owner explicitly selected **storage only** when reviewing C05. The card's
generic identity/header/provider negatives and browser integration instruction
cannot certify nonexistent authentication or admission. Those concerns stay with
their owning cards; they are not replaced with mock authority. C06 owns runtime
CI, C07 identity/sequence allocation, C08/C09 enrollment/mTLS, C12 capture,
C14 spool and later collector/segment cards own their domain semantics.

## Interface and limits

`internal/storage` exposes:

- `Open(directory string, limits Limits) (*Store, error)`
- `Commit(ctx context.Context, operationID string, input []byte) (Receipt, error)`
- `Read(ctx context.Context, operationID string) (Record, error)`
- `Close() error`

Use a dedicated child directory, not a user's home or a shared temporary root.
Its parent must already exist and the path must contain no symlink components.
New stores use 0700 directories and 0600 files. Existing state must already have
those exact permissions and the current effective UID. Symlinks, hardlinked
files, FIFOs, devices and unknown entries fail closed; permissions are not repaired
implicitly. The store does not traverse directories found inside its state.

All three `Limits` fields are required and positive: `MaxOperations`, `MaxBytes`
(sum of raw input sizes across operations), and `MaxManifestBytes`. Values that
would overflow bounded reads or directory enumeration are rejected. There is no
product default, unlimited mode, eviction or background retry. C04's 8192-byte
per-event limit and decoder remain authoritative. A replay consumes no new quota;
different operations containing identical bytes each count toward the byte quota.
Fixture limits (16 operations, 128 KiB inputs, 64 KiB manifest) are test settings,
not measured product capacity or the future spool configuration.

Operation IDs are opaque nonempty UTF-8 strings of at most 128 Unicode code
points. They are separate from `sensor_id`/`event_id` and are never used as paths.
Same operation ID with identical exact bytes returns the original receipt.
Different bytes, including whitespace, return `ErrConflict`. Different operation
IDs are separate writes even for identical domain IDs or bytes: this is storage
idempotency, not collector event deduplication. Callers must preserve the operation
ID across retries and must not mutate input while a call is using it.

A `Receipt` contains `operation_id`, lowercase SHA-256 `input_digest` over the
complete original input bytes, and the generation at which it was published.
`Record` returns that receipt, an independent byte slice, and `contracts.Event`
produced by `DecodeEvent`. Receipts do not alter the C04 result envelope and are
not identity, authenticity, collector admission or full-product claims.

## Version 1 disk protocol

One exclusive nonblocking `flock` on `.lock` is held for the handle lifetime;
concurrent calls on that handle serialize. A second cooperating writer fails
with `ErrLocked`. Process death releases the OS lock. Never unlink the lock file
while any process can hold the store open.

The directory contains `.lock`, `manifest.json`, immutable
`object-<64 lowercase SHA-256 hex>.json` files and temporary
`.stage-<32 random lowercase hex>` files. Names are generated internally and
accessed through `os.Root`, with no-follow/nonblocking file opens and regular-file,
owner, permission and link-count checks. `metadata.path` remains inert text.

The sole authoritative manifest is canonical Go JSON with this private versioned
shape (no trailing newline):

```json
{"schema_version":"1","generation":1,"operations":[{"receipt":{"operation_id":"op-01","input_digest":"a391f2daf6fd4283c0e78a795476413fbd525cae0f3b4ec81a83f81c4f9c0444","generation":1},"size":171}]}
```

This entry describes the exact synthetic positive fixture. Entries are
in commit order; receipt generations are contiguous starting at one, IDs unique,
and manifest generation equals entry count. The immutable object contains exact
C04 input bytes. Object references and idempotency receipts become visible in the
same manifest publication; no independent volatile success/job table exists.
Unknown versions or noncanonical manifests (including unknown, differently cased,
missing or duplicate fields) require recovery. This is an internal file format,
not a database schema or public HTTP format. No automatic migration is offered.

For a new commit:

1. Validate context, operation ID, C04 bytes and all quotas before writing.
2. Write an exclusive temporary file; read back exact bytes and sync/close it.
3. Publish the immutable object, or verify an already identical object; sync the
   containing directory.
4. Write, verify and sync/close a new manifest temporary file. Check cancellation.
5. Atomically rename it over `manifest.json` on the same filesystem, then sync
   the containing directory. Only then return a successful receipt.

A cancelled call before filesystem work leaves the handle usable. Any failure
once staging starts returns no receipt and requires Close/Open before further
operations. Before manifest publication the prior generation remains authority.
Cancellation after publication cannot retract the write: the final directory sync
is completed and a successful receipt may still be returned. Failure of that
final sync returns `ErrRecovery` (unknown outcome), never a false success or a
claim that the write did not happen. Reopen and retry the same operation ID/bytes
to resolve the outcome. Filesystem syscalls themselves are synchronous and cannot
be forcibly interrupted by a context deadline; the adapter starts no detached I/O.

## Reopen and recovery

Open acquires the lock before reading state, bounds directory enumeration and
manifest/object reads, and validates every committed reference, size, hash, C04
payload and quota. It never falls back to an older backup. A missing manifest
with object files, missing/corrupt references, unsupported format, unsafe entry or
unknown file returns `ErrRecovery` and preserves the evidence.

After full validation, Open removes only recognized bounded staging and valid
hash-checked unreferenced objects. Suspicious or oversized staging is retained.
Object cleanup happens only after validating every orphan, so a later bad orphan
cannot cause earlier evidence to disappear. Open syncs the directory and its
parent, including after an interrupted initialization. An empty initial manifest
is published before any object can be created. Recovery cleanup is idempotent;
an interrupted cleanup can be repeated.

For a recovery error: stop writers, retain a private copy of all bytes for
inspection, and restore/repair in a separate location with a compatible reader.
This task provides no destructive repair/import/export command or tested full
backup/restore workflow. Never overwrite newer accepted data with an old backup.

## Errors and security boundary

`errors.Is` distinguishes `ErrLocked`, `ErrConflict`, `ErrQuota`, `ErrRecovery`,
`ErrInvalidInput`, `ErrIO`, `ErrClosed`, `ErrNotFound`, and standard context errors.
Errors contain no operation IDs, input values, paths or raw OS diagnostics.
Open-time malformed/corrupt state is a recovery error; inability to perform a
filesystem operation is an I/O error. A poisoned handle requires reopen.

This profile is a cooperating single writer on a local Linux filesystem, tested
on ext4. `flock` is advisory, not authorization. NFS/SMB, multiple hosts, alternate
platforms and filesystem/hardware flush failures have no certified guarantee.
`os.Root` confines relative paths; it is not a sandbox against a malicious same-UID
process, root, mount replacement or device access. Those local actors are trusted.
There is no network/provider/shell execution in the adapter; no Podman container
is needed for storage tests. Hashes detect accidental mismatches, not a hostile
host rewriting both objects and manifest.

Official references: [Go os.Root](https://pkg.go.dev/os#Root),
[Go File.Sync](https://pkg.go.dev/os#File.Sync),
[Linux flock](https://man7.org/linux/man-pages/man2/flock.2.html),
[Linux rename](https://man7.org/linux/man-pages/man2/rename.2.html),
[Linux fsync and directory flush](https://man7.org/linux/man-pages/man2/fsync.2.html).

## Verification and limits of proof

`go test ./...` collects the public adapter integration tests in
`tests/storage_test.go` and filesystem failure/recovery tests in
`internal/storage/recovery_test.go`. Both use real temporary filesystem state.
The latter starts actual helper subprocesses, observes commit boundaries, issues
SIGKILL and reopens the store. Fault injection replaces individual write/sync/
rename calls while the remaining filesystem operations stay real.

C05 fixtures are repository-authored synthetic data under Apache-2.0; each JSON
manifest records its provenance and license. Positive, invalid and expected-output
fixtures are consumed by tests. Source/tool/filesystem identities, exact commands,
exits, output and fixture hashes are recorded separately in `docs/evidence/C05.json`.

Injected ENOSPC is not physical disk exhaustion, and SIGKILL is not power-loss
certification. No C28 capacity target, authenticated ingestion, full restore,
remote Actions run or C30 readiness follows from these tests. JavaScript lint is
not configured; Go vet and format checks are the available Go static checks.

## C08 additive record support

C08 adds canonical typed enrollment issue/consume objects to the same adapter;
the original C05 event-only proof above remains historical. Manifest shape,
receipts and filesystem guarantees remain unchanged. `Record.Enrollment`
distinguishes metadata from `Record.Event`; `CommitOnceChecked` rejects existing
operation IDs instead of replaying success. See `ENROLLMENT.md` for the approved
service boundary, mixed-store compatibility and forward-only reader recovery.

## C11 compatible extension

The manifest remains version 1 and uses the same atomic publication, hashes,
permissions, writer lock and quotas. `Record.Config` identifies canonical internal
`config.applied` records alongside C04 events and C08 enrollment. Their byte-slice
payload and signature fields use JSON base64 to retain signed bytes exactly. The
public event and desired-state payload caps remain 8192 bytes; internal object
reads have a separate 16384-byte envelope cap so a maximum-size payload still
fits with its signature and acceptance timestamp. `MaxBytes` counts the entire
stored envelope, and each accepted revision consumes an operation.

`Records(ctx)` returns an owned, ordered, quota-bounded snapshot. `Update(ctx,
choose)` reads that snapshot and selects the ID/bytes under the same writer lock
as commit, then reuses the existing publication path. Its callback must not call
back into the store. These operations let C11 check the latest revision and reuse
the exact original envelope on replay atomically; they introduce no second
manifest or persistence engine. Readers predating C11 cannot decode a directory
containing config records. Preserve those bytes and a C11-compatible reader when
rolling back code; do not replace the directory with an older backup.
