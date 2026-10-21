# C11: durable applied configuration

The internal sensor applier reconciles C10 signed desired state with C05 durable
records. The committed configuration is the observed configuration in this slice.
C14 consumes the persisted `spool_limit_events` setting through the internal
spool service below. Decoy settings and batch consumers remain separate work.
This does not claim an external provider has applied the settings.

```go
applier, err := sensor.NewApplier(ctx, store, verifier) // same config.Verifier as C10
accepted, err := applier.Apply(ctx, payload, signature) // config.Applied
observed, exists, err := applier.Active(ctx, "sensor-01")
document, err := config.Parse(observed.Payload) // typed settings when exists
```

`NewApplier` requires an open C05 store and the explicit C10 verifier policy. It
validates all persisted config history before returning. `Active` reads the current
manifest snapshot and reports storage errors explicitly, so another applier using
the same handle cannot leave a stale successful cache hit. Results own their bytes.
The original C10 process-local service keeps its documented behaviour.

## Acceptance and replay

New requests use the same Ed25519 verification, exact-payload parsing, settings
bounds, sensor quota and validity window as C10. Admission checks the clock again
after acquiring the storage writer lock and reading the history, immediately
before filesystem effects. Cancellation before publication cannot acknowledge a
new revision. Once the manifest is published, C05 finishes its flush even if the
context becomes cancelled.

The canonical internal envelope contains `schema_version: "1"`,
`kind: "config.applied"`, base64 `payload`, base64 `signature`, and UTC
`applied_at`. The signed desired-state document is unchanged. A stable operation
ID uses `config/<sha256(sensor_id)>/<revision>`; IDs never become filesystem paths.
The same current revision and exact payload reuses the original envelope and
acceptance time. An older revision returns `config.ErrStale`, even if that revision
was once committed. Different bytes for the current revision return
`config.ErrConflict`. No rejection replaces authoritative state.

`Store.Update` selects and commits under one writer lock, including checks against
the full durable revision history. Multiple appliers sharing a handle therefore
serialize decisions. Separate handles/processes remain subject to C05's exclusive
directory lock. History is bounded by the explicit operation/byte/manifest quotas;
it has no compaction or unlimited retry. Quota exhaustion returns `storage.ErrQuota`.

## Crash and recovery

There is one authoritative publication: the C05 manifest. A successful `Apply`
returns only after the object and manifest publication/directory flush complete.
`Active` reconstructs from these records, so a crash cannot leave a separately
persisted revision ahead of the configuration bytes.

| Interrupted phase | Revision visible after process restart |
| --- | --- |
| Staged bytes; renamed object; before manifest rename | Complete previous revision |
| Manifest renamed; directory flushed before acknowledgement | Complete new revision |

An I/O error after filesystem work starts poisons that handle, following C05.
`Apply` returns an empty result and a typed storage error; `Active` also fails until
the store is reopened. A failed directory flush after manifest rename has an
uncertain durability outcome: reopening may reveal the complete new revision.
Retry against the reopened store converges without a duplicate revision.
SIGKILL tests verify local restart visibility, not physical power-loss durability.

Recovery rechecks each record's canonical envelope, object hash, signature, typed
document, deployment bounds, operation ID and strictly increasing per-sensor
revision. Its time check uses the recorded acceptance instant. A configuration
that subsequently expires remains the last known applied state and preserves the
revision floor; new expired submissions are rejected. Recovery does not renew or
re-admit it. `AppliedAt` is local storage metadata, not an operator-signed timestamp.
The private local store and authoritative clock remain trusted as in C05/C10.

The configured key and bounds must cover persisted history. A changed key or
incompatible bounds fail closed with `storage.ErrRecovery`; key rotation/recovery
policy remains later work. Host clock rollback or malicious replacement/deletion
of the whole local history is not defended against.

## Compatibility and rollback

No database schema, migration, environment file, Dockerfile, public transport,
key lifecycle or dependency changes. C04 event and C08 enrollment bytes and the
version 1 manifest stay compatible with the new reader. Event sequence checks
skip config records. Internal envelope reads allow 16384 bytes while the public
payload cap stays 8192 bytes; byte quota includes the encoded envelope.

After config data is accepted, keep the directory and a C11-compatible reader.
An older reader rejects the new record type. Do not delete accepted revisions or
restore an older backup to make a rollback succeed. This implementation does not
perform a rollback or migration of user data.

The byte encoding follows [Go JSON byte-slice encoding](https://pkg.go.dev/encoding/json#Marshal);
signature verification follows [Go Ed25519](https://pkg.go.dev/crypto/ed25519#Verify).
The persistence mechanism reuses C05's [file synchronization](https://pkg.go.dev/os#File.Sync).

## C14 bounded offline spool

```go
queue, err := spool.New(store, applier) // borrowed C05 store and its C11 applier
receipt, err := queue.Enqueue(ctx, eventBytes)
records, err := store.Records(ctx) // existing owned, bounded durable snapshot
```

`Enqueue` uses the existing C04 decoder, C07 sequence and event identity checks,
and the same `sensor/<sha256(sensor_id)>/<sequence>` operation ID. It stores the
exact original event bytes in the unchanged C05 version 1 manifest. A successful
receipt follows the final directory flush; reopening and replaying the same
bytes returns the original receipt, including when the spool is full.

The additive `sensor.AcceptBounded` helper reads and authenticates the current
applied configuration and checks the per-sensor retained-event count inside
`Store.Update`, under the same writer lock and publication path as C05 commits.
Configuration changes and competing queue instances therefore share one ordered
transaction. The store and applier must refer to the same handle: a mismatch
returns `config.ErrInvalidInput` before a write. Missing dependencies or a nil
queue return `spool.ErrInvalidInput`; no applied configuration returns
`spool.ErrUnconfigured`. Event, context and storage errors retain their existing
typed semantics. Stored config history is verified at its original acceptance
time, following C11's last-known applied-state semantics.

The signed `spool_limit_events` is the per-sensor bound. Other sensors,
enrollment records and config history do not consume that event count; C05's
global operation, byte and manifest quotas still apply. A new event at capacity
follows C15's drop-new policy. After the event has been validated and its loss
marker durably committed, `Enqueue` returns a zero event receipt and an error
matching `spool.ErrDropped`; a retry of the exact dropped bytes returns the same
typed outcome without another marker. The per-sensor loss query rebuilds its
count and contiguous sequence ranges from C05 records. Lowering the signed bound
retains all accepted bytes. Marker records do not consume the signed event
count, but they do consume C05's global quotas; if those quotas prevent marker
publication, the call returns `storage.ErrQuota` and does not report a recorded
loss.

C15 adds the canonical internal `spool.gap` record to the C05 version 1
manifest without changing the manifest or C04 event schema. It carries sensor
and event identity, sequence and the SHA-256 digest of the omitted exact input.
Stable operation IDs make retries idempotent; sensor sequence validation treats
a gap as the sequence that was lost, allowing later events after a configuration
raises capacity. The marker does not retain the lost event payload.

C16 adds durable collector acknowledgements and capacity reclamation below; gap
markers remain loss history and are never acknowledged. C14/C15 add no ACK API,
network transport, CLI, browser write surface or dependency. Existing
`sensor.Accept` callers, including the decoy, keep their C07 behavior; they are
not routed through this new consumer automatically. C26 and C30 remain the
combined resilience and complete workflow gates.

Rollback after a C15 gap has been written requires a C15-compatible reader;
C14 readers reject the new record type. Preserve accepted events and gap
history, and never restore an older manifest to remove them. C14 tests exercise
the real queue during five SIGKILL boundaries and nine filesystem faults through
C05's existing test-only seam. These tests establish local restart visibility
and injected-error recovery, not physical power-loss durability or measured C28
capacity.

## C16 collector batches and durable acknowledgements

```go
ingestor, err := collector.New(store, applier) // same C05 handle and C11 applier
result, err := ingestor.Ingest(ctx, "sensor-01", collector.Batch{
	ID: "batch-01", FirstSequence: 1, LastSequence: 2,
	Events: [][]byte{firstEventBytes, secondEventBytes},
})
```

`internal/collector` is an internal Go boundary. It adds no network listener,
HTTP route, mTLS terminator, CLI or UI. The sensor ID is supplied by the caller
and is not an authentication claim; C09's mTLS guard remains a separate building
block, and no authenticated ingest endpoint is claimed here. C16 proves the
duplicate-free durable delivery semantics that a future transport can call.

The batch shape follows the existing OpenAPI `/sensors/{sensor}/events/batch`
contract: a correlation `batch_id`, inclusive `first_sequence` and
`last_sequence`, and exact C04 event bytes. `batch_id` is correlation metadata,
not event identity. Event identity is `(sensor_id, sequence)` with exact bytes
and digest, matching `contracts/event-types.v1.json`. The batch must be
contiguous, within C04 limits and within the applied signed `event_batch_limit`.
The whole batch is decoded and checked before the first visible write; a replay
of exactly the accepted bytes is not a new observation, while different bytes
for the same event identity return `storage.ErrConflict`.

For each event, `Ingest` uses `sensor.Accept` (C07), which persists the exact
event bytes and advances the per-sensor sequence. After every event in the batch
is durable, it commits one append-only `spool.ack` record per event through
`Store.Update`, under the same writer lock and C05 publication path. An ACK
contains `schema_version`, `kind`, `sensor_id`, `event_id`, `sequence` and the
SHA-256 `input_digest` of the accepted event. Its stable operation ID is
`spool-ack/<sha256(sensor_id)>/<sequence>`; it is an opaque identifier, never a
filesystem path. `Ingest` returns only after all events and all ACKs are
durable, so retrying after a lost acknowledgement returns the original receipts
and creates no duplicate observation.

ACKs do not delete or rewrite event bytes and do not change the C04 event or C05
manifest schema. They consume the explicit C05 operation, byte and manifest
quotas. `spool.Enqueue` counts only events without a valid ACK toward the signed
`spool_limit_events`, so acknowledging delivered events reclaims spool capacity.
A gap is loss history and cannot be acknowledged; a forged, orphaned, duplicate
or future ACK fails sequence/history validation with `storage.ErrRecovery` or
`storage.ErrConflict` and reclaims no capacity. C15 loss counters and ranges are
preserved.

The collector accepts no filesystem path. `metadata.path` remains inert C04
text: traversal- or symlink-looking values are never resolved, opened or used as
storage names. The replay test uses `../../etc/passwd` and a symlink path and
proves an outside sentinel is unchanged; there is no path input to reject before
commit because the event bytes are the only input. The package imports only the
standard context, hashing/JSON, error/format and UTF-8 packages plus internal
config, contracts, sensor and storage; it has no `net`, `os`, `os/exec`,
`path/filepath` or `syscall` import, and the discovery anchor enforces that
allowlist.

C16 adds canonical `spool.ack` records to the version 1 manifest. Readers
predating C16 reject a store containing them; rollback must retain the latest
event and ACK bytes and a C16-compatible reader. Never delete an event while its
ACK remains. C17/C18 segmentation and indexing must skip `spool.gap` and
`spool.ack` as event records, and C23 retention must remove or preserve them
consistently with their event. C16 adds no database schema, migration,
environment file, Dockerfile, sibling import or public surface.
