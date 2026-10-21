# C11: durable applied configuration

The internal sensor applier reconciles C10 signed desired state with C05 durable
records. The committed configuration is the observed configuration in this slice.
Decoy, spool and batch consumers remain C12-C16 work. This does not claim an
external provider has applied the settings.

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
