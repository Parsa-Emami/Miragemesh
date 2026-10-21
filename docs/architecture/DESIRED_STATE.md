# C10: signed versioned desired state

The owner-approved C10/F04 scope is an internal Go service that validates one
strictly typed desired-state document, verifies its Ed25519 signature over the
exact submitted payload bytes and keeps the accepted document as the active
configuration of the running process. There is no HTTP, CLI or UI surface in
C10; the engine owns the domain behaviour, UI work stays in `apps/web` and
adapters sit at the boundaries per ADR-0003. The durable applied revision and
the convergence of a config apply after a crash belong to C11.

## Trusted in-process interface

```go
service, err := config.New(config.Verifier{
    PublicKey:  operatorPublicKey,
    Clock:      time.Now,
    MaxSensors: maxSensors,
    Bounds: config.Bounds{
        MinHeartbeatSeconds: 5, MaxHeartbeatSeconds: 3600,
        MinSpoolLimitEvents: 1, MaxSpoolLimitEvents: 12800,
        MinEventBatchLimit:  1, MaxEventBatchLimit:  12800,
    },
})
signature, err := config.Sign(payload, operatorPrivateKey)   // operator side
applied, err := service.Apply(ctx, payload, signature)
document, err := config.Parse(payload)
active, ok := service.Active("sensor-01")
```

`config.New` fails closed on an incomplete configuration and returns
`ErrInvalidInput`; the public key length is checked there because the standard
library panics on a public key of the wrong size, and the key bytes are copied
into service-owned memory so the caller cannot change which signer the
service trusts after construction. The clock is trusted application
configuration, never a field supplied by a document. Tests pass a controlled
clock; production passes `time.Now`.

The signing key is trusted local configuration and is completely independent
from the mTLS collector certificate authorities and revocation material:
`internal/config` does not import `internal/pki`. C10 neither creates, stores,
rotates nor recovers key material, and no key material, public or private, is
committed to the repository or to the fixtures. The tests create one ephemeral
in-memory Ed25519 key pair per test and never write it to the filesystem.

## The version 1 document

```json
{
  "schema_version": "1",
  "sensor_id": "sensor-01",
  "revision": 2,
  "issued_at": "2026-10-21T00:00:00Z",
  "expires_at": "2026-11-21T00:00:00Z",
  "settings": {
    "heartbeat_seconds": 30,
    "spool_limit_events": 4096,
    "event_batch_limit": 64
  }
}
```

`schema_version` describes the document format and is independent from the
operational `revision`; it must equal the existing `contracts.SchemaVersion`.
`sensor_id` is opaque text validated with the C04 `contracts.ValidSensorID`
rules. `revision` is a positive integer that must increase monotonically for
that sensor. `issued_at` and `expires_at` are RFC 3339 timestamps with an
explicit offset, optionally with fractional seconds; the format carries its own
time zone, so a value never depends on the host time zone, and instants are
compared in UTC. The validity window is `[issued_at, expires_at)` and
`expires_at` must be after `issued_at`.

`settings` carries exactly three integers. Their accepted range is explicit
deployment policy (`config.Bounds`), not a limit the engine ships: a
deployment states the accepted range of every setting and the engine rejects
anything outside it with `ErrInvalidInput`. There is no default, no empty
range and no unlimited mode, and an unset or inverted range is an incomplete
configuration that `config.New` rejects.

The C10 fixture carries **proposed** policy, not an already accepted product
limit:

| Setting | Proposed range | Source of the number |
| --- | --- | --- |
| `spool_limit_events` | 1..12800 | the pre-existing byte budget in `product/project.json` (`spool_max_mib` 100) over the pre-existing payload cap (`payload_max_kib` 8), expressed here as an event count |
| `event_batch_limit` | 1..12800 | the same proposed ceiling for one batch |
| `heartbeat_seconds` | 5..3600 | the C10 engineering choice recorded here |

A byte budget is not an accepted event-count limit. The product file carries
`spool_max_mib` and `payload_max_kib`, and the C10 numbers are this task's
proposal for what those two figures mean in events; the storage adapter's own
limits are test settings rather than spool configuration. The owner confirms
the final values when the bounded spool lands in C14 and C15. The engine
therefore hard-codes none of them, so a later card can align the real spool
policy without changing the engine or invalidating a signature.

The three settings must also agree with each other: `event_batch_limit` may
not exceed `spool_limit_events`. A batch larger than the whole spool is an
internally inconsistent document, because the sensor could never hold the
batch it is told to send. C10 enforces this as a document invariant and
rejects such a document with `ErrInvalidInput`. It is a coherence rule between
two fields of the same document, not a product limit; the absolute values and
the drop policy stay deployment policy and later cards.

A member outside the version 1 schema, a duplicated member and a
case-insensitively matched member are all rejected, so a signed payload has
exactly one field reading.

The payload is bounded by the shared `contracts.MaxInputBytes` cap of 8192
bytes, the same cap the C04 event contract uses.

## The signature covers the exact payload bytes

The signature is Ed25519 (`crypto/ed25519`) over the payload bytes exactly as
the operator submitted them. The engine never re-serializes a document: a
re-serialized variant of the same document has different bytes and therefore
fails verification. RFC 8785 canonicalization is not used: the locked module
has no dependency and adding a canonicalization library would mean a new
upstream dependency with its own license pin, which ADR-0003 and this card do
not allow. The consequence is documented rather than hidden: two different byte
encodings of the same document are two different documents, and the strict
member rules keep one unambiguous field reading per payload.

`config.Sign` is the operator side. It refuses to sign a structurally invalid
document and returns the signature of the exact bytes it was given, so the
signed bytes and the submitted bytes are always the same bytes. The accepted
range of the settings is deployment policy, so only the receiving deployment
can judge it and the operator side does not decide it.

Because the signature covers the whole payload, it covers every document field:
a changed `sensor_id`, `revision`, timestamp, setting or schema version
invalidates the signature.

## Typed verdicts and the monotonic revision

`ErrInvalidInput`, `ErrUnsigned`, `ErrInvalidSignature`, `ErrExpired`,
`ErrNotYetValid`, `ErrStale`, `ErrConflict` and `ErrQuota` are the regimes a
caller can assert against with `errors.Is`. `Apply` evaluates them in a fixed
order: a missing signature fails first, then the signature over the exact
bytes, then the document fields (including the coherence of the settings),
then the settings against the deployment bounds, then the validity window and
finally the revision against the active configuration. Context cancellation is
reported before any other verdict. `ErrQuota` bounds the number of sensors the
service tracks.

The validity window is judged twice: once before the state lock is taken and
again under that lock, immediately before the active configuration changes.
A document that expires while the service waits for the lock is therefore
rejected with `ErrExpired` and never becomes the active configuration, which
is the same rule the C08 enrollment service applies to its token expiry.

A desired state is stale when it cannot become the active configuration
because it is older than the active revision (`ErrStale`), because its
validity window ended (`ErrExpired`) or because it is not valid yet
(`ErrNotYetValid`). The same revision with different bytes is a conflict
(`ErrConflict`): a revision may not be redefined. The exact redelivery of the
active revision and its signature is an idempotent no-op that returns the
active configuration unchanged.

Every rejection leaves the active configuration byte-identical: the active
revision, the active payload bytes and the active apply time are unchanged
after a rejected document. The active state owns its own copy of the payload,
and `Active` returns another copy, so neither a caller that mutates the
result of `Apply` nor a caller that mutates the result of `Active` can change
the stored signed configuration.

## Scope limits and the C11 boundary

The active configuration is process state. C10 does not write desired state to
the C05 file adapter and does not change `internal/storage` or
`internal/sensor`: the accepted desired state is not persisted, and a
restarted service starts with no active configuration. The documented recovery
outcome is that the operator re-applies the latest signed desired state; the
durable applied revision and the crash convergence of an apply are C11's
work, together with the sensor reconciliation of observed and desired state.

`internal/config` reads the shared `contracts` bounds (`MaxInputBytes`,
`SchemaVersion`, `ValidSensorID`) without changing that package. The strict
JSON member reader is local to `internal/config` because `internal/contracts`
keeps its own reader private; consolidating the two is left to a later card.

## Verification and limits

`tests/config_signature_test.go` drives the real service with repository
authored Apache-2.0 fixtures under `tests/fixtures/miragemesh/C10/`: it proves
that a signed document becomes the active configuration, that an unsigned,
tampered, re-serialized, wrongly signed, expired, not-yet-valid, stale,
conflicting or structurally invalid document is rejected with its typed error,
and that no rejection ever replaces the active configuration. It also proves
the ownership and timing rules: the result of `Apply` cannot mutate the
active configuration, the configured verification key cannot be changed by the
caller after construction, the validity window is rechecked at acceptance
time, and the accepted range of the settings is deployment policy rather than
an engine limit. The discovery guard requires the C10 anchors.

There is no HTTP, CLI or UI surface, no key generation, storage, rotation or
recovery, no multi-signer support, no fleet or tenant policy and no network
service: the package performs no socket operation at all. C10 does not claim
a durable applied revision, crash convergence, remote Actions execution or
C30/C40 readiness.

Official standard-library sources: [Ed25519 signing and verification](https://pkg.go.dev/crypto/ed25519),
[Ed25519 public key size](https://pkg.go.dev/crypto/ed25519#PublicKeySize),
[RFC 3339 timestamps](https://pkg.go.dev/time#Parse),
[JSON decoder tokens](https://pkg.go.dev/encoding/json#Decoder.Token),
[RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html).
Implementation is checked against the repository-locked Go 1.27.2 source.
