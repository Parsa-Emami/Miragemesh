# C20: append-only incident triage

C20 adds a local, append-only triage label to the existing C05 store. The
OpenAPI triage path is the request-shape contract, not an HTTP endpoint: this
task adds no listener, route, CLI command, UI, schema, migration, dependency or
egress. C16 batch ingestion remains the only event-delivery boundary, and C17
segments remain immutable.

## Request shape

The incident identifier comes from the opaque path parameter, not from the
body. It is 1–255 Unicode code points and names the local incident collection;
C20 does not implement incident correlation.

The body contains exactly two members:

```json
{"status":"investigating","reason":"Synthetic review started."}
```

- `status` and `reason` are strings of 1–4096 Unicode code points each.
- Unknown members, duplicate members, non-string values, trailing JSON values,
  arrays, `null` and malformed JSON are rejected before the writer is called.
- Unpaired UTF-16 surrogates are rejected. Go's `encoding/json` would otherwise
  replace them with `U+FFFD`, silently changing the stored reason.
- The `Idempotency-Key` is 16–128 Unicode code points. Only its SHA-256 digest is
  persisted; the raw key is never written to C05 or returned.

The shared C05 record limit is 16,384 bytes. A request body above that limit, or
a canonical stored record above it, returns an explicit error. Input is never
truncated. In particular, two valid 4096-code-point fields with three-byte code
points can exceed the local record bound even though each field is inside the
OpenAPI length limit; that request is rejected rather than partially stored.

## Durable record

Each accepted request appends one canonical JSON object through
`storage.Store.Update`:

```json
{
  "schema_version": "1",
  "kind": "incident.triage",
  "incident_id": "incident-01",
  "status": "investigating",
  "reason": "Synthetic review started.",
  "key_digest": "64 lowercase hex characters",
  "triaged_at": "2026-10-22T08:34:33.198967751Z"
}
```

The record contains no observed event bytes, event path, source reference,
segment reference or raw idempotency key. Triage therefore cannot rewrite or
copy the observed source event. The existing C05 object, receipt, manifest and
generation rules provide durability and recovery.

`triaged_at` is canonical UTC RFC 3339 with nanoseconds. The operation ID is
`incident-triage/` followed by SHA-256 of
`incident_id || NUL || key_digest`; the operation ID and digest are checked when
history is opened. A record whose operation ID does not match its identity is a
recovery error, not trusted history.

## Semantics

- A new `(incident_id, Idempotency-Key)` appends one record and increments the
  C05 generation.
- Repeating the same key, incident, status and reason replays the original
  receipt and bytes without publishing a new generation. `Replayed` is true.
- Reusing the same key and incident with a different status or reason returns
  `ErrConflict` before any durable change.
- Different incidents have independent key namespaces even when the key text is
  the same.
- `History` returns records in publication order. The last entry is the current
  label; a new key is how a later status is appended. Nothing is updated in
  place or deleted.
- An unknown incident has empty history. It is not an error and is not evidence
  that an incident was observed.

Triage records are neutral compatibility records: C07 sensor sequence checking
ignores them, and C17/C18 projection skips them. They are never events, gaps,
acknowledgements, enrollment records or applied configuration.

## Byte bound and ownership

The 16,384-byte bound is a local C05 adapter limit, not a claim that every
OpenAPI-maximum string fits. There is no silent truncation and no alternate
store. Raising the bound or adding field-level storage is a later storage design
change, not part of C20.

C20 stores the label only. C21 owns health presentation, C22 owns the
user-facing segment/incident trace, and C23 owns retention/deletion. No
retention, export, replication or remote synchronisation is implemented here.

## Verification

Repository-authored Apache-2.0 fixtures are in
`tests/fixtures/miragemesh/C20/`. The acceptance tests exercise real C05 files,
restart and history replay; reject malformed and hostile bodies before the
writer; prove the C05 event record and C17/C18 segment bytes and index are
unchanged; continue the next sensor sequence after a triage record; validate
maximum ASCII and explicit multibyte rejection; and require the `incidents`
package to have no network or process-execution imports. See
`docs/engineering/ENGINE_TESTS.md` for the exact anchors.
