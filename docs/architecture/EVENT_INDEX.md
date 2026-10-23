# C18: derived event index and deduplication checkpoints

C18 adds a derived, in-memory index over the committed C17 segments. It is
rebuilt from the segment files when the writer is opened; there is no durable
index file, no checkpoint directory and no separate index command. Closing and
reopening the writer after losing the process is the supported way to rebuild
the index. The index is owned by `internal/events` and does not add an HTTP
surface, listener, schema, migration or dependency.

C17 remains the segment-format and crash-recovery contract. C18 changes only how
`Append`, `AppendRecords`, the one-shot `--project-segments` workflow and their
typed outcomes behave on top of that storage. Segment IDs, framing, sync order
and incomplete-tail handling are unchanged.

## What is indexed

One `Entry` represents one unique committed event:

- `SensorID` and `EventID` are the identity used for deduplication.
- `Sequence` is the C07 per-sensor sequence carried by the accepted event.
- `Segment` and `Record` locate the exact segment ID and one-based record number.
- `Digest` is the lowercase SHA-256 of the exact stored payload bytes.
- `Bytes` is the payload length without the framing newline.

Only complete newline-terminated valid records become entries. An incomplete
tail reported by C17 is status metadata, not an event, and is excluded from the
index. A torn record is not retried implicitly.

The index keeps the first occurrence of each identity. An exact repeat with the
same digest and sequence is tolerated so that stores projected twice before C18
remain readable; it increments `Duplicates` and is not added as a second entry.
The same sensor/event identity with different content or sequence is an
`ErrIndexConflict`, not a second event and not silent success. Conflicts are
also detected while `Open` rebuilds the index, so an already ambiguous segment
directory fails closed instead of producing a trusted index.

Each snapshot also reports:

- `Records`: unique indexed event records.
- `Sensors`: distinct sensor IDs among those records.
- `SegmentIDs`, `FirstOrdinal`, `LastOrdinal`: present segment files in order.
- `Missing`: exclusive ordinal ranges between present segments.
- `Incomplete`: preserved tails, using the C17 Offset/Bytes/Digest meanings.
- `Complete`: no internal ordinal gap and no incomplete tail.

`Complete` is a statement about index coverage, not about sensor-sequence
completeness. C15 gap records, C23 retention and a missing segment can all remove
evidence from the view. Absence from the index never proves that an event was
never ingested, and a present entry proves only that one complete record was
durably written at that location.

A missing ordinal range is deliberately reported as `After`/`Before`, for
example `{After: 1, Before: 3}` for a removed segment 2. Deleting the lowest or
highest present segment creates no internal range and is indistinguishable from
a short history; C23 must preserve an ordinal high-water mark before all
segments can be removed.

## Interface

```go
func (w *Writer) Index() (Index, error)

func (i Index) Entries() []Entry
func (i Index) Lookup(sensorID, eventID string) (Entry, bool)
```

`Index` is an owned snapshot: its slices cannot mutate the writer and its lookup
maps are rebuilt for the snapshot. `Entries` returns storage order (segment
ordinal, then record number). `Lookup` answers only "is this identity in this
snapshot"; it is not proof of non-ingestion when it returns false.

`Projection` now reports `Appended`, `Skipped`, `AlreadyProjected`, `IndexKnown`
and `Rebuilt`. `Rebuilt` is the index snapshot captured under the writer lock
before any append in that call. Holding the lock across the snapshot and the
appends is what makes deduplication a checkpoint rather than a best-effort read:
two concurrent projections cannot both decide to write the same event.

## Deduplication in the append path

`AppendRecords` normalizes each storage record exactly like `Append`, then checks
the rebuilt index before writing:

- identity absent: append normally;
- identity present with the same digest and sequence: count
  `AlreadyProjected` and write nothing;
- identity present with different content or sequence: return
  `ErrIndexConflict` without writing.

`Append` performs the same identity check, so direct callers cannot bypass the
checkpoint. An exact duplicate is still an append from the direct API's point of
view: the bytes are written and the index records a duplicate count. A conflicted
append is rejected before any file is created or changed, and an index conflict
does not poison the writer.

The one-shot `--project-segments` command therefore becomes repeatable. Its JSON
outcome adds:

```json
{
  "already_projected": 5,
  "index_known": true,
  "index_records": 5,
  "index_sensors": 2,
  "index_complete": true,
  "index_duplicates": 0,
  "deduplicated": true
}
```

`index_missing_ordinals` appears when an internal segment ordinal is absent, and
`index_incomplete_segments` counts preserved tails. `error_kind:"conflict"`
identifies `ErrIndexConflict`. A failed projection still reports the durable
segment state and, when the writer could build it, the index snapshot; an
unknown index state is never reported as an empty one.

## Error and recovery semantics

`ErrIndexConflict` is a typed input/evidence conflict. It is returned before
bytes change, so callers may repair the C05 or segment evidence and retry.
Reopening after a genuine index loss rebuilds from disk; the caller should then
project again, and records already committed are counted instead of duplicated.

The index adds no new durability claim. A record written before a reported
`ErrIO` may still be present, so callers resolve the outcome by reopening and
using the rebuilt index. In-memory index loss is harmless by design; losing a
segment file is not repaired or hidden, and shows up as an ordinal range or as
an absent entry.

## Boundaries and future cards

C18 does not add alerts, queries, traces, retention, deletion, a UI, a public
endpoint or a second authority. C19 alert rules may reference indexed source
IDs; C22 will trace a source to its segment; C23 performs retention with audit
metadata and must keep ordinal gaps explainable. C30 remains the clean-host
workflow, restart and restore gate.

## Verification

`tests/rebuild_test.go` covers rebuild from committed segments, restart,
identity conflicts, modified bytes, missing segments, incomplete tails,
idempotent reprojection and no-network imports. `cmd/miragemesh/segments_test.go`
runs the real child-process workflow twice, verifies deduplication, reports
index coverage after segment loss and keeps C05 receipts unchanged. The discovery
guard requires these anchors. Fixtures under `tests/fixtures/miragemesh/C18/`
are repository-authored Apache-2.0 synthetic data. Exact commands, exits and
source identity live in `docs/evidence/C18.json`.

## Opaque identities and multiline payloads

In-memory identity maps use a two-string tuple, not delimiter concatenation.
NUL and other valid opaque identifier characters cannot merge distinct sensor
and event identities. Rebuild and alert derivation preserve the same tuple
semantics. Multiline string frames are decoded by the segment reader before
indexing, so source digests refer to the exact normalized C04 payload. See the
compatible multiline frame extension in `EVENT_SEGMENTS.md`.

## C23 retained identities

The rebuilt live index excludes expired files and retains explicit audit gaps, including leading/trailing/whole-log gaps. Any retention gap makes coverage incomplete. Exact retired identities cannot be resurrected by C05 projection; different bytes or sequences conflict. Surviving duplicate references rebuild to their actual remaining frame. See [EVENT_RETENTION.md](EVENT_RETENTION.md).
