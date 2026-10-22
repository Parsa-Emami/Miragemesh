# C17: immutable event segments

C17 adds a standalone append-only JSONL event log in `internal/events`. It is the
segment-storage boundary, not a second authoritative acceptance store and not a
collector, transport, API or UI. The engine binary exposes one bounded,
one-shot projection command so the writer has a real runtime caller; it opens no
listener.

C05 remains authoritative for acceptance receipts, spool records, ACKs,
configuration and enrollment. C16 remains authoritative for whole-batch
validation and durable ACK publication. `AppendRecords` reads an already-owned
C05 snapshot and projects only validated event records; it does not rewrite C16
receipts or ACKs, and no atomicity between a C16 commit and a segment append is
claimed. A segment failure is a separate typed outcome. C17's original behavior
appended every supplied record, including repeats; that no-deduplication behavior
is historical. C18 rebuilds a derived index from the committed segments and uses
it as the projection checkpoint. The C18 contract lives in
`docs/architecture/EVENT_INDEX.md`; this document remains the segment-format and
crash-recovery contract.

## Interface

```go
func Open(directory string, limits Limits) (*Writer, error)
func (w *Writer) Append(ctx context.Context, raw []byte) (Ref, error)
func (w *Writer) AppendRecords(ctx context.Context, records []storage.Record) (Projection, error)
func (w *Writer) Index() (Index, error)
func (w *Writer) Segments() ([]Segment, error)
func (w *Writer) Close() error
```

`Ref` reports the stable segment ID, one-based record number, sensor/event
identity, sequence, SHA-256 digest of the stored payload and its byte length.
`Segment` reports the stable ID, complete-record count, file bytes, whether it is
sealed, and optional `Incomplete` metadata. `Index` is the derived snapshot
described in `docs/architecture/EVENT_INDEX.md`. `Projection` reports appended
event records, already-indexed records and intentionally skipped non-event
records, plus the index snapshot captured before the call.

Limits are mandatory and have no product default or unlimited mode:
`MaxSegments > 0`, `MaxRecordsPerSegment > 0`, and
`MaxBytesPerSegment >= contracts.MaxInputBytes + 1` (at least 8193 bytes, enough
for the 8192-byte event payload plus its framing newline). Invalid values,
including zero where invalid, return `ErrInvalidInput`. Fixture values are test
policy, not measured capacity.

## Runtime projection command

The engine runtime provides a one-shot command path in
`cmd/miragemesh/segments.go`; it does not add an HTTP endpoint or a second service:

```sh
dist/engine/miragemesh --project-segments \
  --storage-dir /path/to/existing-c05-store \
  --segments-dir /path/to/immutable-segments \
  --storage-max-operations 64 \
  --storage-max-bytes 1048576 \
  --storage-max-manifest-bytes 65536 \
  --segments-max-count 8 \
  --segments-max-records 2 \
  --segments-max-bytes 8193
```

The command requires an existing C05 `manifest.json`; it refuses to initialize a
missing acceptance store. The storage and segment directories must be distinct
and must not contain one another, because placing segment files inside C05 would
corrupt its inventory. The command opens the C05 store, reads its owned snapshot,
opens the segment writer, appends only event records and exits. It does not write
a C05 receipt or ACK.

The JSON outcome has `scope`, `status`, `appended`, `skipped`,
`already_projected`, `segments`, `segments_known`, `incomplete_segments`, exact
`incomplete` Offset/Bytes/Digest metadata, `deduplicated:true`,
`atomic_with_c16:false`, and the C18 index coverage fields `index_known`,
`index_records`, `index_sensors`, `index_complete`, `index_duplicates`,
`index_incomplete_segments` and optional `index_missing_ordinals`. On failure it
adds `error` and `error_kind`; a C18 identity conflict uses
`error_kind:"conflict"`. Exit `0` means projection completed, `2` means invalid
configuration or limits and `1` means a runtime, storage or segment failure. A
repeated invocation is deduplicated: records already in the rebuilt index are
counted in `already_projected` and are not written again. Historical C17 output
reported `deduplicated:false`; current evidence for the deduplicating workflow is
in `docs/evidence/C18.json`.

A failed projection still reports the durable state that exists. When the append
fails after some records were written, the command snapshots the segment writer
before returning, so `segments`, `incomplete_segments` and `incomplete` describe
the sealed and active files that are already on disk. `segments_known` is then
`true`. If the writer is poisoned or closed and cannot expose a trustworthy
snapshot, `segments_known` stays `false` and the counts stay unset: an unknown
state is never reported as an empty segment store.

## Version 1 disk protocol

The directory is private (0700) and contains one `.lock` plus segment files:

- active: `segment-<20-digit-ordinal>.jsonl`
- sealed: `segment-<20-digit-ordinal>.sealed.jsonl`
- incomplete: `segment-<20-digit-ordinal>.incomplete.jsonl`

The ordinal is an internal storage ordinal, not an event sequence. A segment ID
(`segment-<20 digits>`) is stable across active-to-sealed and
active-to-incomplete transitions.

One exclusive nonblocking `flock` is held for the handle lifetime. Every file is
opened through `os.Root` with no-follow/nonblocking flags and exact owner,
regular-file, mode 0600 and single-link checks. Unknown entries, symlinks,
hardlinks, public modes, malformed names, zero ordinals, duplicate ordinals and
oversized files fail closed with `ErrRecovery`; permissions are never repaired
implicitly.

An append validates the complete event before creating or changing any file:

1. Accept at most one trailing framing newline and reject empty payloads,
   payloads over 8192 bytes and invalid C04 events. Internal newlines are
   preserved by the encoded-frame extension below.
2. Create the first active file with `O_EXCL`, sync the directory, then append
   exactly one payload plus `\n`.
3. Sync the active file before returning success.

Rotation happens before an append that would exceed the record or byte limit:

1. Sync and close the active file.
2. Rename it to `.sealed.jsonl`.
3. Sync the directory, so the sealed file is durable before any new active file.
4. Create the next active file with `O_EXCL` and sync the directory.
5. Append and sync the new record.

Empty active files are allowed after a crash between steps 4 and 5. Empty sealed
or incomplete files are malformed. The ordinals do not have to be contiguous:
deleting a lower sealed segment is a retention fact and is not an event sequence
gap. C17 defines no deletion command. C23 must make deletion explainable with
retention/audit metadata and must not use a missing segment as proof that no
event was lost. The next ordinal is derived from the highest present segment, so
retention must preserve an ordinal high-water mark before all segments can be
removed.

## Incomplete final record

Only complete, newline-terminated valid records are events. If Open finds an
active file whose final bytes have no terminating newline, it preserves those
bytes unchanged and renames the file to `.incomplete.jsonl`; it does not write a
JSON marker into the JSONL stream and does not turn the tail into an event. The
complete valid prefix remains readable.

`Incomplete` has exactly these meanings:

- `Offset`: byte offset in the file where the incomplete record begins.
- `Bytes`: number of preserved tail bytes.
- `Digest`: lowercase SHA-256 of exactly those tail bytes.

The incomplete file itself is reported as `Sealed: true` with `Incomplete` set.
Its `Records` count covers only the complete prefix. A tail is metadata/status,
not an event and not a sequence gap. A torn record may be retried only by the
caller after accounting for the explicit incomplete marker.

Open also treats a sealed file with a tail, an incomplete file without a tail,
an incomplete tail above its frame bound, a blank line, a malformed complete
record or an over-bound decoded payload as `ErrRecovery`. Recovery is fail-closed and
preserves evidence; there is no automatic destructive repair, import or truncate
command.

## Projection and ownership boundaries

`AppendRecords` appends only `storage.Record.Event` records. It skips
`spool.gap`, `spool.ack`, enrollment and applied-config records. A blank record
that is none of those, or an ambiguous record carrying both an event and a
non-event marker, returns `ErrRecovery` without writing. Skipping is not loss:
the non-event bytes remain in C05 and are owned by C15/C16/C08/C11.

Projection deduplicates through the C18 index rebuilt at `Open`. An exact repeat
of a committed identity is skipped and counted; the same identity with different
bytes or sequence is `ErrIndexConflict` before any write. The segment directory
must not be used as C16 authority and C16 must not dual-write segments. See
`docs/architecture/EVENT_INDEX.md` for coverage semantics and the rule that
absence is never proof of non-ingestion.

## Errors and recovery

`errors.Is` distinguishes `ErrLocked`, `ErrQuota`, `ErrRecovery`,
`ErrIndexConflict`, `ErrInvalidInput`, `ErrInvalidEvent`, `ErrIO` and `ErrClosed`,
plus standard context errors. A context cancelled before filesystem work leaves
the writer usable. An I/O or unknown directory-sync failure poisons the handle;
close and reopen to recover. A complete record written before a reported `ErrIO` may still
be present, so callers must resolve the outcome by reopening and using the
rebuilt C18 index, not by assuming the append did not happen.

C17 is a cooperating single-writer local Linux/ext4 profile. `flock` is advisory,
not authorization. Same-UID/root/mount-replacement attackers are outside this
sandbox profile. There is no network, provider, shell or container execution in
the package. SIGKILL and injected syscall failures prove local process-crash and
I/O-error recovery, not physical power-loss certification.

## Verification and future compatibility

`internal/events/segments_recovery_test.go` covers real child-process SIGKILL at
seal-rename, post-rename, next-create, torn-write and incomplete-rename
boundaries, plus injected create/rename/sync/write failures. `tests/rotation_test.go`
covers record/byte rotation, restart/immutability, ordinal gaps, incomplete
Offset/Bytes/Digest preservation, max-frame and invalid inputs, unsafe inventory
including zero ordinals, C16 projection, non-atomic C16/segment failure and
no-network imports. `cmd/miragemesh/segments_test.go` runs a real child process
through the engine flags and verifies the C05 snapshot projection, exact
incomplete metadata, typed failures, unchanged C05 receipts, rejection of
overlapping storage/segment directories, the durable segment state of a failed
quota projection and the unknown-state marker when the writer cannot report. Both the package tests and the
projection workflow test pass under a network-syscall trace with no socket,
connect, bind or listen calls observed. C18 adds `tests/rebuild_test.go` and the
deduplicating projection workflow anchor. The discovery guard requires these
anchors. Fixtures under `tests/fixtures/miragemesh/C17/` are repository-authored
Apache-2.0 synthetic data. Exact command output and source identity live in
`docs/evidence/C17.json`; the C18 contract is verified separately in
`docs/evidence/C18.json`.

Future cards: C18 rebuilt the derived index without changing segment IDs; C19
alerts may reference indexed source IDs; C22 traces a source to its segment;
C23 performs retention with audit metadata; C30 is the clean-host workflow,
restart and restore gate. No C19-C30 capability is asserted here.

Official references: [Go os.Root](https://pkg.go.dev/os#Root),
[Go File.Sync](https://pkg.go.dev/os#File.Sync),
[Linux flock](https://man7.org/linux/man-pages/man2/flock.2.html),
[Linux rename](https://man7.org/linux/man-pages/man2/rename.2.html),
[Linux fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

## Compatible multiline frames (C01–C21 review remediation)

The reader still accepts every existing object JSONL frame. Existing segment
bytes are never rewritten. Input normalization retains the established rule of
removing at most one trailing framing LF; the remaining payload, including
internal newlines and other whitespace, is the indexed evidence.

When that payload contains LF, the writer stores one canonical JSON string
containing the base64 encoding of its exact bytes, followed by the framing LF.
Go's `encoding/json` maps `[]byte` to this representation. A top-level string
cannot be a C04 event, so it is unambiguous beside legacy object frames. The
reader requires canonical base64 JSON, decodes it, enforces the 8192-byte payload
limit and applies the ordinary C04 validator. The index `Digest` and `Bytes`
refer to decoded payload bytes, never to the encoded string. Direct append,
projection, restart/rebuild, deduplication and alert references share that rule.

The largest encoded frame is 10,926 bytes plus one framing LF. The existing
minimum segment quota of 8193 bytes remains accepted for compatibility; use at
least 10,927 bytes to accommodate every encoded payload. A frame that exceeds
the explicitly configured segment byte quota returns `ErrQuota` before file
creation or rotation. Encoded bytes count toward rotation and disk bounds.

A torn string frame is preserved without decoding as incomplete evidence;
Offset/Bytes/Digest describe the raw tail. Its maximum tail bound is 10,926
bytes; a legacy object tail remains bounded by 8192 bytes. Only complete frames
become events. Recovery keeps valid preceding events and the exact torn bytes.

This is an additive file-adapter encoding extension, not a database schema or
migration. Older readers remain usable for directories containing only legacy
object frames. After a string frame is written, downgrade to a reader without
this extension is unsupported and fails closed. Preserve the accepted source
store and segment bytes and use the compatible reader; never truncate or
re-serialize accepted history to force a downgrade.

Regressions cover accepted pretty JSON through projection and alerts, index
rebuild/replay, the maximum encoded payload, quota rejection, malformed encoded
frames and preservation of a torn encoded tail alongside a valid record.
Reference: [Go JSON byte encoding](https://pkg.go.dev/encoding/json#Marshal).
