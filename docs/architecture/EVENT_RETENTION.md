# Event segment retention (C23)

The local operator can preview and explicitly apply expiration of complete sealed event segments. The active segment, a segment containing any event at or after the cutoff, and an incomplete segment are preserved. The cutoff uses each validated event's `observed_at`, strictly before the supplied UTC instant; storage order is never substituted for event age.

The writer owns the same private directory and exclusive lock as projection and replay. Stop the local supervisor before using retention. An unavailable directory or a held lock produces a typed error. There is no timer, network request, background job or HTTP deletion endpoint.

## Operator workflow

Preview without deleting files or creating an audit decision:

```sh
dist/engine/miragemesh --expire-segments \
  --retention-dir /absolute/private/segments \
  --retention-before 2026-01-05T00:00:00Z \
  --retention-reason 'Operator-approved segment retention' \
  --retention-key operator-retention-2026-01 \
  --retention-max-segments 16 \
  --retention-max-records 2 \
  --retention-max-bytes 32768
```

The limits above are a small synthetic example, not production capacity. Supply the actual writer policy. Add `--retention-apply` to commit that explicit request. The JSON outcome reports `planned`, `applied` or `failed`, a typed `error_kind`, and whether index state is known. CLI usage errors exit 2, runtime failures exit 1, successful preview/apply exits 0. Retention cannot be combined with HTTP, projection, validation, version or other runtime flags. A preview is not a reserved plan: another write between preview and apply can change eligibility, so inspect the apply result.

`Before` must be a past RFC3339 instant with year 1–9999. The reason is 1–1024 Unicode characters and must contain non-whitespace text; the idempotency key is 16–128 characters with the same text validation. The raw key is never stored. Identical key and canonical cutoff/reason replay the original durable decision and time. A changed request with the same key fails with `ErrRetentionConflict`. An empty eligible set is also committed, so a replay cannot unexpectedly delete segments sealed later.

## Durable decision and recovery

`retention.json` is canonical version 1 JSON containing append-only decisions, a hash of each key and request, reason, cutoff, decision time, physical segment length/hash and each exact source identity, sequence, record, length/hash and observed time. Event payloads and request paths are omitted. Each decision has a checksum; this detects corruption, not hostile rewriting by the trusted local owner. The private audit is bounded to 4 MiB and 1024 decisions, including empty decisions. Quota fails before any deletion. This task does not implement audit compaction.

Application holds the existing writer mutex and lock through these steps:

1. Validate the whole request, scan complete sealed frames and cross-check identities with the current index.
2. Write the complete next audit to `.retention.tmp`, sync its file, close it, rename to `retention.json`, then sync the directory.
3. Verify every pending physical file and every decoded record against the durable decision before unlinking any target. Sync the published audit file and directory again before unlinking, including during recovery.
4. Remove only verified sealed segment files, sync the directory, rebuild the live index and return success.

The second audit fence matters when recovery follows an earlier directory-sync failure. Unlinking before that publication is durable could lose both the evidence and the deletion record. File sync alone does not establish directory-entry durability: see [Linux fsync](https://www.man7.org/linux/man-pages/man2/fsync.2.html) and the root-scoped [Go os.Root API](https://pkg.go.dev/os#Root).

A syscall failure poisons the open writer; it refuses to expose a trustworthy index or accept more writes until reopen. Before audit publication, reopen discards only the bounded, private unpublished staging file and preserves segment bytes. After publication, reopen verifies all still-present targets, finishes pending removals and flushes the directory even when a previous attempt already removed them. Missing targets covered by the audit are expected. Corrupt, noncanonical, linked or semantically inconsistent audit metadata and changed pending source bytes fail closed. No unverified target is deleted. A crash after commit but before a reply is recovered by the same key.

These are tested process-crash and syscall-error semantics on the local filesystem. They are not a physical power-loss certification or a distributed storage protocol. The directory is a trusted single-host owner boundary; another process with the owner's authority must not rewrite its files concurrently.

## Index, projection and incident coverage

The live index drops deleted source references and rebuilds from remaining complete frames. If an exact duplicate survives in a protected segment, its reference moves to that actual surviving frame. Retired identities remain in the bounded audit. A conflicting sequence or digest is still an index conflict; an exact expired identity cannot be appended as a new source. C05 projection counts `retained` separately from `already_projected` and does not resurrect expired events. New segment ordinals always exceed both live and retired ordinals, even after the entire sealed log expires.

`Index.Retention` keeps explicit leading, trailing, internal and whole-log gaps. Any retained segment means incomplete coverage, even without a missing ordinal between two live segments. Retention gaps are separate from missing ordinals, incomplete tails and spool loss markers. `Index.Retained` and every returned audit slice are owned snapshots.

The local incident snapshot exposes optional `retained_events` and `coverage.retention_gaps` summaries. The UI presents deliberately expired event sources separately from unprojected events and has a keyboard-accessible retention audit with segment IDs, counts, physical digest, cutoff, reason and decision time. The response remains bounded by the existing 1 MiB replay limit and fails unavailable without truncating history. Event paths and reasons remain inert text. Existing clients without the additive fields remain compatible.

## Scope and rollback

C05 event bytes, receipts, acknowledgements, triage and manifests remain unchanged. Retention here releases segment files only: it neither frees the C05 quota nor securely erases every copy of an event. Sensor health can still use C05 event metadata. Operators requiring full-data erasure need the later documented data-lifecycle workflow.

Keep `retention.json` with the segment directory in backups and keep a C23-compatible reader after accepting this format. Old readers reject the new audit file; downgrading in place or discarding it can lose deduplication and gap evidence. Retain the latest accepted bytes and use forward repair instead of overwriting newer state. Full restore and C30/C40 workflow/release proofs remain separate gates.

Tests use Apache-2.0 synthetic C23 fixtures, real C05/segment files, seven SIGKILL publication/deletion boundaries, eight injected syscall errors, corrupt/linked audits, changed pending bytes and metadata, concurrent replay, quota, mixed timestamps, active/incomplete protection, surviving duplicates, restart and a real browser/supervisor workflow at 360px. No user event directory is used.
