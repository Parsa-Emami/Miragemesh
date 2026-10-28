# MirageMesh local service and privacy policy

Policy revision: C38, 2026-10-28. Applies to the repository's `0.0.1` local
profile. It records supported behavior, not a published v1 release. C39/C40
remain the release gates. This policy and [MAINTENANCE.md](MAINTENANCE.md)
supersede earlier guide examples or promises that conflict with these limits.

## Supported profiles and responsibility

The verified full-workflow reference host is Linux amd64, Ubuntu 24.04, with
Node 24.19.0, npm 11.9.0, Go 1.27.2 and rootless Podman 4.9.3. Exact hashes,
licenses and preparation commands are in
[the toolchain lock](../engineering/toolchain-lock.json) and
[clone-to-run guide](../engineering/CLONE_TO_RUN.md). Other distributions,
WSL2, macOS, Windows, other architectures, NFS/SMB and multi-host storage need
their own evidence before being advertised as supported full-workflow hosts.

`local-demo` uses repository-authored synthetic events. `local-private` is a
single trusted operator on a private local filesystem: the operator provisions
keys, checks permissions, revocation and expiry, controls retention, and tests
recovery before admitting sensitive data. Loopback HTTP is not authentication
between OS users. A process with the operator's UID can read files and call the
local API. Public ingress, hostile multi-tenancy and a hosted service SLA are
outside this profile; an optional reverse proxy does not establish those claims.

All core features and source are available under Apache-2.0 with compatible
upstream notices. No hosted subscription, paid core feature, proprietary
entitlement, cloud account, owned domain or sibling clone is required. The
software is provided as is under [LICENSE](../../LICENSE); availability,
response times, incident detection, zero loss and secure erasure are not
guaranteed services. See [the maintenance policy](MAINTENANCE.md) for support.

## What is retained

An accepted v1 event contains `schema_version`, `sensor_id`, `event_id`,
`sequence`, `observed_at`, `kind` and `metadata.path`. Exact accepted bytes are
stored with receipts; validation is not anonymization or secret detection.
Identifiers, times and paths can identify people or systems. The metadata-only
HTTP decoy records the validated URL path and discards the query, headers and
body; it does not make operator-supplied event paths safe to publish.

The C05 ledger also retains signed applied configuration, enrollment issue and
consumption metadata, certificate lifecycle, update/revocation/recovery state,
spool ACKs and explicit loss gaps, and incident status/reason history. Tokens
and idempotency keys are hashed in their respective records; operator-held raw
tokens and private signing keys remain secrets. Retention audits retain source
identities, digests, cutoff, time and operator reason, even after segment bytes
are removed. Do not put secrets in paths, reasons, filenames or reports.

## Data locations and ownership

There is no automatic `~/.local/state/miragemesh` discovery. `npm start` without
explicit domain options starts the shell and health runtime; it does not seed
sensor data. Record the absolute paths and limits supplied to each enabled
mode. The same C05 ledger may back several read surfaces; do not copy it once
per tab or run a second writer against it.

| Data | Actual location / selector | Lifecycle |
| --- | --- | --- |
| Accepted C05 objects, manifest and receipts | Explicit `--sensor-status-dir`, `--incident-state-dir`, `--rotation-state-dir`, `--update-state-dir`; standalone projection uses `--storage-dir` | Private directory mode `0700`, files `0600`; `.lock`, `manifest.json`, `object-*.json`, recognized `.stage-*` files. Never edit individual records or unlink a held lock. |
| Event projection and retention audit | Explicit `--incident-segments-dir`; standalone `--segments-dir` or `--retention-dir` | Separate private directory and lock; active/sealed/incomplete JSONL, `retention.json`. The index rebuilds from retained files and audit. |
| Isolated decoy state | Explicit `--decoy-state` | Separate operator-owned private mount; include it in the inventory if used. The artifact mount is read-only. |
| Trust and private material | Operator-chosen key, issuer, certificate, CRL, signed metadata, candidate and token files passed to the relevant mode | Inventory separately; keep private signing/CA/recovery keys off the browser path and outside source/artifacts. Loss or disclosure requires the documented rotation/revocation procedure. |
| Verified installation metadata | `--prefix` contains `install-state.json`, `releases/`, `attestations/` | Installer default data path is `<prefix>/data` unless explicitly selected; this records a path, not automatic engine configuration. Preserve external trusted public keys and release revision history. |
| Build, test and setup outputs | Repository `node_modules/`, `dist/`, `test-results/`, `playwright-report/`; host npm/Go/Podman/browser caches | Rebuildable outputs can still contain local paths, synthetic state, screenshots or reports. Real diagnostics must be reviewed before sharing. Caches are separate from accepted data. |
| Browser state | In-memory imported JSON and fetched local snapshots | JSON preview does not upload or ingest a file. No application localStorage, IndexedDB or service-worker store; closing the page clears application memory, not browser/OS history or screenshots. |

Files are not encrypted at rest by MirageMesh. Use operator-managed disk and
backup encryption and access controls where needed. Permission checks and
hashes do not protect against root, a compromised OS or a malicious same-UID
writer. See [storage guarantees](../architecture/STORAGE_PROOF.md).

## Export and disclosure

There is no product export/import command, per-person export, browser download
of a complete ledger or portable CSV promised here. A stopped, complete private
filesystem copy is the supported operational backup/export. Read API snapshots
and JSON previews are bounded projections, not authoritative backups. Preserve
the compatible reader, source revision, manifests, all referenced objects,
segments and audit, key inventory and the exact configured limits together.

Sharing is an explicit operator action. Public issues, CI artifacts and pull
requests must contain only synthetic or reviewed/redacted reproductions.
Hashes alone do not anonymize low-entropy identities. Never attach a real
ledger, private key, raw token, backup or browser capture containing sensitive
records to a public report. See [SECURITY.md](../../SECURITY.md).

## Retention and deletion

There is no automatic seven-day expiry, scheduled purge or size-based eviction.
The seven-day value in the resource budget is a planning value, not a running
timer. C05 operations/bytes/manifest limits and signed per-sensor spool/batch
limits must be explicit. C28 measured 8.01 events/s for 30 seconds with five
sensors under 2 vCPU / 2048 MiB; the published bounded target is 8 events/s.
10 GiB free disk is a planning budget, not multi-day retention capacity.

Segment retention is a stopped-supervisor, explicit preview/apply operation:
use the complete commands and actual limits in
[EVENT_RETENTION.md](../architecture/EVENT_RETENTION.md). Preview returns
`planned`; adding `--retention-apply` can return `applied`. Usage errors exit 2,
runtime failures exit 1, success exits 0; inspect the typed outcome. Only
complete sealed segments whose events are all strictly before the cutoff are
eligible. Active, mixed-age and incomplete segments remain. There is no HTTP
deletion endpoint. Reusing the same key and request replays the durable decision;
changing its request returns `ErrRetentionConflict`.

**Segment retention is not complete-data deletion:** C05 event copies, receipts,
ACKs, gaps, triage, update/certificate state, retention audit, backups and any
operator exports remain. It does not free C05 quota or erase personal data from
all copies. There is no supported selective C05 deletion/compaction command.
Do not remove object files, rewrite manifests or discard `retention.json` to
simulate erasure; that destroys recovery, revocation and deduplication evidence.

For deliberate complete local decommissioning, stop all writers and isolate the
installation first. Inventory every configured state/segment/decoy directory,
key/token/issuer file, installer metadata and stored data path, backup, snapshot,
export, report and browser/OS copy. If any identity remains in use, revoke or
rotate its credentials through the appropriate authority before disposal.
After the owner authorizes removal, use OS/storage administration to remove
only the inventoried dedicated paths and all retained copies according to their
own storage policy. Removing the application or `dist/` alone leaves data.
No automatic uninstall/purge, secure overwrite, SSD/snapshot erasure or legal
compliance certification is claimed. Retaining any backup retains its data.

## Backup and recovery procedure

1. Stop the supervisor and every CLI/decoy writer that shares the inventory.
   Wait for process exit and lock release. Never copy a live manifest/object
   set or stop only the browser. Do not delete locks to force access.
2. Copy the complete C05 and segment directories, including hidden files,
   `retention.json` and incomplete evidence, to a new private backup location;
   preserve modes, ownership and exact bytes. For dedicated directories, a
   stopped example is `cp -a /absolute/private/state /absolute/new-backup/state`
   and `cp -a /absolute/private/segments /absolute/new-backup/segments`. The
   destination parent must already be private and these destinations absent.
   Confirm copy success and compare a recursive SHA-256 inventory of regular
   files. Back up other configured ledgers/mounts and installation metadata
   separately, with private keys protected separately from shared reports.
3. Record the source/reader version, trust fingerprints, current limits and
   accepted revision floors in the private backup inventory. Backups have no
   automatic schedule, remote upload, expiry or validation service; the operator
   owns frequency, capacity and access. Resume the original only after the copy
   has been checked.
4. Test recovery into a new separate private directory with the same compatible
   reader and policy, no symlinks/hardlinks, and no active competing writer.
   Preserve originals. Reopen validates references, hashes, canonical records
   and quotas; corruption fails closed. Confirm exact receipts, sequence/loss
   counts, triage and retained-source coverage. Recheck current certificate,
   CRL, configuration and update expiry/revocation before reconnecting: a
   restored disk copy cannot undo a revocation or make expired authority valid.
5. Start with explicit restored paths and complete policy; check `/readyz` and
   the Sensors/Incidents/Certificates/Updates views that were configured. An
   unavailable view is not successful recovery. Retain the original and latest
   valid bytes until the restored workflow has passed. Never overwrite newer
   accepted state or roll back security revision floors with an older backup.

`npm run test:clone` independently checks the synthetic full workflow, restart
and a restored copy. The C38 real-file tests additionally check copied data,
replay at quota, corrupted-copy refusal and retained C05 bytes. This is not a
one-command restore tool or physical power-loss certification.

After an unknown write outcome, close/reopen and retry the identical operation
ID/key and bytes; do not invent a new key or loop without a bound. `ErrQuota`
means stop admission and resolve capacity; segment expiry does not increase the
C05 budget. An `ErrRecovery`/I/O error requires preservation and compatible
inspection, not deleting the manifest or silently choosing an older backup.

## Network and diagnostic limits

No egress by default applies to the prepared local runtime: no telemetry,
analytics, crash upload, remote entitlement check or automatic update download.
Web/engine bind loopback, browser assets and API requests are same-origin, and
isolated decoys use `--network=none`. A proxy, OS agent or operator-run command
can create traffic outside this application boundary.

Setup/build may download locked npm packages, the Go toolchain and prepared
Podman/browser resources. The operator explicitly pulls the pinned image; the
runtime does not pull it. Preparing dependencies is not offline runtime proof.
Diagnostics expose a bounded redacted in-memory transition log (32 entries /
8192 bytes) that resets on restart; it is not a durable read-access audit.
Inspect local console, test and report output before sharing. The executable
security/egress and crash proofs remain required in the normal CI suites.
