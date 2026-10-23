# Signed sensor update verification

C25 verifies signed release metadata and the exact bytes of a local candidate file. It persists authority and verification decisions through the existing C05 adapter. The Updates page reads that state. A verified file is not evidence of installation, execution or a live sensor version.

## Components and trust

| Component | Responsibility |
| --- | --- |
| `internal/update/verify.go` | Metadata signatures, release identities, revocation, expiry, version floor and recovery policy |
| `internal/contracts/update.go` | Bounded canonical durable envelopes; no cryptographic trust decision |
| C05 `Store.Update` | Serialize checks with publication, sync bytes and acknowledge the visible manifest |
| `cmd/miragemesh/update.go` | Strict local operator actions, bounded regular files and typed results |
| `/api/v1/updates` and the browser proxy | Read public verified state, enforce local Host/Origin and response bounds |
| `apps/web/src/pages/Updates.tsx` | Current, expired, revoked, superseded and stale evidence with keyboard-accessible details |

Provision two distinct raw 32-byte Ed25519 public keys through trusted local files: the release publisher and the offline recovery authority. These keys are separate from C09 TLS identity, C10 desired configuration and each other. The verifier copies them at construction and never loads a private key. Replacing a pinned key must not make old history unreadable; automated signing-key migration is outside C25.

Ed25519 signatures cover the exact payload bytes. See the [Go signature API](https://pkg.go.dev/crypto/ed25519@go1.27.2#Verify). C25 uses a bounded local protocol, not a TUF implementation. TUF's [client workflow](https://theupdateframework.github.io/specification/v1.0.37/index.html) provides relevant background on persisting revision floors and enforcing expiration.

## Signed documents

Create payloads with `encoding/json.Marshal` of `update.Metadata` or `update.RecoveryGrant`. Their declared field order is part of this version 1 canonical format: no trailing newline, extra whitespace, reordered/unknown/duplicate fields, alternative escaping or null arrays. JSON strings use Go's standard escaping. Sign the resulting bytes with the corresponding Ed25519 private key outside the runtime, and deliver the detached raw 64-byte signature separately. Changing even one byte invalidates the signature.

Metadata fields, in order:

| Field | Constraint |
| --- | --- |
| `schema_version`, `kind` | `"1"`, `"sensor-update-metadata"` |
| `sensor_id` | C04 opaque sensor ID, 1–128 Unicode characters |
| `revision` | Positive integer through 9007199254740991; independent of the release number |
| `platform` | Must equal the configured platform, for example `linux/amd64` |
| `issued_at`, `expires_at` | Canonical UTC RFC3339Nano; issued ≤ now < expiry; lifetime within the explicit local maximum |
| `releases` | Array of at most 16 `{version,sha256,length}` entries, in that field order; unique positive release numbers, lowercase SHA-256 and a positive bounded byte length |
| `revoked_versions` | Array of at most 64 unique positive release numbers; every previously accepted revocation must remain present |

A metadata payload is at most 8192 bytes. Release numbers define ordering; they are not semantic-version strings. A release number's digest and length are immutable across accepted metadata history for the sensor. A later signed revision can remove an offered file or add revocations, including revoking a previously verified file. Revocation-only metadata with an empty release array is valid. A revoked version can never be restored by a later revision or recovery grant.

`Verifier.Accept` verifies and atomically records the signed authority without requiring a candidate to succeed. This lets an operator persist an urgent revocation even when every available candidate is blocked. Metadata revisions must strictly increase. An exact retry of the current revision returns its original receipt with `replayed:true` and no new generation; different bytes at that revision conflict. An older revision, including a once-valid exact replay, is rejected. Expired authority retains its revision and revocation floors but authorizes no candidate.

`Verifier.Verify` streams a candidate through SHA-256 with an explicit byte bound. Both length and digest must match a release in the current unexpired authority. It rechecks authority inside the C05 writer transaction after reading the file. No URL, downloader, subprocess, executable loader or artifact bytes are stored in this module. Its caller supplies a reader; callers must supply readers whose blocking behavior they control. The CLI accepts only bounded regular non-linked local files.

Every new verification decision receives a contiguous per-sensor verification revision. The highest verified release never decreases. An exact retry of the latest decision rechecks current authority, revocation, file bytes and any recovery grant's expiry, then returns the original receipt. Superseded decisions cannot be replayed to replace the latest decision. A new metadata revision requires a new file verification; the UI marks the previous check as needing renewal.

## Explicit rollback recovery

Returning below the highest verified release requires a separately signed grant. The grant is at most 2048 bytes and has these fields in order:

`schema_version`, `kind`, `id`, `sensor_id`, `metadata_revision`, `platform`, `from_version`, `to_version`, `sha256`, `length`, `issued_at`, `expires_at`, `reason`.

Use schema `"1"` and kind `"sensor-update-recovery"`. The ID is 1–64 ASCII letters, digits, underscores or hyphens. The grant must bind the exact sensor, current metadata revision, configured platform, last verified release, target release digest and length. Its validity must fit the explicit recovery TTL. The signed reason is mandatory, at most 256 Unicode characters, with no control characters. The target still needs current publisher evidence and cannot be revoked.

The new decision and grant consumption share one `update.verified` C05 record. No check-then-consume window exists. An exact current retry can return that decision only while both authority and grant remain valid; it does not create another decision. After another decision, the same grant ID is consumed and cannot authorize another rollback. Returning to the higher release does not erase the floor or the consumption history.

## Operator workflow

Stop the local supervisor before operator writes: C05 permits one process writer. Provision the public keys and signed files locally; private signing keys never enter the application.

```bash
update_common=(
  --update-state-dir /absolute/private/update-state
  --update-publisher-key-file /absolute/operator/publisher.pub
  --update-recovery-key-file /absolute/operator/recovery.pub
  --update-platform linux/amd64
  --update-max-operations 128
  --update-max-bytes 2097152
  --update-max-manifest-bytes 131072
  --update-max-sensors 16
  --update-max-artifact-bytes 1048576
  --update-max-metadata-ttl-seconds 3600
  --update-max-recovery-ttl-seconds 600
)
dist/engine/miragemesh --verify-update "${update_common[@]}" \
  --update-action accept-metadata \
  --update-metadata-file /absolute/operator/metadata.json \
  --update-signature-file /absolute/operator/metadata.sig

dist/engine/miragemesh --verify-update "${update_common[@]}" \
  --update-action verify --update-sensor sensor-25 --update-version 4 \
  --update-artifact-file /absolute/operator/release-4.bin

dist/engine/miragemesh --verify-update "${update_common[@]}" --update-action status
```

Only `accept-metadata` may initialize a new C05 store. Status and verification require existing state. File inputs reject symlinks in the path, hard links, non-regular files and group/other write permissions. Public metadata/key/signature inputs are bounded to 8 KiB; artifact size is explicitly configured, at most 64 MiB. State uses the original C05 manifest format and explicit operation, byte and manifest quotas. Recovery TTL must not exceed metadata TTL. Sensor count is bounded to 8192; status is bounded to 1 MiB. History is append-only with no automatic eviction.

For a rollback, add both `--update-grant-file /absolute/operator/grant.json` and `--update-grant-signature-file /absolute/operator/grant.sig` to the `verify` action for the allowed target version. Retain the same signed inputs for a lost-response retry. A failed candidate cannot overwrite accepted authority or clear revocations. Invalid configuration exits 2, rejected/runtime operations exit 1, and successful actions exit 0. JSON reports scope `sensor-update-verification` and status `metadata_accepted`, `artifact_verified`, `snapshot` or `failed`.

| `error_kind` | Meaning |
| --- | --- |
| `untrusted_signature` | Missing, modified or wrong publisher signature |
| `expired_authority`, `stale_authority`, `authority_conflict` | Invalid validity window, older revision or incompatible same-revision/release identity |
| `revoked_version`, `missing_evidence`, `artifact_mismatch` | Blocked target, absent current release or file digest/length mismatch |
| `rollback_denied`, `invalid_recovery` | Missing rollback authorization or invalid/expired/consumed scoped grant |
| `invalid_input` | Unsupported/mixed action, malformed document or incomplete local policy |

Existing typed C05 errors distinguish quota, lock, I/O and recovery failures. No success receipt is returned after an uncertain write. Reopen reconciles the visible manifest, then retry the same intent. Five actual SIGKILL boundaries and nine syscall faults exercise metadata publication and recovery decision publication separately; they demonstrate process-crash recovery, not a power-loss guarantee.

## Read-only workspace

Use the same common flags with the supervisor; it enables the read-only endpoint automatically:

```bash
npm start -- "${update_common[@]}"
```

Open the Updates tab (`#updates`). For direct engine HTTP use `--update-status` plus the common flags and a loopback listen address. Combining status with sensor, certificate or incident views requires the exact same C05 directory and quotas. The JavaScript supervisor also accepts a complete `updateStatus` object with `stateDir`, `publisherKeyFile`, `recoveryKeyFile`, `platform`, `maxOperations`, `maxBytes`, `maxManifestBytes`, `maxSensors`, `maxArtifactBytes`, `maxMetadataTTLSeconds` and `maxRecoveryTTLSeconds`.

`GET /api/v1/updates` exposes only public authority fingerprints, metadata digest/revision/validity, offered/revoked versions, highest and last verified release and its original time. It exposes no signature envelopes, raw files, recovery reason, local path or private key. Disabled or unreadable state returns 503 `update_status_unavailable`; other methods return 405. Foreign Host/Origin is rejected. The browser validates the complete response, compares expiry with nanosecond precision and retains an explicitly stale snapshot after a failed or malformed refresh. It does not sign, upload or install updates.

## Operating limits

Keep the latest C05 history when restarting, upgrading or repairing. Restoring an older store or replacing the local trust configuration defeats local floors; C25 has no external anti-rollback checkpoint, trusted hardware clock, threshold signatures, remote repository protocol or signing-key migration. The trusted local operator controls these files and the authoritative clock. C25 does not download, install, activate or roll back an executable. C28 capacity measurement, C30 complete restart/restore workflow and C40 release certification remain pending.
