# MirageMesh: reference workflow

Status: planned domain acceptance contract; the current web JSON preview does not implement or execute this workflow. The C01 validator checks documentation metadata only.

The repository-owned scenario is `tests/scenarios/clone-to-value.json`. Its synthetic fixtures live under `tests/fixtures/miragemesh/C01/`; each records Apache-2.0 licensing and repository-authored provenance. Do not add real secrets, customer identities, sensor traffic, case data or unlicensed corpora.

## Workflow

1. Enroll synthetic sensor `sensor-01` and apply signed desired configuration version 1.
2. Accept `event-01` with sequence 1 and its domain fields: `sensor_id`, `event_id`, `sequence`, `observed_at`, `kind` and bounded `metadata`.
3. Disconnect the sensor, queue `event-02` with sequence 2, reconnect, deliver it and repeat its acknowledgement. Expected behavior is one accepted copy; spool overflow must report loss explicitly.
4. Triage the accepted events, inspect retention gaps, then restart services and restore the last accepted state. Applied version, event identities and loss/gap accounting must remain consistent.

## Required invariants and failures

- No egress by default.
- Signed desired state applies monotonically.
- The bounded offline spool is replay-safe and accounts explicitly for loss.
- Replayed enrollment tokens and invalid certificates fail before event acceptance.
- Spool overflow is visible; decoys cannot access the Internet or operational internal network.

`node scripts/verify-reference.mjs` validates scenario structure, fixture references, provenance and license metadata. A successful validation does not execute or prove any workflow behavior. Engine behavior, isolation and restart/restore require later implementation and evidence; C30 is the local usability gate.

The intended local setup is `npm run setup` followed by `npm start`. No paid account, cloud service, public domain or sibling repository is required for the core open-source profile.

C11 implements only the internal signed-configuration part of steps 1 and 4:
`sensor.NewApplier` persists and recovers the exact applied payload, revision and
original acceptance time through C05. It does not execute the full scenario or
apply settings to a decoy/spool; those consumers belong to later cards. See
`docs/architecture/CONFIG_APPLY.md` for this supported in-process interface.

C12 adds the decoy observation of step 2 as an internal component:
`decoy.New` and `decoy.Service.ServeHTTP` answer a request with a fixed body
and record one bounded observation of the path through the C04 contract and the
C05 store, under the separate `decoy-01` identity. The decoy never executes a
command, never echoes request content and bounds the request size. It is not a
published surface in C12: no listener, no container isolation and no egress
denial are proven here, and the scenario itself is still not executed end to
end. See `docs/architecture/DECOY_HTTP.md`.

C13 adds the isolation of that decoy: the decoy runs in a rootless container
with no network at all, no capabilities, no host namespace, a read-only root
filesystem and hard process and memory limits. `decoy.NewSupervisor` states
the policy, `internal/podman` applies it and the supervisor verifies the
observed and the effective state before it reports a running decoy; a container
that does not match the policy is removed and reported as an explicit failure.
The decoy handler of C12 runs inside that container and answers on its own
loopback, so the recorded observations are the observations of the isolated
decoy. The engine starts the isolated decoy with `--decoy-isolation` and
reports the typed outcome, so the isolation is part of the supported workflow.
C13 publishes no decoy surface: the container has no inbound path either, and
the egress attempt of the scenario stays denied. See
`docs/architecture/DECOY_ISOLATION.md`.

C14 implements the local retention of step 3 as an internal Go queue:
`spool.New(store, applier)` and `Enqueue` retain exact C04 event bytes through
C05 using the C11 applied signed `spool_limit_events`. Full queues drop the new
event and durably record its sequence gap; an exact retry reports the same typed
drop without double-counting. C05 global quota exhaustion returns an explicit
storage error without claiming the loss was recorded. The queue has no
network/CLI/browser surface and does not execute the whole scenario. See
`docs/architecture/CONFIG_APPLY.md`.

C16 implements collector delivery for step 3 as an internal Go boundary:
`collector.New(store, applier)` and `Ingest` accept a contiguous
`batch_id`/`first_sequence`/`last_sequence` batch of exact C04 bytes, persist
every event through the C07 sequence, then commit append-only `spool.ack`
records through C05. `Ingest` succeeds only after every event and ACK is
durable. An exact retry after a lost acknowledgement returns the original
receipts and creates no duplicate event observation; acknowledged events no
longer consume the signed spool limit, so capacity is reclaimed. A forged,
orphaned or out-of-order ACK fails closed. C16 adds no listener, public HTTP/CLI
surface, mTLS terminator or UI and does not execute the whole scenario; C30 is
still the local end-to-end gate. See `docs/engineering/ENGINE_TESTS.md` and
`docs/architecture/CONFIG_APPLY.md`.

C17 implements immutable segment storage for the accepted event stream:
`events.Open`, `Append` and `AppendRecords` write newline-framed C04 events into
bounded active JSONL segments, sync each record, then seal a full segment by
rename and directory sync before starting the next. A crash at rotation leaves
complete records readable. A torn final tail is preserved byte-for-byte as an
explicit `.incomplete.jsonl` file with Offset, Bytes and SHA-256 Digest; it is
never treated as an event or as an event sequence gap. `AppendRecords` skips C15
gaps, C16 acknowledgements, enrollment and applied configuration. C17's original
no-deduplication behavior is historical; C18 now rebuilds a projection index from
the committed segments. Segment failure cannot rewrite C16 receipts or ACKs, and
no atomicity between the two writes is claimed.

The engine also exposes a one-shot `--project-segments` command with explicit
C05/segment directories and mandatory limits. It requires an existing C05 store,
rejects overlapping directories, projects the snapshot without writing a C05
receipt or ACK, reports typed appended/skipped/incomplete data and returns
exit `2` for invalid configuration or `1` for a runtime failure. A failed
projection reports the segment state that is already durable, or marks it
unknown when no trustworthy snapshot exists. It opens no
listener and does not execute the whole scenario. C17 adds no retention command
or UI; C23 owns deletion/retention and C30 remains the end-to-end gate. See
`docs/architecture/EVENT_SEGMENTS.md`.

C18 makes event projection repeatable without a durable checkpoint file:
`events.Open` rebuilds a derived index from the complete records of the committed
segments. `AppendRecords` skips an already indexed event and counts it in
`already_projected`. Direct `Append` permits exact duplicates and counts them
in the index; both APIs reject conflicting identities before writing; the same
sensor/event identity with different bytes or sequence is a typed
`ErrIndexConflict` before any file changes. Reopening the writer after index loss
is the rebuild path. The `--project-segments` outcome now reports
`deduplicated:true`, index record/sensor coverage, duplicate counts, incomplete
tails and exclusive missing ordinal ranges. Missing evidence is still not proof
that an event was never ingested: C15 gaps, C23 retention and deleted segments
remain explicit coverage facts. C18 opens no listener and adds no command, UI,
schema or dependency. See `docs/architecture/EVENT_INDEX.md`.

C19 adds read-only, explainable findings to the existing one-shot
`--project-segments` workflow. An explicit per-sensor rate count and window
produce a rate signal when the configured request count is reached inside the
window; each accepted event also yields an interaction finding. Every signal
references the committed C18 segment, record, sequence and digest. Durable spool
gaps produce separate sensor-health findings. Missing or incomplete index
coverage remains visible and is never reported as a clean scan. C19 adds no
listener, endpoint, UI, schema or dependency. See `docs/architecture/ALERT_RULES.md`.

C20 persists append-only incident triage labels through the same C05 store used
for events and internal records. A request carries only the opaque incident ID,
a mandatory idempotency key and a body with exactly `status` and `reason`;
unknown, duplicate, malformed or over-bound input is rejected before writing.
The durable record stores the status, reason, UTC triage time and only a SHA-256
digest of the key. It contains no observed event bytes or source reference, so
triage cannot alter the source event. A repeated key and identical request
replays the original receipt without a new generation, while key reuse with a
different status or reason is a typed conflict. History is ordered, with the
last entry as the current label, and survives restart. A triage record is not an
event: the next sensor sequence continues and C17/C18 projection skips it. C20
adds no HTTP endpoint, CLI, UI, schema, migration or dependency. See
`docs/architecture/INCIDENT_TRIAGE.md`.

C21 adds a read-only `GET /api/v1/sensors` loopback view over committed C05
records: the highest accepted event sequence supplies last activity, C15 gap
records supply dropped-event counts, and C11 verifies applied configuration
before the UI reports it as current or expired. No event body or gap metadata
is exposed. Offline means no stored event within five minutes (or no stored
event); it is a last-event heuristic, not a live heartbeat. The endpoint is
disabled unless the local engine receives explicit C05 quotas, a raw Ed25519
public-key file and explicit C10 verifier bounds. It never writes to the
store; enrollment, ingest and configuration application still have no browser
write surface. See `docs/architecture/SENSOR_STATUS.md`.

The C01–C21 review remediation preserves legacy segment reads and adds canonical
base64 JSON-string frames for multiline accepted payloads without changing their
indexed bytes/digests. Identity maps use tuples. Container cleanup checks the
installation and run markers; foreign or unlabeled containers are preserved.
Local HTTP rejects foreign Host/Origin, and sensor refresh failures retain an
explicitly stale snapshot. These are fixes to existing cards; the C22 local view builds on those boundaries.

C22 implements the local incident inspection and status/reason portion of step 4.
The Incidents page reads segment frames and their exact source digests through
`GET /api/v1/incidents`, and appends triage through the same-origin local
`POST /api/v1/incidents/{incident}/triage` boundary. Every displayed finding has
segment/record/sequence/digest sources; incomplete coverage stays explicit. It
does not perform retention, ingest, enrollment or the full clone-to-value
scenario. See `docs/architecture/INCIDENT_REPLAY.md`.

## Explicit segment retention

C23 adds standalone preview/apply retention of complete sealed segments with a durable audit, restart convergence and no projection resurrection. Run it while the supervisor is stopped. Incident coverage identifies deliberately expired sources separately from unprojected events and spool loss. C05 copies remain unchanged; see [EVENT_RETENTION.md](../architecture/EVENT_RETENTION.md) for actual scope, bounds and commands.

## Sensor certificate lifecycle

C24 adds durable client leaf rotation under the C09 issuer, explicit overlap cutoff and atomic token-backed offline recovery. The operator CLI handles signing and private token delivery; the Certificates page reads lifecycle state without loading signing keys. Configure `pki.Options.Rotation` to enforce the ledger at the existing mTLS boundary. See [CERTIFICATE_ROTATION.md](../architecture/CERTIFICATE_ROTATION.md) for scope, policy, provisioning and recovery.

## Signed sensor update authority

C25 adds durable publisher-signed sensor release metadata, exact local candidate file verification, permanent revocation floors and scoped one-time rollback authority signed by a separate recovery key. Operator actions and the read-only Updates page use the same C05 state. Verification does not install an update. See [SENSOR_UPDATES.md](../architecture/SENSOR_UPDATES.md).

## Security validation for the local profile

C27 audits every enabled local surface and records the executable proof in
[tests/release/security-matrix.md](../../tests/release/security-matrix.md) and
the boundary assumptions in
[THREAT_MODEL.md](../security/THREAT_MODEL.md). It adds no product surface: the
new browser regressions exercise the existing shell, JSON import and incident
triage boundaries (CSP, forbidden Host/Origin, request bounds, object IDs and
stored-content inertness), while mTLS identity, provider ownership, storage and
signed authority remain proved by their C09-C25 anchors. The matrix records no
critical or high finding in the local profile and states the limits: one trusted
local operator, no public ingress or multi-tenant authorization, and no C30/C40
claim.

## Integrated offline, duplicate-delivery and restart path

C26 exercises the sensor-side portion of steps 3 and 4 as one scenario through
the existing C14/C16 boundaries: a bounded offline spool drops beyond its
signed limit with an explicit gap, reconnection delivers batches, an identical
redelivery is idempotent, and a real store restart preserves the applied
revision, receipts, acknowledgements and loss accounting before delivery
continues across the gap. The composed path is checked to import no network
capability; the real container egress denial and crash recovery remain the
C13/C14/C16 proofs. C26 adds no product surface and does not execute the whole
reference workflow; C30 remains the local end-to-end gate.
