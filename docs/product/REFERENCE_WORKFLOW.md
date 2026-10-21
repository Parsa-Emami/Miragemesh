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
C05 using the C11 applied signed `spool_limit_events`. Full queues return an
explicit quota error and exact replay keeps the original receipt after restart.
C15 owns overflow loss accounting; C16 owns collector delivery, durable ACKs and
capacity reclamation. The queue has no network/CLI/browser surface and does not
execute the whole scenario. See `docs/architecture/CONFIG_APPLY.md`.
