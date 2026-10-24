# Sensor resilience evidence template (C26 / F20)

Status: **template only**. It records the shape of a real sensor resilience run;
the placeholders are not results. A filled copy belongs in
`docs/evidence/<task>/<run>.json` and must be backed by retained command output.
Never copy this file into evidence as if it were a measurement.

Use one record per sensor-level run. Small fixture policies (for example
`spool_limit_events=3`) are test policy, not product defaults, capacity or
measured limits; record that distinction explicitly. No real sensor traffic,
customer identity, secret or unlicensed corpus belongs in these fields.

## Record identity

| Field | Required value |
| --- | --- |
| Card / requirement | Task ID and functional requirement (for example `C26` / `F20`) |
| Date and operator | UTC date; the person or agent that ran it |
| Base and final source | Commit SHAs; `sha256:<...>` from `scripts/source_identity.py` |
| Evidence files | Command logs, stored-output SHA-256s and their paths |
| Scope | What this run does and does not prove |

## Environment and resources

| Field | Required value |
| --- | --- |
| Platform | OS, kernel, architecture, CPU model, RAM, free disk |
| Go | Version plus archive SHA-256 and checksum source (`go.dev/dl` release JSON) |
| Node / npm | Exact versions and lockfile identity |
| Container provider | Podman version, `Host.Security.Rootless`, pinned image digest and platform |
| Fixture set | Directory, `fixture_version`, license, provenance, per-file SHA-256 |

## Applied policy and fixture

| Field | Required value |
| --- | --- |
| Sensor and revision | Synthetic sensor ID and the signed applied revision |
| `spool_limit_events` | Applied value plus where its accepted range came from |
| `event_batch_limit` | Applied value plus where its accepted range came from |
| Signature authority | Ephemeral in-memory key only; state that no key material was persisted |

## Offline spool phase

| Field | Required value |
| --- | --- |
| Retained sequences | Exact sequences accepted while disconnected |
| Dropped sequences | Exact sequences rejected at capacity with the typed drop |
| Retry outcome | Same typed drop, no second gap, manifest unchanged |
| Loss summary | Durable loss count and compact gap ranges, reconstructed from records |
| Restart check | The same summary after closing and reopening the store |

## Delivery and duplicate batches

| Field | Required value |
| --- | --- |
| Batch identities | `batch_id`, first and last sequence, event count |
| Delivery result | Per-event and per-ACK receipts, first sequence, last sequence |
| Duplicate delivery | Identical receipts, unchanged event/acknowledgement counts |
| Lost-acknowledgement replay | Same receipts after restart; no duplicate observation |
| Capacity reclamation | Acknowledged events no longer consume the signed spool bound |

## Restart and recovery

| Field | Required value |
| --- | --- |
| Restart boundary | Clean close/reopen, process restart or the exact crash phase |
| Applied state | Revision and payload bytes after restart |
| Durable identity | Confirmed at the storage boundary before acknowledgement |
| Continued delivery | Next batch across an explicit gap; resulting sequences |
| Crash coverage | Which real SIGKILL anchors ran (task IDs), or that none ran |

## Egress and isolation

| Field | Required value |
| --- | --- |
| Composed path | Packages inspected and the rejected import classes |
| Real isolation anchor | Test name, provider/image identity, observed outcome |
| Probe targets | Internet and private address targets that were attempted |
| Negative result | What remains unproven (transport, public endpoint, multi-tenant boundary) |

## Negative cases

| Field | Required value |
| --- | --- |
| Cases executed | Names from the versioned negative fixture |
| Expected sentinel | Typed error per case |
| Observed result | Actual error and whether the store was unchanged |
| Missing prerequisites | How absence or an unavailable provider failed explicitly |

## Commands and results

| Field | Required value |
| --- | --- |
| Command | Exact argv, environment overrides and working directory |
| Exit code | Actual exit status; failures are retained, never rewritten |
| Output | Retained log path and its SHA-256 |
| Guard | Executed-suite/anchor count printed by the discovery guard |

## Limitations

State them instead of implying more: local process/filesystem guarantees only,
no physical power-loss proof, no remote CI or release certification, no C30
clean-host workflow and no C40 artifact proof. A passing run on one host is not
a capacity claim or a supported multi-tenant boundary.
