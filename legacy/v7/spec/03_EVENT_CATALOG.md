# MirageMesh — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Versioned domain/integration events
- `sensor.enrolled.v1`
- `sensor.heartbeat.v1`
- `desired_state.published.v1`
- `applied_state.reported.v1`
- `decoy.interaction_observed.v1`
- `incident.correlated.v1`
- `sensor.spool_pressure.v1`

## Envelope
Every message carries `specversion`, `id`, `source`, `type`, `subject`, `time`, `datacontenttype`, `correlation_id`, `causation_id`, `tenant/workspace scope`, aggregate ID/version and payload schema version.

## Delivery semantics
At-least-once delivery is assumed. Consumers deduplicate by event/command identity and verify aggregate/projection checkpoint. Ordering is guaranteed only within an explicitly versioned stream. Consumers tolerate duplicates and documented reordering; correctness never assumes exactly-once transport.
