# MirageMesh — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Domain objects
- `Fleet`
- `Sensor`
- `SensorIdentity`
- `DesiredState`
- `AppliedState`
- `DecoyTemplate`
- `DecoyInstance`
- `HoneyToken`
- `SensorEvent`
- `Correlation`
- `Incident`
- `UpdateMetadata`

## Aggregate rules
- Aggregate mutations occur through application commands, never controller/model convenience writes.
- Aggregate version is checked on conflicting writes.
- Invariants are tested with illegal-transition/negative cases.
- Domain objects do not import Laravel/Eloquent/vendor SDKs.

## Frozen v1 invariants
1. Sensor identity is revocable and unique; clone/replay is detectable.
2. DesiredState revision is monotonic and signed; sensor never silently rolls back.
3. Decoy containers have no default outbound network and no host namespaces/capabilities.
4. Events have stable sensor/boot/sequence identity for deduplication.
