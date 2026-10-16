# MirageMesh — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Golden E2E scenarios
1. Enroll sensor -> mTLS heartbeat
2. Publish desired decoy -> applied convergence
3. Disconnect control plane -> bounded spool -> reconnect dedupe
4. Attempt stale config rollback and reject
5. Trigger safe decoy -> correlate incident

For every golden scenario record expected authoritative state, emitted event IDs/types, audit action, projection state, critical metrics and cleanup state. Run from a clean environment with deterministic synthetic fixtures. At least one scenario must fail mid-flight and then converge after restart/retry/reconciliation.
