# MirageMesh — Final Engine Decisions v7

These are accepted v1 decisions, not open blockers. Alternatives require a future ADR and must preserve public/domain contracts.

1. v1 sensors use one-time enrollment then short-lived mTLS certificates from SensorIdentityProvider; OpenBao PKI is the production reference. SPIFFE/SPIRE is an optional environment adapter.
2. Decoys are low-interaction defensive services only. Active exploitation, hack-back, credential replay into real systems and outbound attack behavior are prohibited invariants.
3. OCI decoys run rootless with default-deny egress, dropped capabilities, no host PID/network namespace and explicit resource limits.
4. DesiredState revisions are monotonic, hash-addressed and server-signed. Sensor reports AppliedState with revision/hash/status.
5. Binary/plugin automatic update uses TUF update metadata and atomic last-known-good rollback; configuration distribution is separate from binary update trust.
6. Event identity is sensor_id + boot_id + monotonic_seq plus UUID; server deduplicates while retaining observed_at and received_at for skew analysis.
7. Offline spool is bounded, encrypted-at-rest when platform support exists, and uses explicit oldest/priority drop policy with loss counters.
