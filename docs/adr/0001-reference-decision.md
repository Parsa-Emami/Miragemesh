# ADR 0001 — MirageMesh reference decision

**Status:** Accepted for v1

## Decision
v1 sensors use one-time enrollment then short-lived mTLS certificates from SensorIdentityProvider; OpenBao PKI is the production reference. SPIFFE/SPIRE is an optional environment adapter.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
