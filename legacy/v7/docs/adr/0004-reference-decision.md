# ADR 0004 — MirageMesh reference decision

**Status:** Accepted for v1

## Decision
DesiredState revisions are monotonic, hash-addressed and server-signed. Sensor reports AppliedState with revision/hash/status.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
