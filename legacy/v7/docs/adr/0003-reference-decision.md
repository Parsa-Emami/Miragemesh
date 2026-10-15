# ADR 0003 — MirageMesh reference decision

**Status:** Accepted for v1

## Decision
OCI decoys run rootless with default-deny egress, dropped capabilities, no host PID/network namespace and explicit resource limits.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
