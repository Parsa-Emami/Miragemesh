# ADR 0005 — MirageMesh reference decision

**Status:** Accepted for v1

## Decision
Binary/plugin automatic update uses TUF update metadata and atomic last-known-good rollback; configuration distribution is separate from binary update trust.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
