# MirageMesh — Failure & Recovery Proof v7

## Mandatory injected failures
- expired cert
- offline spool full
- duplicate/reordered event
- bad config signature
- plugin crash
- egress attempt
- clock skew
- rollback update

## Pass criteria
For every failure: no invariant violation; no unauthorized bypass; no unbounded retry storm; orphan resources are reconciled; user-visible state becomes correct; telemetry identifies cause; retry/cancel/manual recovery is documented; recovery test is automated where feasible.
