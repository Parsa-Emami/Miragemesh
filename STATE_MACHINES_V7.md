# MirageMesh — State Machines v7

- **Sensor:** `ENROLLING -> ONLINE -> DEGRADED -> OFFLINE -> REVOKED`
- **Deployment:** `DESIRED -> APPLYING -> APPLIED | DEGRADED | FAILED -> REMOVING -> REMOVED`
- **Incident:** `OPEN -> TRIAGED -> CLOSED`

Transitions are domain commands with authorization, optimistic version check where applicable, audit event and invariant tests. Illegal transitions fail closed and are observable.
