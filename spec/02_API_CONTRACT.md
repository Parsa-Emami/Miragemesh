# MirageMesh — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## HTTP conventions
- Prefix `/api/v1`; JSON UTF-8; explicit content type.
- Resource IDs are opaque UUID/ULID-style identifiers and authorization is re-evaluated after lookup.
- Cursor pagination for unbounded collections.
- Mutation request/response schemas are versioned in OpenAPI; unknown security-sensitive fields are rejected where ambiguity is dangerous.
- Stable error codes follow the common error standard.

| Method | Route | Purpose | Gate |
|---|---|---|---|
| `GET` | `/sensors` | Implemented opt-in local status projection | Loopback Host/listener port and same-origin checks; read-only; no bearer auth |
| `POST` | `/sensors/enrollment-tokens` | Create one-time enrollment | auth + validation + idempotency where side-effecting |
| `POST` | `/sensors/enroll` | Exchange token for identity | auth + validation + idempotency where side-effecting |
| `POST` | `/sensors/{sensor}/desired-state` | Versioned signed desired configuration | auth + validation + idempotency where side-effecting |
| `POST` | `/sensors/{sensor}/events/batch` | mTLS event batch | auth + validation + idempotency where side-effecting |
| `GET` | `/sensors/{sensor}` | Desired/applied/health | auth + validation + idempotency where side-effecting |
| `POST` | `/incidents/{incident}/triage` | Analyst decision | auth + validation + idempotency where side-effecting |

## Compatibility
Additive compatible changes may ship in v1. Removing/renaming/changing semantics requires deprecation + migration and normally a new API major. Golden request/response fixtures run in CI.

## Implemented local status collection

C21 implements only `GET /api/v1/sensors` as a local status collection. Its
versioned snapshot, explicit startup prerequisites and 200/403/405/503 results
are in OpenAPI and `docs/architecture/SENSOR_STATUS.md`. Planned mutation and
per-resource routes above remain unimplemented HTTP contracts. The local
projection is not a remote authenticated management API.
