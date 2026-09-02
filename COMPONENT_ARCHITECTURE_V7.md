# MirageMesh — Component Architecture v7

## Runtime/components
- Laravel 13 control plane
- Go sensor
- rootless Podman OCI decoys
- OpenBao PKI/signing provider
- PostgreSQL 18
- Valkey
- ObjectStore
- OpenTelemetry

## Dependency direction
`Web/CLI -> HTTP/Application -> Domain <- Ports <- Infrastructure Adapters`

Specialized workers/engines consume versioned commands/contracts; they do not reach into Laravel tables except through explicit repositories or service APIs owned by the responsible module.

## Cross-cutting
Transactional outbox, idempotent jobs, correlation IDs, OpenTelemetry, structured audit, rate/resource limits, health/readiness and graceful shutdown are mandatory.
