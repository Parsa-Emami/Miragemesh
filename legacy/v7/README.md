# MirageMesh

> v7.0 status: **ARCHITECTURE-GO / BOOTSTRAP-GO / SOURCE-NOT-IMPLEMENTED**

This directory is a standalone GitHub repository starting point for MirageMesh. It contains the frozen architecture/specification, valid HTTP/event/configuration contracts, GitHub governance/security controls, and project-specific source bootstrap commands.

## Runtime boundary
- Laravel 13 control plane
- Go 1.27 sensor
- rootless Podman OCI decoys
- OpenBao 2.6.x PKI/signing
- PostgreSQL 18.6
- Valkey
- S3-compatible object storage
- OpenTelemetry

## First executable proof
mTLS sensor enrollment → signed desired state → no-egress decoy → offline event spool → reconnect/replay/deduplicate → applied-state proof.

## Start
```bash
make validate
# verify the GitHub owner/module namespace first
make bootstrap
```

Read `ROADMAP_V7.md`, `PROJECT_START_CHECKLIST_V7.md`, `ACCEPTANCE_GATES_V7.md`, and `GITHUB_REPOSITORY_SETUP_V7.md` before the first code commit.

## Evidence rule
Architecture readiness is not production readiness. “S-tier”, “secure”, “resilient”, or performance claims require executable test/observability/failure/recovery/benchmark/release evidence.

## v7 portfolio position
Recommended implementation order: **8 / 10**. Useful but operationally complex; safe decoy isolation, signed desired state, PKI and fleet updates need mature primitives first.
