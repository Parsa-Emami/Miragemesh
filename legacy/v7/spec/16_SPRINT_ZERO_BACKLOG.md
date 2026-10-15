# MirageMesh — Sprint Zero Backlog (v7.0)

## Status
**ARCHITECTURE-GO / REPOSITORY-BOOTSTRAP-READY / SOURCE-NOT-IMPLEMENTED**

This backlog is project-specific. It replaces the generic v5 instruction that incorrectly bootstrapped Laravel + React for every project.

## P0 — repository controls before application code
1. Verify the GitHub owner/module namespace in `.github/CODEOWNERS` and module bootstrap commands.
2. Enable branch protection: required PR, required `contracts` status check, code-owner review after CODEOWNERS is finalized, no force-push to `main`.
3. Enable secret scanning / push protection and private vulnerability reporting where supported.
4. Run `python3 scripts/validate_repo.py`; commit only on green.

## P1 — source bootstrap
Runtime boundary:
- Laravel 13 control plane
- Go 1.27 sensor
- rootless Podman OCI decoys
- OpenBao 2.6.x PKI/signing
- PostgreSQL 18.6
- Valkey
- S3-compatible object storage
- OpenTelemetry

Commands are in `scripts/bootstrap-development.sh`. Review generated dependency manifests and commit lockfiles before adding features.

## P2 — first executable vertical slice
mTLS sensor enrollment → signed desired state → no-egress decoy → offline event spool → reconnect/replay/deduplicate → applied-state proof.

Definition of done:
- public HTTP/event contracts are exercised by golden fixtures;
- idempotency and stable identifiers are proven under retry/replay;
- authorization is tested after object lookup;
- logs/traces contain correlation IDs and no secret/plaintext leakage;
- one kill/restart or drop/rebuild failure drill passes;
- no security claim is promoted to “proved” without executable evidence.

## P3 — dependency-bearing CI
Add language-specific build/test jobs only after the first source manifests exist. Pin third-party GitHub Actions to immutable full commit SHAs and review every lockfile update.
