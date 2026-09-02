# MirageMesh — Data Ownership v7

- **PostgreSQL:** fleet/desired state/incidents/authoritative metadata
- **Sensor spool:** bounded temporary event buffer
- **ObjectStore:** plugin/update artifacts and exported incident evidence
- **OCI runtime:** ephemeral decoy state

## Universal rules
- cache is never authority
- derived projections have checkpoint + rebuild + staleness metric
- secrets/evidence follow project-specific retention and redaction
- deletion does not rewrite immutable audit/custody history
