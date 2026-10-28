# Evidence-backed local v1 readiness (C39)

`npm run release:check` is a read-only, offline check of the retained C39
verification capsule against this checkout. It exits 0 only when the complete
supported-profile proof is present and valid; it exits 2 with typed JSON errors
otherwise. A `verified` status or `core_ready: true` alone cannot open the gate.
This verifies local release readiness, not C40 publication or an installed
published release. Every result keeps `published: false`.

## Run and retain fresh proof

Prepare the locked Ubuntu 24.04 Linux amd64 host, Node/npm/Go, rootless Podman,
pinned image, Chromium and strace using
[CLONE_TO_RUN.md](../engineering/CLONE_TO_RUN.md). Commit the candidate inputs
first. On a pull request, its head tree must match the tested merge checkout;
update the branch if the base has changed.

```sh
npm run release:check -- --run --output dist/ci/v1-gate.json
npm run release:check -- --report dist/ci/v1-gate.json
```

The runner executes the fixed plan, repository/source/resource/reference checks,
web/Go build, Go vet and uncached race suite, the entire Node suite in TAP form,
the real Chromium suite, two clean-clone workflows, full packaging and artifact
verification. It also compares every source-archive member byte for byte with
the candidate's complete distributable source inventory. No command is loaded
from an evidence file or executed through a shell. Commands have bounded output
and five-minute deadlines; there is no retry loop. The CI job is bounded to
twenty minutes. Preparation may download pinned resources; prepared runtime
no-egress remains a required actual test.

The report starts as failed and is atomically published as passed only after
every check and final report validation succeeds. Failures preserve command
stdout/stderr and typed error details. Generated output must stay in ignored
`dist/`; it never writes a user ledger, key or retention directory.

The `release-gate` workflow has read-only repository permissions, full history
and the pinned provider/toolchain. It uploads `dist/ci/v1-gate.json` plus
`dist/ci/C39/verification/`, including hashed compressed command logs, the clone
report, package provenance, SBOM, checksum manifest and exact source inventory.
Review/download that actual output and retain it as `docs/evidence/v1-gate.json`
and `docs/evidence/C39/verification/` without altering the report or its payloads.
The default check then works in a clone without providers, a browser or built
artifacts. CI always executes fresh proof rather than trusting that old capsule.

## Historical evidence and current source

The immutable C38 baseline in `plans/release-gates.json` owns the original
C01-C38 evidence. Every record must remain byte-identical to that Git history,
have its own card ID, successful commands, real source identity and verified
progress. Both historical command forms (`command` and `argv`) are supported;
old proof is never relabelled as a current execution.

Where a source-file inventory exists, its individual hashes and aggregate
identity are checked against its historical Git snapshot. Scoped owned-path
proofs and explicit implementation commits are independently recomputed using
their original identity rules. Some early specification/resource records and
C29-C35 staged, pre-bookkeeping snapshots have no standalone reachable source
commit. They remain explicitly classified as retained precommit receipts; their
identity is not represented as a newly tested Git commit. Fresh execution of the
complete current suites and actual clone/package/recovery workflow is required
in addition to all original records. This is why historical status flags cannot
substitute for the current capsule.

The report stores the exact tested commit, Git tree and full source identity.
Its release-input identity additionally binds file modes and all runtime,
policy, build, workflow, contract, fixture and license bytes. It excludes only
evidence, the historical root checksum manifest, progress/project-state/session
bookkeeping, and generated roadmap task status values. Other generated fields
remain bound. This permits a later evidence/status certification commit without
pretending the old command ran on that later Git tree. Changing an engine,
fixture, dependency, gate rule, policy or workflow makes the capsule stale and
requires a complete rerun. The final certification candidate is rechecked by CI
before merge.

## Required boundaries

The executed engine discovery guard retains all crash/publication, syscall and
ENOSPC injection, lost-ACK replay, quota, retention, identity/revocation,
no-egress and full reference-workflow anchors. Package-only success or skipped
required engine tests fail. Node proof must include actual test results and the
egress, signed installation/rollback, reproducibility and readiness checks;
browser security, accessibility and full-workflow suites cannot be skipped.
Clone proof requires separate accepted state, typed provider/prerequisite/input
failures, readiness, restart and an equivalent restored copy.

All direct/transitive lockfile licenses, resource pins and fixture byte hashes
are inventoried. Root fixture metadata must have an explicit compatible license
and repository-authored provenance; nested raw payloads/helpers inherit the
declared parent/project license and are individually hashed. Unknown dependency
licenses, missing notices, floating or substituted image digests, and unlicensed
fixtures fail. The complete native engine, web assets, source archive, SBOM,
licenses and checksums must belong to the same verified source. Web-only bundles
and a self-asserted provenance identity are insufficient.

## Failure semantics and limits

| Code | Required action |
| --- | --- |
| `missing_report`, `missing_proof`, `incomplete_proof` | Run the full supported-host verification and retain all outputs. |
| `changed_historical_evidence`, `template_evidence` | Preserve the original records; investigate the mismatch instead of rewriting old proof. |
| `wrong_source`, `dirty_source` | Commit/update the candidate and generate fresh evidence for its exact inputs. |
| `proof_digest_mismatch`, `unsafe_path` | Preserve suspect files and obtain the original bounded, hash-checked proof. |
| `failed_required_test`, `incomplete_clone` | Fix the observed failure and rerun the entire gate. |
| `unlicensed_fixture`, `unlicensed_dependency`, `unlicensed_resource` | Resolve provenance/license/integrity before release. |
| `web_only_artifact`, `unsupported_profile` | Use the complete supported build and prepared tool/provider profile. |
| `usage` | Use only the documented read/report/run options. |

The capsule hashes detect changed evidence, not a hostile maintainer or
compromised OS forging both logs and source. Release signatures and external
trust are the separate C35/C40 boundaries. SIGKILL/syscall tests do not certify
physical power loss; the retained C28 capacity measurement does not become a
new multi-day capacity claim. There is no paid/cloud requirement, public ingress,
SLA or authorization to publish, delete accepted state or change protected
schemas, migrations, `.env` files or Dockerfiles.
