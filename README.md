# MirageMesh

[![Source](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Miragemesh/actions/workflows/web.yml?query=branch%3Amain)

[CI source integrity and dependency updates](docs/engineering/CI_SOURCE_INTEGRITY.md)

Open-source local-first web application under [Apache-2.0](LICENSE). MirageMesh delivers a supervised Go engine runtime, an accessible web UI, isolated decoy deception via rootless Podman, durable offline event spooling, and cryptographic credential rotation. All core capabilities operate locally with zero mandatory cloud accounts, paid entitlements, or external egress.

---

## Documentation & Guides

- **[Local Service and Privacy Policy](docs/release/SERVICE_POLICY.md)**: Actual data locations, export/deletion limits, retention and tested backup/recovery.
- **[Maintenance Policy](docs/release/MAINTENANCE.md)**: Supported source/platforms, dependency review, security support and data-safe upgrades.

- **[User Guide](docs/release/USER_GUIDE.md)**: Complete step-by-step installation, core reference workflow, limits, backups, and operational instructions for fresh readers.
- **[Clone to Run](docs/engineering/CLONE_TO_RUN.md)**: Deep dive into workstation prerequisites, source build alternatives, provider verification, and troubleshooting.
- **[Open-Source Contract](OPEN_SOURCE.md)**: Guarantees regarding source code freedom, offline durability, and zero proprietary lock-in.
- **[Contributing Guide](CONTRIBUTING.md)**: Workflow for contributors, roadmap execution, coding invariants, and testing standards.
- **[Security Policy](SECURITY.md)**: Conditional private vulnerability reporting, supported source and best-effort disclosure.
- **[Third-Party Inventory](THIRD_PARTY_NOTICES.md)**: Pinned dependency licenses and attribution notices.
- **[Artifact Verification](docs/release/ARTIFACTS.md#signed-release-attestation)**: Detached Ed25519 attestation, verified install/upgrade/rollback and the source-build alternative.
- **[Definition of Done](docs/release/DEFINITION_OF_DONE.md)**: Release gates and evidence verification criteria.
- **[Evidence-backed v1 Gate](docs/release/V1_GATE.md)**: Fresh supported-host verification, immutable historical evidence and offline source-bound release checks.

---

## Clone and run the current workspace

Verified reference host: Ubuntu 24.04 Linux amd64, Git, Node 24.19.0, npm CLI 11.9.0, installed Go (1.21+ for automatic toolchain selection), and rootless Podman 4.9.3. Setup automatically selects Go 1.27.2. Other hosts, including WSL2, require their own full-workflow evidence.

```sh
git clone https://github.com/Parsa-Emami/Miragemesh.git
cd Miragemesh
npm run setup
npm start
# or build and verify the complete reproducible release package:
npm run package
npm run verify:artifact
```

Open http://127.0.0.1:4173. The workspace includes a roadmap browser, local bounded JSON structure preview, read-only Sensors and Certificates views, and source-backed incident replay and triage over explicit local engine state. `npm run test:clone` proves the reference workflow end-to-end in a real clean clone: enrollment, mTLS batch ingest, signed configuration, offline spool, explicit loss accounting, duplicate delivery, triage, non-destructive retention preview, restart, and restore, followed by the real browser workflow.

No Python, database service, paid/cloud account, public domain, or sibling clone is required. The supervised HTTP runtime exposes health/version and the enabled read surfaces. A separate local command validates v1 HTTP-event documents without ingesting or storing them. See [the event contract](contracts/README.md).

---

## Full product endpoint

Enroll sensor -> apply signed config -> isolated decoy event -> disconnect -> spool -> reconnect with duplicate ACK test -> triage and retention gap check.

[C30](plans/commits/C30.md) proves the first locally usable supported product from a clean clone, including negative cases, restart and restore. [C31](docs/release/ARTIFACTS.md) packages that product with the real engine, web build, offline resources, source archive, SBOM, notices, checksums and provenance. [C40](plans/commits/C40.md) remains the complete published OSS v1 gate. [Runtime resources](ops/runtime-requirements.json).

---

## Implement the next commit

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C07
npm run check
```

Each [work card](plans/COMMIT_ROADMAP.md) specifies paths, actions, resources, fixtures, acceptance, negative tests, command availability and rollback. [AGENTS.md](AGENTS.md) and [execution contract](docs/agents/EXECUTION_CONTRACT.md) let an agent resume from this repository alone. [فارسی](docs/ROADMAP_FA.md).

[Open-source contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-party inventory](THIRD_PARTY_NOTICES.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). No DB schema, migration, .env or Dockerfile changes are authorized.
