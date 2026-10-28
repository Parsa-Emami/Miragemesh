# MirageMesh: Open-Source Contract

This document defines the core principles, legal terms, dependency policies, and architectural commitments governing MirageMesh as a public open-source project.

---

## 1. Apache-2.0 Core Licensing

MirageMesh is released under the [Apache License, Version 2.0](LICENSE). 

- **Full Local Core**: All source code—including the Go supervisor engine, the React/Vite web application, contracts, synthetic test fixtures, build recipes, and operational scripts—is freely available under Apache-2.0.
- **No Proprietary Gating**: No core feature is restricted behind proprietary extensions, enterprise editions, or commercial licenses.
- **Package Manifest Note**: The `"private": true` setting in `package.json` exists solely to prevent accidental publishing of internal workspace packages to the public npm registry; it does not restrict source inspection, distribution, or fork rights under Apache-2.0.

---

## 2. Third-Party Dependencies & Provenance

MirageMesh strictly audits and pins all external components:
- **Compatible Licensing**: Upstream libraries and runtime dependencies retain their original licenses (MIT, Apache-2.0, BSD-3-Clause, etc.). No copyleft or proprietary dependencies may silently be introduced into the core distribution.
- **Third-Party Notices**: A complete inventory of third-party software, licenses, and copyright notices is maintained and distributed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Synthetic Data Only**: All repository test corpora and fixtures (such as `tests/fixtures/miragemesh/`) are synthetic, repository-authored under Apache-2.0, and free from real-world confidential, proprietary, or unverified data.

---

## 3. Zero Compulsory Cloud or Paid Entitlements

MirageMesh is firmly committed to architectural self-sovereignty:
- **No Required Accounts**: You do not need an account with AWS, Google Cloud, Microsoft Azure, or any SaaS provider to deploy or operate MirageMesh.
- **No Paid Subscriptions**: There are no license tiers, seat limits, or paid features. The complete reference workflow runs on standard commodity hardware.
- **No Remote Telemetry**: The application transmits zero telemetry, usage metrics, tracking pixels, or diagnostic phone-homes. Network egress is disabled by default.

---

## 4. Offline-First and Local Durability

In accordance with [ADR-0003](docs/architecture/ADR-0003-open-source-local-first.md):
- **Commodity Infrastructure**: The verified reference host is Ubuntu 24.04 Linux amd64 (2 vCPU / 2048 MiB RAM target), using a private local POSIX filesystem and rootless Podman. Other hosts, including WSL2, need their own full-workflow evidence; see [the service policy](docs/release/SERVICE_POLICY.md).
- **No Mandatory Database Service**: Durable state is maintained through atomic file manifests and immutable segments, eliminating the operational overhead of running external database servers.
- **Air-Gapped Operation**: Once built or installed, MirageMesh functions seamlessly in completely disconnected, air-gapped network perimeters.

---

## 5. Source Build and Reproducibility

Operators retain the right and ability to independently verify and build the software:
- **Documented Toolchains**: Clear source build instructions are provided in [docs/engineering/CLONE_TO_RUN.md](docs/engineering/CLONE_TO_RUN.md).
- **Verifiable Artifacts**: Release packages include SBOMs (Software Bill of Materials) and cryptographic checksums verified by `npm run verify:artifact`.

---

## 6. Community and Contributions

We welcome community collaboration aligned with our open-source values:
- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code. All contributions require sign-off under the Developer Certificate of Origin ([DCO.md](DCO.md)).
- **Security Inquiries**: Security vulnerabilities are managed responsibly through private channels. See [SECURITY.md](SECURITY.md).
