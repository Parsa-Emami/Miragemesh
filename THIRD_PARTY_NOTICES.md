# Third-party inventory

Updated 2026-10-25 for the C31 complete local artifact. This index distinguishes redistributed code from build-only tools and host prerequisites; the CycloneDX SBOM in `dist/release/sbom.cdx.json` is the machine-readable inventory.

## Redistributed in the complete artifact

| Component | Version | License | Notice |
|---|---|---|---|
| MirageMesh | 0.0.1 | Apache-2.0 | `LICENSE`, `NOTICE` |
| React | 19.3.1 | MIT | `licenses/react-MIT.txt` |
| React DOM | 19.3.1 | MIT | `licenses/react-dom-MIT.txt` |
| scheduler | 0.28.0 | MIT | `licenses/scheduler-MIT.txt` |
| Go standard library (compiled into the engine) | 1.27.2 | BSD-3-Clause | `licenses/go-BSD-3-Clause.txt` |

The built JavaScript bundle contains React, React DOM and scheduler. The Go license text covers the runtime and standard library compiled into `dist/engine/miragemesh`. The source archive contains the corresponding source and build recipe.

## Host prerequisites, not redistributed

| Resource | Version | License | Route |
|---|---|---|---|
| Node.js | 24.19.0 | MIT | Official archive pinned in `docs/engineering/toolchain-lock.json`; installed by the operator. |
| npm CLI | 11.9.0 | Artistic-2.0 | Invoked separately; not bundled with the artifact. |
| Go toolchain | 1.27.2 | BSD-3-Clause | Used to build the engine; not required at runtime. |
| Podman provider | 4.9.3 (`4.9.3+ds1-1ubuntu0.2`) | Apache-2.0 (main project; package files may vary) | Ubuntu source package; optional decoy workflow. |
| Alpine decoy image | 3.23.2, digest `sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62` | MIT base plus GPL-2.0-only busybox, Apache-2.0 OpenSSL, MPL-2.0 ca-certificates and zlib | Operator pulls the pinned digest; not redistributed. Per-component licenses are recorded in the toolchain lock and SBOM. |

The local product runs without a paid or cloud account. Only the optional decoy workflow pulls the Alpine image.

## Build/test-only inventory (not redistributed)

The following declared versions come from the committed npm lockfile and are used to build or test the project. They are not part of `dist/release`.

| Resource | Version | Declared license |
|---|---|---|
| `@oxc-project/types` | 0.154.0 | MIT |
| `@playwright/test` | 1.64.1 | Apache-2.0 |
| `@rolldown/binding-android-arm-eabi` | 1.2.14 | MIT |
| `@rolldown/binding-android-arm64` | 1.2.14 | MIT |
| `@rolldown/binding-darwin-arm64` | 1.2.14 | MIT |
| `@rolldown/binding-darwin-x64` | 1.2.14 | MIT |
| `@rolldown/binding-freebsd-x64` | 1.2.14 | MIT |
| `@rolldown/binding-linux-arm-gnueabihf` | 1.2.14 | MIT |
| `@rolldown/binding-linux-arm64-gnu` | 1.2.14 | MIT |
| `@rolldown/binding-linux-arm64-musl` | 1.2.14 | MIT |
| `@rolldown/binding-linux-ppc64-gnu` | 1.2.14 | MIT |
| `@rolldown/binding-linux-s390x-gnu` | 1.2.14 | MIT |
| `@rolldown/binding-linux-x64-gnu` | 1.2.14 | MIT |
| `@rolldown/binding-linux-x64-musl` | 1.2.14 | MIT |
| `@rolldown/binding-openharmony-arm64` | 1.2.14 | MIT |
| `@rolldown/binding-win32-arm64-msvc` | 1.2.14 | MIT |
| `@rolldown/binding-win32-x64-msvc` | 1.2.14 | MIT |
| `@rolldown/pluginutils` | 1.0.1 | MIT |
| `@types/react` | 19.3.0 | MIT |
| `@types/react-dom` | 19.3.0 | MIT |
| `@typescript/typescript-aix-ppc64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-darwin-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-darwin-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-freebsd-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-freebsd-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-arm` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-loong64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-mips64el` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-ppc64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-riscv64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-s390x` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-linux-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-netbsd-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-netbsd-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-openbsd-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-openbsd-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-sunos-x64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-win32-arm64` | 7.0.2 | Apache-2.0 |
| `@typescript/typescript-win32-x64` | 7.0.2 | Apache-2.0 |
| `csstype` | 3.2.3 | MIT |
| `detect-libc` | 2.1.2 | Apache-2.0 |
| `fdir` | 6.5.0 | MIT |
| `fsevents` | 2.3.3 | MIT |
| `lightningcss` | 1.33.0 | MPL-2.0 |
| `lightningcss-android-arm64` | 1.33.0 | MPL-2.0 |
| `lightningcss-darwin-arm64` | 1.33.0 | MPL-2.0 |
| `lightningcss-darwin-x64` | 1.33.0 | MPL-2.0 |
| `lightningcss-freebsd-x64` | 1.33.0 | MPL-2.0 |
| `lightningcss-linux-arm-gnueabihf` | 1.33.0 | MPL-2.0 |
| `lightningcss-linux-arm64-gnu` | 1.33.0 | MPL-2.0 |
| `lightningcss-linux-arm64-musl` | 1.33.0 | MPL-2.0 |
| `lightningcss-linux-x64-gnu` | 1.33.0 | MPL-2.0 |
| `lightningcss-linux-x64-musl` | 1.33.0 | MPL-2.0 |
| `lightningcss-win32-arm64-msvc` | 1.33.0 | MPL-2.0 |
| `lightningcss-win32-x64-msvc` | 1.33.0 | MPL-2.0 |
| `nanoid` | 3.3.20 | MIT |
| `picocolors` | 1.1.1 | ISC |
| `picomatch` | 4.0.7 | MIT |
| `playwright` | 1.64.1 | Apache-2.0 |
| `playwright-core` | 1.64.1 | Apache-2.0 |
| `postcss` | 8.5.30 | MIT |
| `react` | 19.3.1 | MIT |
| `react-dom` | 19.3.1 | MIT |
| `rolldown` | 1.2.14 | MIT |
| `scheduler` | 0.28.0 | MIT |
| `source-map-js` | 1.2.2 | BSD-3-Clause |
| `tinyglobby` | 0.2.17 | MIT |
| `typescript` | 7.0.2 | Apache-2.0 |
| `vite` | 8.3.4 | MIT |

## C04 contract-test dependencies

These exact development-only versions come from package-lock.json, including their upstream npm URLs and integrity values. Ajv and ajv-formats execute the reviewed JSON Schema and date-time format checks in tests; neither enters the browser bundle or Go runtime.

| Resource | Version | Declared license |
|---|---|---|
| `ajv` | 8.20.0 | MIT |
| `ajv-formats` | 3.0.1 | MIT |
| `fast-deep-equal` | 3.1.3 | MIT |
| `fast-uri` | 3.1.8 | BSD-3-Clause |
| `json-schema-traverse` | 1.0.0 | MIT |
| `require-from-string` | 2.0.2 | MIT |

Sources: [Ajv](https://ajv.js.org/), [formats](https://github.com/ajv-validator/ajv-formats).

## Notice completeness

`dist/release/THIRD_PARTY_NOTICES.md`, `dist/release/licenses/`, `dist/release/sbom.cdx.json` and `dist/release/provenance.json` are generated from the same source and toolchain lock during packaging. A missing or unreferenced required component blocks the artifact verifier. This inventory is not a legal conclusion or a certification of every transitive license.
