# Third-party inventory

Updated 2026-10-19. Web package facts come from the committed npm lockfile. Toolchain artifact pins and source/license references are in `docs/engineering/toolchain-lock.json`. Complete distributed notices/license texts and SBOM are C31 work; this index is not compliance certification.

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

Sources: [Ajv](https://ajv.js.org/), [formats](https://github.com/ajv-validator/ajv-formats). Complete shipped-artifact notices remain C31 work.

## Planned engine resources

| Resource | Version | Declared license | Source / notes |
|---|---|---|---|
| Node.js runtime | 24.19.0 | MIT | [release source](https://github.com/nodejs/node/tree/v24.19.0); Node archive SHA-256 is in the toolchain lock. |
| npm CLI (separate invocation) | 11.9.0 | Artistic-2.0 | [release source](https://github.com/npm/cli/tree/v11.9.0); Node 24.19.0 bundles npm 11.17.0, so use the pinned CLI package. |
| Go toolchain | 1.27.2 | BSD-3-Clause | [source tag](https://go.googlesource.com/go/+/refs/tags/go1.27.2); official source build path and checksum metadata are in the toolchain lock. |
| Podman Ubuntu provider | 4.9.3 (`4.9.3+ds1-1ubuntu0.2`) | Apache-2.0 (main project; package files may vary) | [Ubuntu source package](https://launchpad.net/ubuntu/+source/libpod/4.9.3+ds1-1ubuntu0.2); reference package is for Ubuntu 24.04 amd64. |

No OCI image, external grammar or rule bundle has been selected; those choices belong to C12/C13. The package inventory above is not a complete redistribution notice or SBOM.
