# Complete local artifacts

Status: C31 implements a locally built, verified complete-product artifact. It is not a
published release. C40 remains the authorized published-artifact and installed
full-workflow gate.

## Build

From a clean checkout with the locked toolchain (Node 24.19.0, npm CLI 11.9.0, Go
1.27.2 and rootless Podman for the separate decoy workflow):

```sh
npx --yes --package=npm@11.9.0 --call 'npm run package'
```

`npm run package` runs `scripts/package.sh`, which builds the real web workspace and Go
engine before assembling `dist/release`. For repeat packaging against an existing build:

```sh
node scripts/package-web.mjs --no-build --output /tmp/miragemesh-0.0.1-linux-amd64
```

The packager refuses arbitrary replacement paths. Use `dist/release`, a temporary path
whose final component is `miragemesh-<version>-linux-amd64`, or another directory with
that artifact name.

## Contract

`dist/release` contains:

| Path | Purpose |
|---|---|
| `dist/engine/miragemesh` | Real Go engine, built with `-trimpath` |
| `dist/web/` | Built web workspace used by the local server |
| `scripts/start-local.mjs`, `scripts/serve-web.mjs` | Supervised runtime entrypoint |
| `apps/web/src/lib/` | Browser/server validation adapters used at runtime |
| `ops/web/`, `ops/runtime-requirements.json`, `ops/diagnostics.md` | Private-host templates and limits |
| `contracts/`, `tests/fixtures/miragemesh/C04/`, `tests/fixtures/miragemesh/C30/` | Offline schemas, fixtures and reference scenario |
| `offline/resources.json`, `offline/README.md` | Offline resource inventory; no remote rules or grammars |
| `licenses/`, `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | Project and redistributed upstream texts |
| `source/miragemesh-<version>-source.tar.gz`, `source/provenance.json` | Complete source and build recipe |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM, including host-only prerequisites as excluded components |
| `provenance.json` | Source commit/tree/identity, toolchain, archive and SBOM digests |
| `SHA256SUMS.txt` | SHA-256 digest for every regular file except itself |

The engine binary, web build, contracts and fixtures are all required. A web-only
package fails verification with `missing_required_path`.

## Verify

```sh
cd dist/release
sha256sum -c SHA256SUMS.txt
dist/engine/miragemesh --version
node scripts/start-local.mjs --port 4307
```

`node scripts/verify-artifact.mjs dist/release` performs the same structural checks used
by the packager: required files, executable engine, checksum coverage and integrity,
unsafe or duplicate checksum paths, forbidden private material, provenance fields,
CycloneDX components and licenses, source-archive contents and offline-resource hashes.

The fixture contract is versioned in `tests/fixtures/miragemesh/C31/`; negative cases
cover missing engine/SBOM/source/notice, a modified file, a web-only tree, forbidden
private material, unsafe checksum paths, duplicate checksum entries and incomplete
checksum coverage.

## Reproducibility

`tests/web/package-complete.test.mjs` builds the artifact twice from the same source and
toolchain, in separate temporary directories, and compares every file byte-for-byte,
including provenance, SBOM, source archive and checksums. The source archive is
deterministic: paths are sorted, mtimes and owners are normalized, and gzip is invoked
with `-n`. JSON manifests contain no timestamps or absolute output paths.

Reproducibility across different Node, Go, tar or gzip versions is not claimed. The
provenance records the exact toolchain observed for each build.

## Host-only resources

Node.js, npm CLI, Go toolchain, Podman and the pinned Alpine image are operator
prerequisites. They are not redistributed here. Their versions, digests, official
source routes and licenses are recorded in `docs/engineering/toolchain-lock.json` and
included in the SBOM with `scope: excluded`. The local product runs without a paid or
cloud account. Only the optional decoy workflow pulls the pinned image.

## Release limits

This artifact is installed locally and is not signed, published, uploaded to a package
registry or hosted by the project. It contains no authentication service, telemetry or
customer data. `engineEnabled` remains false; unsupported domain routes return 503. A
releasable provenance record requires a clean source tree; a dirty tree is recorded
truthfully and must not be presented as a release.
