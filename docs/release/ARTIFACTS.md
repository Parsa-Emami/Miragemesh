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

## Signed release attestation

C35 adds a detached Ed25519 attestation for an already packaged artifact. The artifact
tree is not modified: `release.json` and `release.sig.json` are distributed beside it,
and the signature covers the exact bytes of the manifest. The manifest binds the
artifact name, version, platform, monotonic release revision, validity window, source
commit/tree/identity, declared data schema, and the SHA-256 digests of `SHA256SUMS.txt`,
`provenance.json`, `sbom.cdx.json` and the source archive.

A maintainer signs with a PKCS#8 Ed25519 private key that never belongs in the
repository or the artifact:

```sh
node scripts/sign-release.mjs \
  --artifact dist/release \
  --key ~/.config/miragemesh/release-key.pem \
  --revision 1 \
  --expires-at 2027-10-25T00:00:00Z \
  --output dist/attestations \
  --public-key-out ~/.config/miragemesh/release-key.pub
```

The public key, or its SHA-256 fingerprint over the raw 32-byte key, is published
out-of-band and copied outside the artifact. Verification never accepts a trust root
from inside the artifact:

```sh
node scripts/verify-release.mjs dist/release \
  --manifest dist/attestations/miragemesh-0.0.1-linux-amd64.release.json \
  --signature dist/attestations/miragemesh-0.0.1-linux-amd64.release.sig.json \
  --trusted-key ~/.config/miragemesh/release-key.pub
```

A changed artifact byte, a changed manifest byte, missing evidence, a wrong signer,
or an expired manifest fails with a typed error and a non-zero exit. Verification does
not infer trust from the presence of a signature, a checksum file or a provenance
record alone. The verifier ships in the source archive; obtain it from the repository
or the source archive rather than trusting a script inside a downloaded artifact.

The repository does not contain a production release key or a published signature.
`tests/release/upgrade-recovery.mjs` generates ephemeral test keys, signs a locally
built artifact, and exercises the positive and negative cases. Actual key publication
and signing belong to the authorized C40 release.

## Verified upgrade and rollback

`scripts/install-release.mjs` verifies the attestation before changing the install
prefix. Releases live side by side and are activated through a private
`install-state.json`; the data directory is never copied, rewritten or rolled back.

```sh
node scripts/install-release.mjs install \
  --prefix ~/.local/lib/miragemesh \
  --artifact dist/release \
  --manifest dist/attestations/miragemesh-0.0.1-linux-amd64.release.json \
  --signature dist/attestations/miragemesh-0.0.1-linux-amd64.release.sig.json \
  --trusted-key ~/.config/miragemesh/release-key.pub \
  --data-dir ~/.local/state/miragemesh

node scripts/install-release.mjs upgrade --prefix ~/.local/lib/miragemesh ...
node scripts/install-release.mjs rollback --prefix ~/.local/lib/miragemesh \
  --trusted-key ~/.config/miragemesh/release-key.pub
```

`upgrade` requires a newer version and a revision above the durable high-water mark
unless that exact release was already accepted (so a release can be reactivated after
rollback). Rollback only targets the recorded previous release and re-verifies the
installed bytes before activation; a modified installed tree is refused. The data
directory is opened read-only for compatibility and is never written. A store whose C05
manifest declares a newer `schema_version` than the target release's signed
`data.store_schema` is refused with `data_schema_newer`, so an older release cannot be
activated over newer accepted data. The installer also refuses a foreign platform
unless `--allow-foreign-platform` is given for staging, and runs the installed engine's
`--version` check when the host matches the signed platform.

## Source-build alternative

The verified-artifact installer is optional. The documented source path remains the
primary build route and needs no release key, account or network service at runtime:

```sh
npm run setup
npm start
npm run package
npm run verify:artifact
```

`npm run package` still assembles the complete source archive, build recipe, SBOM,
licenses, checksums and provenance used by both the source-build and signed-artifact
paths.

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

A C31 artifact is unsigned by default. C35 adds the detached attestation path for a
maintainer who publishes the matching public key; no production signature is created by
the build itself. No artifact is published, uploaded to a package registry or hosted by
the project in this repository. The product contains no authentication service,
telemetry or customer data. `engineEnabled` remains false; unsupported domain routes return 503. A
releasable provenance record requires a clean source tree; a dirty tree is recorded
truthfully and must not be presented as a release.

## C37 installation refusal and retry behavior

Repeated installation and same-release upgrades verify the entire installed release before returning `idempotent`. A changed installed file returns `installed_release_modified` without rewriting state or accepted data. Verify against the independently trusted attestation and restore only known original release bytes before retrying; an idempotent call is not a repair command.

The data directory must be separate from `releases`, `attestations` and their descendants, and must not contain the install prefix. This boundary resolves filesystem aliases, including reserved metadata symlinks into data. Overlap is refused as `unsafe_data_dir` before writes; the default `prefix/data` remains supported. Rollback applies the same data-path check. A prefix that resolves into the signed source artifact is refused as `unsafe_prefix` before any staging writes. Missing required API arguments return the existing typed `usage` error. Detailed reproductions and checks are in [BETA_FIXES.md](../product/BETA_FIXES.md).
