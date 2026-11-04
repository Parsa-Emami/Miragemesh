# Public distribution and installed-release verification

MirageMesh has two distribution surfaces. GitHub Pages serves the public browser
workspace at <https://parsa-emami.github.io/Miragemesh/>. The complete Linux amd64
release contains the Go engine, local web workspace, offline contracts and fixtures,
source archive, SBOM, license notices, checksums and installation verification tools.
The public site never connects to a local or remote operational API. Hash routes and
the project subpath work without a server fallback. Sensor data and credentials stay
on the operator's host; they are not included in the Pages bundle.

## Publication contract

The owner authorized publication on 2026-11-04. RELEASE_MANIFEST.json records that
scope and the selected 0.0.1 version. C40 remains in progress until an actual release
has been downloaded and installed on another clean supported runner and the complete
reference task passes there. Publication does not certify additional operating
systems, a hosted service, multi-user authorization or a higher workload capacity.

The read-only release-gate workflow first checks the complete exact source. A
separate release build repeats that proof and packages the result. Only the publish
job receives contents, OIDC and attestation write permissions. It refuses a dirty
source, changed assets, missing checks, a moved main branch, or an existing release.
It publishes a prerelease; a fresh installation job promotes it only after the
published bytes pass signature verification, installation, workflow, restart and
restore checks. Failed verification leaves an explicit prerelease and failed run.
Existing release assets and tags must never be silently replaced.

GitHub Pages has its own unprivileged build and browser tests. Only the deployment
job has pages:write and id-token:write, and only main can deploy. Public pull requests
can build and test without publishing.

## Authenticate the download

The archive and per-release public key receive GitHub OIDC build attestations.
The Ed25519 signing private key exists only in a restricted temporary build directory
and is removed after signing; it is never committed, uploaded or retained as a
production credential. The detached signature proves artifact integrity once the
operator has authenticated the public key. A key downloaded beside an archive is
not independently trusted merely because the signature matches.

Use the official GitHub CLI to authenticate repository and workflow identity before
trusting the key. Check the exact source commit and source tree in candidate.json,
provenance.json and the release attestation against the published tag.

```sh
gh release download v0.0.1 --repo Parsa-Emami/Miragemesh --dir miragemesh-download
cd miragemesh-download
sha256sum -c SHA256SUMS.txt
gh attestation verify miragemesh-0.0.1-linux-amd64.tar.gz --repo Parsa-Emami/Miragemesh --signer-workflow Parsa-Emami/Miragemesh/.github/workflows/release.yml
gh attestation verify release-ed25519.pub --repo Parsa-Emami/Miragemesh --signer-workflow Parsa-Emami/Miragemesh/.github/workflows/release.yml
tar -xzf miragemesh-0.0.1-linux-amd64.tar.gz
```

Publication authentication requires Internet access to GitHub's attestation service.
Prepared local engine operation does not. The signatures and checksum files are
retained for offline integrity checks after the public key has been authenticated.

## Install the complete release

Use the supported Linux amd64 profile and Node 24.19.0. Set absolute paths outside
the artifact for the installation and accepted operator data. The rootless Podman
version and locked decoy image remain prerequisites for isolation scenarios; they
are not silently installed by the artifact. Read CLONE_TO_RUN.md for provider setup.

```sh
ARTIFACT="$PWD/miragemesh-0.0.1-linux-amd64"
node "$ARTIFACT/scripts/install-release.mjs" install \
  --artifact "$ARTIFACT" \
  --manifest "$PWD/miragemesh-0.0.1-linux-amd64.release.json" \
  --signature "$PWD/miragemesh-0.0.1-linux-amd64.release.sig.json" \
  --trusted-key "$PWD/release-ed25519.pub" \
  --prefix "$PWD/installed" \
  --data-dir "$PWD/operator-data"
node installed/releases/miragemesh-0.0.1-linux-amd64/scripts/start-local.mjs
```

## Repeat the installed verification

The artifact includes a separate, clearly labelled verification executable compiled
from the same source's real acceptance modules. It generates synthetic identities
and a fresh isolated temporary state directory, then runs enrollment, signed apply,
real loopback mTLS delivery, offline spool, loss accounting, duplicate ACK handling,
triage, retention preview, restart and an independent restored copy. Its transport
harness is a verifier, not a newly published ingest protocol. The installed Go
engine then opens that accepted state through the real runtime and sensor, incident
and certificate surfaces twice. Neither a Go compiler nor a source checkout is
used by this installation probe.

```sh
node installed/releases/miragemesh-0.0.1-linux-amd64/scripts/verify-installed-release.mjs "$PWD/installed-proof.json"
```

The proof binds both binary hashes and verifies that restart leaves accepted manifest
and segment bytes unchanged. The fresh release gate also retains actual crash,
lost-ACK, quota, egress and signed installation/upgrade/rollback regressions. The
first public release has no earlier published version to roll back to; the existing
installer must refuse an absent or incompatible previous release without replacing
newer accepted data. No claim of a tested upgrade from an invented public version
is made. Physical power failure and multi-day capacity are separate unmeasured cases.

The verification-capsule.tar.gz asset retains the full fresh readiness report and
all hashed command logs beyond the temporary Actions artifact retention period.
The public launch.json asset records installed-source/version, observed steps,
negative outcomes, recovery and the actual workflow URL. Keep verification state
private; only the bounded summary belongs in release evidence. Release signing
metadata expires one year after issue; renew publication authority explicitly
instead of weakening expiry or anti-rollback checks.

## Official implementation references

- <https://vite.dev/guide/static-deploy.html#github-pages>
- <https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages>
- <https://github.com/actions/deploy-pages>
- <https://github.com/actions/attest-build-provenance>
- <https://cli.github.com/manual/gh_attestation_verify>
- <https://docs.github.com/en/rest/releases/releases#create-a-release>
