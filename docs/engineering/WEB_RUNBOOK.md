# MirageMesh runtime and release runbook

## Local checkout

Use Linux amd64, installed Go and rootless Podman 4.9.3 alongside Node 24.19.0. Setup
selects Go 1.27.2; see ENGINE_LAUNCH.md. This Node archive bundles npm 11.17.0; invoke
the separately pinned npm CLI 11.9.0 for project commands:

```sh
npx --yes --package=npm@11.9.0 --call 'npm ci --ignore-scripts'
npx --yes --package=npm@11.9.0 --call 'npm run check'
./node_modules/.bin/playwright install chromium
npx --yes --package=npm@11.9.0 --call 'npm run test:browser'
npx --yes --package=npm@11.9.0 --call 'npm run dev'
```

Browser checks may use an operator-provided Chromium executable through the
`WEB_TEST_CHROMIUM` process variable. CI uses the Playwright-managed browser. This test
override never changes application configuration.

Development URL: http://127.0.0.1:5173. To run the built web and supervised Go runtime:

```sh
npx --yes --package=npm@11.9.0 --call 'npm run build'
npx --yes --package=npm@11.9.0 --call 'npm start -- --port 4307'
```

Built URL: http://127.0.0.1:4307. Browser routing uses hashes and hosting at the origin
root. There is no subpath deployment in this release. Change the public nonsecret
configuration in `ops/web/runtime-config.json`; `apps/web/public/runtime-config.json`
must mirror it for static hosts/development. The Node server validates its config at
startup and the browser validates its own project identity. Do not put credentials in
either file.

## What is runnable

The responsive React workspace, forty-step product roadmap, local bounded JSON structure
preview, Node web server and supervised Go engine are implemented. Preview uses tab
memory, does not persist files and does not send them to the server. Reload clears the
preview. This is not a domain import or a security assessment. The PWA manifest supplies
install metadata; there is no service worker or offline claim. Cache rules retain only
fingerprinted static assets; HTML and runtime configuration are no-store.

`GET /healthz` covers the web process; `GET /readyz` covers web assets and valid startup
configuration. `GET /api/engine/health` reads a bounded, validated response from the
owned loopback engine with a two-second deadline and is the only integrated runtime
route. Domain API routes remain 503 in this release. The public engineEnabled flag
remains false; health does not admit work. No upload endpoint or authentication service
is created. Engine admission cannot be enabled by a public config flag.

## Build the complete artifact

```sh
npx --yes --package=npm@11.9.0 --call 'npm run package'
cd dist/release
sha256sum -c SHA256SUMS.txt
node scripts/start-local.mjs --port 4307
```

`npm run package` builds the web workspace and the real Go engine, then creates the full
artifact: engine, web assets, offline contracts/fixtures, source archive and build
recipe, SBOM, notices, license texts, checksums and provenance. The entrypoint is
`scripts/package.sh`; `scripts/package-web.mjs` performs assembly and refuses unsafe
replacement directories. `scripts/verify-artifact.mjs` verifies required paths,
checksums, provenance, SBOM licenses, source-archive contents, offline resources and
forbidden private material.

`provenance.json` records the source commit and tree, source identity, dirty-state
sample, exact toolchain, source-archive digest and SBOM digest. Build from a clean commit
for a releasable record. The packager truthfully marks a dirty tree; that artifact is not
a release. Copy the complete `dist/release` tree to an immutable release directory.

## Private Linux host

Prerequisites: operator-owned domain/DNS, valid TLS certificate/key, installed Node
24.19.0, Nginx, systemd, and an unprivileged `miragemesh-web` account. Rootless Podman
4.9.3 and the pinned Alpine digest are needed only for the optional decoy workflow.
Reserve port 4307 for this project. Keep certificates outside the artifact and never
commit a private key. Install releases under `/srv/miragemesh/releases/<source-commit>`
and point `/srv/miragemesh/current` to the selected verified release. Ensure the service
user has read/execute access to artifact directories. Match the actual Node binary path
in the service file.

Use `ops/web/service.systemd` and render `ops/web/nginx.conf.template` with the real
owned domain, TLS paths and reviewed operator network ranges. The proxy initially denies
external traffic. Keep the deny-all default until private admission is configured and
tested; do not treat an IP range as per-user authentication. The service starts the
supervised Node runtime, which starts the bundled engine on owned loopback. The engine is
not exposed to Nginx directly. Validate the rendered Nginx configuration with `nginx -t`
before reload. Install the service under `/etc/systemd/system/miragemesh-web.service`,
then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now miragemesh-web
curl --fail http://127.0.0.1:4307/healthz
curl --fail http://127.0.0.1:4307/readyz
curl --fail http://127.0.0.1:4307/api/engine/health
sudo journalctl -u miragemesh-web --since '10 minutes ago'
```

Test HTTPS access from an allowed operator and rejection from a disallowed network.
Test that an unsupported domain route stays unavailable. No domain, certificate, host or
credentials were provisioned by the source commit. Inspect `ops/diagnostics.md` for
startup failures.

## Update and rollback

Build/test/package from a clean source commit and verify `SHA256SUMS.txt` before switching
the current symlink. Retain the previous artifact; switch the symlink and restart the
service in a maintenance window. Check both web probes, engine health and browser
navigation. If any fails, restore the previous symlink and restart.

The default packaged runtime does not open durable user data. Once an operator configures
engine storage or providers, a frontend rollback does not roll back engine data. Add
backup/restore and schema-compatibility evidence for that state before calling an update
safe; follow the C30 restart/restore proof and the release policy.

## Engine integration and operations still required

Profile: `private-web`. Retained engine choices: Go sensor and collector, rootless
Podman optional decoy adapter, SQLite metadata/spool, Segmented JSONL events. Typed
contracts, file storage, identity and domain features follow their dependency-ready C
cards. Provider isolation and broader domain authorization remain unverified. Route only
explicitly supported endpoints through a same-origin authenticated service. Keep secrets
exclusively on the server/provider. Add real engine readiness for each enabled surface,
bounded jobs, cancellation, redacted audit, operational metrics, alerts and
retention/restore proof alongside the domain implementation.

For KeyHelix, no plaintext secrets may enter browser file preview; import only synthetic
nonsecret metadata. For RiftRange/MirageMesh, orchestration/sensors stay on isolated
private hosts. Existing RiskWeft Laravel source is preserved and has not been connected
to this shell or certified by web tests.

## Reproduce source evidence

For historical web proof, use its recorded source revision. `python3
scripts/verify_ci_source.py` verifies historical records plus an exact committed checkout;
it intentionally rejects uncommitted source. The digest covers tracked and deliverable
untracked files, excluding only the self-referential evidence JSON and SHA256SUMS.txt.
Build/test output directories are ignored. C03 evidence is in docs/evidence/C03.json with
its explicit checksum method; lifecycle/health proof does not certify the domain workflow.
C31 evidence records the complete-artifact build, verification, reproducibility, isolated
runtime and no-egress observations.
