# MirageMesh: clone to run

## Runnable today

Use Linux amd64 with Git, Node 24.19.0, npm CLI 11.9.0, an installed Go command (1.21+ for toolchain selection) and rootless Podman 4.9.3 (Ubuntu 24.04 reference package 4.9.3+ds1-1ubuntu0.2), then:

```sh
git clone https://github.com/Parsa-Emami/Miragemesh.git
cd Miragemesh
npx --yes --package=npm@11.9.0 --call 'npm run setup'
npx --yes --package=npm@11.9.0 --call 'npm start'
```

Open http://127.0.0.1:4173. Setup checks Go and rootless Podman, installs the committed web lockfile with lifecycle scripts disabled, and builds the web and Go runtime. The official Go toolchain mechanism selects/downloads and verifies Go 1.27.2 without replacing the system Go. No database or cloud account is required. The workspace previews JSON locally and browses the roadmap; the supervised Go HTTP runtime supplies health/version only. The separate local --validate-event command validates a v1 event without ingesting or storing it (see contracts/README.md). Full domain processing remains unavailable.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `npm run doctor` reports tool/provider versions, built runtime version and web/core state; Go resolution may require a download if its cache is missing. `npm run release:check` deliberately exits 2 until full evidence is ready. Ctrl+C stops both web and the owned engine process. Ports can be selected with `npm start -- --port 4301` when running multiple projects.

## Full-product contract to implement

The same clone/setup/start sequence must prepare and supervise the actual Go engine and required self-hosted open-source resources by C30. No second undocumented terminal, paid account, sibling clone or owned public domain. C03 supplies local lifecycle/health and C31 supplies verified convenience artifacts plus a documented source-build alternative. Downloads may be needed to prepare resources; user payloads are not sent to a compulsory proprietary service. No global runtime install, system trust change or user data deletion occurs implicitly.

Local resources: rootless Podman for isolated decoys. Hardware target: 2 vCPU / 2048 MiB RAM / 10240 MiB free disk plus real dataset/provider/backup space. These are unmeasured targets until C28. Full engine support initially targets Linux x86_64; other hosts require their own actual C30/C33 evidence. Rootless workloads need Linux or a tested Linux/WSL2 host.

`local-demo` uses synthetic fixtures and isolated development providers; `local-private` requires real identity/permission, provider durability, revocation and restore evidence before sensitive use. A development provider mode never becomes a production vault/gateway by relabeling it.

## Checks

```sh
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

The current test:clone performs a real local Git clone of the staged/committed source, runs setup and verifies unified startup, actual Go runtime health and disabled domain admission. C30 must extend it to the full tests/scenarios/clone-to-value.json workflow and real engine readiness. Current lifecycle checks cannot certify domain functionality. See ENGINE_LAUNCH.md for lifecycle tests and recovery. See each C task for future engine commands and prerequisites. Optional hosting/package operations remain in WEB_RUNBOOK.md.
