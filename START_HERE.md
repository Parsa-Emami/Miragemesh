# Continue MirageMesh

Use the [public demo](https://parsa-emami.github.io/Miragemesh/) to explore the interface with sample data. For the published local Linux profile, follow the [release installation guide](docs/release/PUBLICATION.md). Build from source for [private team monitoring](docs/engineering/TEAM_MONITORING.md).

Use Linux amd64, Node 24.19.0, npm CLI 11.9.0, installed Go and rootless Podman 4.9.3. Setup selects Go 1.27.2 through the official Go toolchain mechanism.

```sh
npm run setup
npm start
```

Open http://127.0.0.1:4173. See the [clone guide](docs/engineering/CLONE_TO_RUN.md) for prerequisites and supported workflows. For development, read the [agent entry point](AGENTS.md), [execution contract](docs/agents/EXECUTION_CONTRACT.md) and [roadmap](ROADMAP.md).

```sh
npm run validate:plan
npm run plan -- status
npm run check
```

The [release gate](docs/release/V1_GATE.md) explains how to verify a release candidate against its exact source.
