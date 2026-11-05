# Continue MirageMesh

Current: the bounded Linux local profile is published as v0.0.1 with C01-C40 verified against their recorded sources. Public Pages is a static interface. Read docs/product/GLOBAL_READINESS_REVIEW.md for the separate product-readiness gaps and plans/UI_UPGRADE.md for the authorized UI follow-up.

Use Linux amd64, Node 24.19.0, npm CLI 11.9.0, installed Go and rootless Podman 4.9.3. Setup selects Go 1.27.2 through the official Go toolchain mechanism.

```sh
npm run setup
npm start
```

Open http://127.0.0.1:4173. Read docs/engineering/CLONE_TO_RUN.md for actual prerequisites/capability. For implementation read AGENTS.md, docs/agents/EXECUTION_CONTRACT.md and ROADMAP.md, then use:

```sh
npm run validate:plan
npm run plan -- status
npm run plan -- next
```

Each task links exact work/resources/tests. C30 is first actual local usability and C40 full OSS v1; both require evidence. Do not run historical bootstrap or modify protected files.
