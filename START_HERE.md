# Continue MirageMesh

Current: locally usable supported Linux profile through C38. C39 verifies source-bound local release readiness; C40 publication and installed-release proof remain separate.

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
