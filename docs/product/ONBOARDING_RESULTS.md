# Independent clone-to-value verification (C36)

C36 repeats the public onboarding procedure in a fresh Git transport clone, installs the committed dependency lockfile and runs the real engine and browser workflow twice with separate private state directories. This is automated clean-environment evidence, not a claim that an independent person tested the product or that customers requested it.

The entry points are [Clone to Run](../engineering/CLONE_TO_RUN.md) and the [User Guide](../release/USER_GUIDE.md). Run `npm run test:clone` after preparing their documented toolchain, rootless Podman image and Playwright Chromium. Source changes must be staged: the check verifies the Git index so a proposed commit can be tested before publication. The source checkout's `dist` and `node_modules` are never used by the cloned workflow. System compiler, provider/image and browser caches are prepared host prerequisites, not a claim of an empty machine or offline dependency installation.

## What the check observes

The runner checks the exact cloned Git tree and historical source integrity, then executes `npm run setup`, Go vet, uncached Go race tests and the required-test discovery guard. It runs the C30 sensor enrollment, signed configuration, real loopback mTLS ingestion, bounded offline spool, duplicate acknowledgements, explicit loss, durable triage and non-destructive retention preview against real storage. Each run restarts the accepted store, opens an independent restored copy, starts the clone-owned engine and web assets twice, checks engine/storage/certificate-provider readiness and renders the Sensors, Incidents and Certificates views in Chromium.

The versioned C36 event fixtures exercise the actual Go event-validator binary. The valid event remains structural validation, not an admission or persistence claim. Invalid event input returns exit 1 and `INVALID_INPUT`. Missing Go fails setup before installing dependencies. Missing or malformed licensed fixtures fail explicitly without placeholder state. A missing required issuer fails engine startup; restoring the declared provider configuration reopens the same accepted manifest and segment bytes. The browser also verifies unavailable domain services show an alert rather than successful empty data, then recovers against accepted state before and after restart.

## Results and observed effort

`dist/ci/onboarding.json` records the source identity, guide and fixture hashes, tool versions, start/end times, elapsed time per command, expected and actual exit codes, typed failures and the outcomes of both fresh-state runs. `dist/ci/onboarding-logs/` contains the actual command output. These are generated observations, never fixed success examples. GitHub's web-foundation job uploads them even on failure. The committed `docs/evidence/C36.json` records the verification source and links the hosted result when available.

Runtime/browser checks assert loopback requests only. The full required engine suite retains the real rootless-container egress-denial and resource-limit tests; this check does not weaken those prerequisites. Setup may download locked dependencies and compiler resources; runtime no-egress and installation downloads are distinct phases.

The implementation fixes the previous harness importing `startLocal` from the parent checkout. The workflow now runs as a child process from the fresh clone and refuses another working directory. The reference-scenario validator now recognizes the implemented acceptance/browser/clone runners, while retaining planned-scenario validation and rejection of unsupported execution claims.

## Recovery and limitations

A failure leaves a report with `passed: false`, a nonzero process exit and the failing stage; it never advances project progress automatically. Correct the prerequisite, fixture or provider and rerun the guide command. Temporary cloned code and synthetic state are removed; no existing user state is touched. Retain a failed report separately before rerunning if it is needed for comparison.

The automated run measures preparation and execution time, not human learning time, UX satisfaction, market demand or pilot count. It does not publish a release or certify C37–C40. Linux amd64 is the supported reference profile. Hosts without rootless namespaces or delegated container resource controls must use a supported host; no provider-success substitute is accepted.
