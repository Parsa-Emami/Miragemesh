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

## Recorded run on 26 October 2026

The [web-foundation run](https://github.com/Parsa-Emami/Miragemesh/actions/runs/40384863051) passed on implementation `db386410acfc6a5d92b9d6699ae605a8bbc4e63d`, with the same tree tested through the PR merge checkout. All four hosted workflows passed. The full browser suite passed 24 tests; Node tests passed 135 of 136 with one C35 foreign-platform test correctly skipped on a matching Linux host. The Go JSON stream records 230 top-level tests and 359 subtests passing; the discovery guard requires 203 anchors across nine engine suites.

| Observation | Measured result |
| --- | --- |
| Complete clone-to-value check | 83.171 s |
| Guide setup in the clean clone | 3.745 s |
| First fresh-state workflow, readiness and browser proof | 3.863 s |
| Second fresh-state workflow, readiness and browser proof | 3.523 s |
| Accepted/acknowledged event sequences | 1, 2, 3, 5 |
| Explicit loss | Sequence 4; exactly one durable gap |
| Recovery | Both runs preserve accepted state after restart/restore |
| Verification host | Linux amd64; 4 logical CPUs; 15990 MiB RAM |
| Tools | Node 24.19.0; npm 11.9.0; Go 1.27.2; rootless Podman 4.9.3 |

The raw report and actual test outputs are retained in `docs/evidence/C36/`. These timings measure the automated procedure on that prepared host, not a human's first-run effort or a new capacity benchmark. Local attempts on the restricted implementation host explicitly failed at rootless Podman, Chromium socket and ptrace prerequisites; those failures remain in `docs/evidence/C36.json`. No checks were disabled to obtain the hosted pass.

## Recovery and limitations

A failure leaves a report with `passed: false`, a nonzero process exit and the failing stage; it never advances project progress automatically. Correct the prerequisite, fixture or provider and rerun the guide command. Temporary cloned code and synthetic state are removed; no existing user state is touched. Retain a failed report separately before rerunning if it is needed for comparison.

The automated run measures preparation and execution time, not human learning time, UX satisfaction, market demand or pilot count. It does not publish a release or certify C37–C40. Linux amd64 is the supported reference profile. Hosts without rootless namespaces or delegated container resource controls must use a supported host; no provider-success substitute is accepted.
