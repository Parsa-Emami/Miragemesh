# MirageMesh maintenance policy

Policy revision: C38, 2026-10-28. Applies with
[SERVICE_POLICY.md](SERVICE_POLICY.md) to the repository's local `0.0.1`
profile. It supersedes earlier unsupported support promises. No public v1
release, commercial service or guaranteed response time is established here.

## Supported source and platforms

`main` is the active maintenance line; a change is verified only by evidence
bound to its exact source and passing required workflows. Old commits remain
reproducible historical sources, not independently maintained branches. There
is no blanket support promise for all `v0.x` tags. Future release support and
end-of-support dates must be stated in actual release notes; no fixed lifetime
or backport cadence is promised before those releases exist.

The full-workflow reference platform is Ubuntu 24.04 Linux amd64 with the
versions and integrity pins in [toolchain-lock.json](../engineering/toolchain-lock.json):
Node 24.19.0, npm 11.9.0, Go 1.27.2 and rootless Podman 4.9.3 with working user
namespaces and cgroup delegation. The pinned Alpine image must be prepared
locally. Other hosts and filesystems need independent workflow, isolation and
recovery evidence. The 8 events/s, five-sensor profile and its short constrained
measurement are described in [the service policy](SERVICE_POLICY.md); they
are not availability or latency SLAs.

## Community support and security

Use [GitHub issues](https://github.com/Parsa-Emami/Miragemesh/issues) for ordinary
bugs and feature requests. Include the reviewed commit, platform, locked tool
versions, exact command, typed error/exit, synthetic reproduction and relevant
redacted output. Preserve failed attempts. A maintainer may request a smaller
reproduction or decline unsupported deployments; community help is best effort.

For suspected vulnerabilities, follow [SECURITY.md](../../SECURITY.md): use
GitHub Private Vulnerability Reporting only when the repository offers its
private report form. This policy does not assert that reporting is enabled or
invent an alternate mailbox. Do not publish an exploit or sensitive data in an
issue to work around an unavailable private channel. No 48-hour acknowledgment,
five-day triage, fixed disclosure deadline, uptime, remediation deadline or
on-call coverage is guaranteed. Coordinate disclosure with the maintainer when
a private route exists; publish verified affected/fixed versions with the fix.

## Dependency and provenance policy

`package.json` and `package-lock.json` pin the web dependency set; `go.mod` pins
the selected Go toolchain and currently has no external Go modules. The
toolchain lock inventories compiler/provider/image versions, official sources,
integrity values, licenses and source-build steps. The source remains
Apache-2.0; shipped dependencies need compatible explicit licenses and notices.
Unknown, restricted or missing required provenance blocks release.

Dependabot is configured for weekly npm and GitHub Actions proposals with five
open pull requests per ecosystem. A proposed update is not an automatic install
or permission to merge. There is no background runtime updater. Review direct
and transitive changes, security advisories, compatibility, lifecycle scripts,
licenses and checksums before changing a pin. Advisory review is best effort;
this policy is not evidence that a vulnerability scan has run or found nothing.

For an intentional dependency/toolchain/provider update, change the relevant
manifest and lock together, regenerate official resource identity and shipped
notices/SBOM as applicable, and document the actual migration or incompatibility.
Do not hand-edit integrity fields to bypass a mismatch, use floating image tags,
run unknown install scripts, suppress analysis broadly or skip a failing check.
No database schemas, migrations, `.env` files or Dockerfiles are changed under
this task. Use the compatible existing adapters and record precise blockers.

## Verification before acceptance

Keep the existing domain, browser, packaging and clean-clone checks enabled.
On the supported prepared host, run the commands applicable to the change:

```sh
npm run validate:plan
python3 scripts/validate_repo.py
python3 -m unittest discover -s tests/engineering -p 'test_*.py' -v
npm run check
go vet ./...
mkdir -p dist/ci
go test -race -count=1 -json ./... > dist/ci/engine-tests.jsonl
node scripts/verify-engine-tests.mjs dist/ci/engine-tests.jsonl
npm run test:browser
npm run test:clone
npm run package
npm run verify:artifact
```

`contracts`, `plan-consistency`, `engine-runtime` and `web-foundation` must pass
on the exact candidate before it is certified. Required engine discovery keeps
real SIGKILL, syscall/ENOSPC injection, lost-ACK replay, quota, retention,
revocation and no-egress anchors mandatory; Node/browser checks alone do not
prove those boundaries. Preserve command exits/output, fixture hashes/licenses,
source/tree identity, tool/provider versions and failed attempts in evidence.
Record local host limitations explicitly; a skipped or unexecuted case is not
positive proof. Historical evidence stays attached to its original source.

New routes, stored fields, CLI modes or trust changes must update the threat
model and security matrix and add real negative cases. Real payloads, private
keys and host secrets never belong in fixtures, CI artifacts or source archives.
Policy changes require reviewing the public guide, security policy and shipped
offline policy copies for consistency. C39 checks C01-C38 release prerequisites;
C40 separately requires authorized publication and the installed published
artifact workflow. Green C38 CI does not publish a release.

## Upgrade, rollback and recovery

Stop writers and create/check a complete private backup as described in
[SERVICE_POLICY.md](SERVICE_POLICY.md#backup-and-recovery-procedure). Keep the
last compatible reader, accepted data and separate trust material. Source
builds remain available through `npm run setup`, `npm start`, `npm run package`
and `npm run verify:artifact`; no paid account or release signature is needed
to build your own reviewed source.

For a genuinely published artifact, use the
[detached attestation and install procedure](ARTIFACTS.md#signed-release-attestation).
Supply a trusted public key obtained independently and stored outside the
artifact. Verify exact artifact, source, SBOM and validity before installation.
Sensor `--verify-update` verifies a local candidate only; it does not install
or execute it. The operator chooses whether and when to install software.

Install/upgrade/rollback preserve the data directory; they do not migrate,
compact, erase, repair or restore it. Installation metadata records the chosen
path, current/previous release and highest revision. A same-release retry still
checks all installed bytes. `installed_release_modified`, `unsafe_data_dir`,
`unsafe_prefix`, expired/untrusted authority, stale revision and incompatible
data schemas fail explicitly. Preserve the refused bytes and investigate;
do not reset revision state, replace the trusted key with an artifact-supplied
key or delete a manifest to force acceptance.

Rollback selects only the recorded previous verified release and refuses an
older reader that cannot accept the current data schema. Even where a schema
number is unchanged, newer typed records or retention audit require a compatible
reader; a numeric check alone is not semantic compatibility proof. Prefer tested
forward repair while preserving latest accepted bytes. Never overwrite newer
state, resurrect expired sources or undo revocation/recovery floors with an old
backup. Rehearse restore in a separate location and recheck current authority
before switching the local workflow to it.

## Evidence and policy revisions

[C37 evidence](../evidence/C37.json) is the verified entry dependency.
[C38 evidence](../evidence/C38.json) records this policy's actual acceptance,
including real-file stopped copies and typed corruption/quota/replay refusal;
the existing engine suites prove crash/ACK/egress boundaries. Future policy
changes must state a new revision, source-bound verification and operational
consequences. Update progress and session handoff only after the claimed work
has been observed; do not mark C39/C40 complete as a side effect of documentation.
