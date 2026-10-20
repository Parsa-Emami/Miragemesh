# C09 implementation report

Completed the owner-approved local mTLS collector identity guard. It
authenticates collector traffic against locally configured anchors, a locally
delivered signed CRL and an operator fingerprint-to-sensor scope mapping, over
TLS 1.3 with mandatory client verification and no session reuse. No HTTP/UI/CLI
ingest endpoint, certificate issuance, OCSP or other network revocation
transport was added; the C04/C05/C07/C08 behavior and the C05 storage authority
are unchanged.

## Validation

- Go: 145 test run/pass events, no failures; uncached race run and ordinary run.
- Discovery guard: 4 required suites, 21 executed anchors.
- mTLS: trusted collector ingests C07 event bytes through the real sensor/store
  pipeline with durable receipts; missing/untrusted/expired/wrong-EKU/revoked
  identities are denied, typed verdicts are evaluated on captured real
  ConnectionState transcripts, a later revocation stops the replayed identity
  before side effects, and 15 invalid configuration rows fail construction.
- npm: 40 tests passed; TypeScript, web build and real Go engine build passed.
- Browser: 3 Chromium tests passed.
- Python: 6 source-integrity regressions; repository/plan validators passed.
- Real clean clone from the candidate snapshot: setup, Go vet/race/guard, event
  validation and web/engine lifecycle passed; 21 anchors verified in the clone.
- Go format/vet, dependency/resource validation and package checksums passed.
- Focused mTLS test binary under strace: 10 connect() syscalls, all loopback
  AF_INET 127.0.0.1 listeners; no external destination or other socket family.
- Security review: unanchored chain, expired leaves, CRL signature/structure/
  staleness failures, revoked serials anywhere in the presented chain, scope
  mismatches and invalid local configurations are covered with typed verdicts
  that precede decode and scope enforcement before any ingest side effect.

Expected TDD failure (missing pki package before implementation) is retained in
the RED log. Two TLS 1.3 semantics corrections during development — the server
invokes VerifyConnection before handshake completion, and the client handshake
finishes before the server examines the client certificate — are documented in
the committed tests and implementation comments; they occurred before evidence
collection, so no separate failure logs exist for them. No product defect
remained from those iterations. No standalone JavaScript lint script is
configured.

## Source and delivery

- Source identity: `sha256:eaac5e7e8af168f7b847bb4fe903e1977bcacb6d6bf513ac83873cc5357711b7`
  (evidence, plans/progress.json and docs/agents/SESSION_HANDOFF.json excluded;
  recomputable from `docs/evidence/C09/source-files.json`).
- Implementation base: `a746af65eb4b1796c3e71e19d85d93feb199fc79`.
- Verification used an isolated temporary snapshot object
  (`da8658b7cd8e0dac26e2598d322856cc10856bee`, tree
  `b05eab4cf4ef2359f865094a7c7394d4001f123f`) without changing any branch,
  remote ref or the user's staging area; the clean clone and diff check ran
  against that candidate. C09 is delivered in the local commit containing this
  report, with subject `feat(pki): authenticate collector traffic with mtls`.
  No push or publication.
- Progress: C09 verified locally; next task C10; coreReady remains false.

## Changed files

No task files were deleted. This list includes implementation, tests, fixtures,
documentation/status, and the complete evidence inventory:

- `docs/ROADMAP_FA.md`
- `docs/agents/SESSION_HANDOFF.json`
- `docs/architecture/IDENTITY.md`
- `docs/engineering/ENGINE_TESTS.md`
- `docs/evidence/C09.json`
- `docs/evidence/C09/REPORT.md`
- `docs/evidence/C09/all-race.log`
- `docs/evidence/C09/browser.log`
- `docs/evidence/C09/check.log`
- `docs/evidence/C09/clone.log`
- `docs/evidence/C09/diff-check-final.log`
- `docs/evidence/C09/diff-check.log`
- `docs/evidence/C09/discovery.log`
- `docs/evidence/C09/engine-tests.jsonl`
- `docs/evidence/C09/environment.json`
- `docs/evidence/C09/gofmt.log`
- `docs/evidence/C09/green.log`
- `docs/evidence/C09/install.log`
- `docs/evidence/C09/network-check.log`
- `docs/evidence/C09/network-tests.log`
- `docs/evidence/C09/network.trace`
- `docs/evidence/C09/next-task.log`
- `docs/evidence/C09/official-api.log`
- `docs/evidence/C09/package-checksums.log`
- `docs/evidence/C09/package.log`
- `docs/evidence/C09/plan-metadata.log`
- `docs/evidence/C09/plan.log`
- `docs/evidence/C09/python-tests.log`
- `docs/evidence/C09/red.log`
- `docs/evidence/C09/repository.log`
- `docs/evidence/C09/resources.log`
- `docs/evidence/C09/snapshot.json`
- `docs/evidence/C09/source-files.json`
- `docs/evidence/C09/standard-tests.log`
- `docs/evidence/C09/vet.log`
- `internal/pki/identity.go`
- `plans/commits/C09.md`
- `plans/progress.json`
- `plans/project-state.json`
- `plans/roadmap.json`
- `scripts/verify-engine-tests.mjs`
- `tests/engineering/engine-tests.test.mjs`
- `tests/fixtures/miragemesh/C09/expected-output.json`
- `tests/fixtures/miragemesh/C09/invalid.json`
- `tests/fixtures/miragemesh/C09/positive.json`
- `tests/mtls_test.go`

## Limits and recovery

Remote GitHub Actions are unverified. The authenticated ingest endpoint (C16),
certificate rotation (C24), decoy isolation (C13), physical power-loss
durability, C28 capacity and C30/C40 readiness remain outside this proof.
Revocation trusts a locally delivered signed CRL and the local clock; hostile
host-clock rollback and network revocation transports are outside this scope.
The guard is process-local state with no durable writes: an invalid or stale
reconfiguration fails closed at construction and already-ingested events and
prior receipts stay valid; a later revocation is enforced by configuration-only
change on the next connection. SQL schemas, migrations, environment files,
Dockerfiles and dependency/toolchain locks were not changed.
