# C09 implementation report

Completed the owner-approved local mTLS collector identity guard, including
the review-driven revocation-matching fix. It authenticates collector traffic
against locally configured anchors, a locally delivered signed CRL and an
operator fingerprint-to-sensor scope mapping, over TLS 1.3 with mandatory
client verification and no session reuse. No HTTP/UI/CLI ingest endpoint,
certificate issuance, OCSP or other network revocation transport was added;
the C04/C05/C07/C08 behavior and the C05 storage authority are unchanged.

## Review fix

The owner `review.md` report (worktree root, kept git-ignored and untracked so
the checkout stays clean) found a valid must-fix in the delivered guard
`c89127f8f7c20e0b1f65cabcfbc96185a009845c`: CRL membership was matched by
serial number alone although RFC 5280 identifies a revoked certificate by
(issuer, serial), while `New` only accepted CRLs signed by a configured
anchor and intermediate-including chains still executed. The committed fix
implements the reviewer's smallest suitable option plus issuer-keyed
membership:

- `Verify` rejects client chains that are not exactly `[leaf, terminal
  anchor]` with the leaf issued directly by that anchor
  (typed `ErrUntrusted`), so an intermediate-issued collector that would
  only be revocable through its intermediate's CRL is structural out of
  scope and can never bypass revocation by presenting a chain x509 itself
  labels as verified.
- CRL membership is matched per certificate on `(issuer, serial)`, never on
  the serial alone, so a legitimate same-serial certificate issued by
  another configured anchor is never falsely revoked.
- Both reviewer regressions were reproduced against the pre-fix matcher by
  temporarily reverting the matcher in the worktree only
  (`docs/evidence/C09/review-red-reverted-matcher.log`); after restoring the
  fix both tests pass, as do all anchors before. The restriction and the
  RFC source are documented in `IDENTITY.md` and the C09 card.

## Validation

- Go: 146 test run/pass events, no failures; uncached race run and ordinary run.
- Discovery guard: 4 required suites, 22 executed anchors.
- mTLS: trusted collector ingests C07 event bytes through the real sensor/store
  pipeline with durable receipts; missing/untrusted/expired/wrong-EKU/revoked
  and intermediate-issued chains are denied, typed verdicts are evaluated on
  captured real ConnectionState transcripts, issuer-bound revocation membership
  is proven across a real dual-anchor listener (secondary-issued serial 7004
  accepted and ingested while the primary-issued same serial stays revoked), a
  later revocation stops the replayed identity before side effects, and 15
  invalid configuration rows fail construction.
- npm: 40 tests passed; TypeScript, web build and real Go engine build passed.
  The roadmap-tooling regression was updated so it checks the first not-yet
  verified task instead of a hard-coded delivered index.
- Browser: 3 Chromium tests passed.
- Python: 6 source-integrity regressions; repository/plan validators passed.
- Real clean clone from the candidate snapshot: setup, Go vet/race/guard, event
  validation and web/engine lifecycle passed; 22 anchors verified in the clone.
- Go format/vet, dependency/resource validation and package checksums passed.
- Focused mTLS test binary under strace: 13 connect() syscalls, all loopback
  AF_INET 127.0.0.1 listeners; no external destination or other connect socket
  family.
- Security review: unanchored chains, direct-issuance violations, expired
  leaves, CRL signature/structure/staleness failures, issuer-matched revoked
  serials, scope mismatches and invalid local configurations are covered with
  typed verdicts that precede decode and scope enforcement before any ingest
  side effect.

Expected TDD failure (missing pki package before implementation) is retained in
the RED log, together with the per-revision review-fix failure record. Two TLS
1.3 semantics corrections during development — the server invokes
VerifyConnection before handshake completion, and the client handshake finishes
before the server examines the client certificate — are documented in the
committed tests and implementation comments; they occurred before evidence
collection, so no separate failure logs exist for them. No product defect
remained from those iterations. No standalone JavaScript lint script is
configured.

## Source and delivery

- Source identity: `sha256:f29ad0323fefb2f9145933be3a3ce710dd957e07dbf23d3994dae102b2c50bc7`
  (evidence, plans/progress.json and docs/agents/SESSION_HANDOFF.json excluded;
  recomputable from `docs/evidence/C09/source-files.json`).
- Implementation base: `a746af65eb4b1796c3e71e19d85d93feb199fc79`; review fix
  base: `c89127f8f7c20e0b1f65cabcfbc96185a009845c`.
- Verification used an isolated temporary snapshot object
  (`70acbe1ccc3c48bcff97d189677ed06b9ba73b20`, tree
  `305849c955c6ab75769fd2d64e62b6eafc6d5a33`) without changing any branch,
  remote ref or the user's staging area; the clean clone and diff check ran
  against that candidate. The original C09 delivery commit carries the first
  implementation and this commit carries the review fix with subject
  `fix(pki): match CRL revocation to certificate issuer`.
  No push or publication.
- Progress: C09 verified locally; next task C10; coreReady remains false.

## Changed files

No task files were deleted. This list includes the review-fix implementation,
tests, fixtures regenerated with the new identities, documentation/status, and
the complete evidence inventory:

- `.gitignore`
- `apps/web/src/generated/project.json`
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
- `docs/evidence/C09/package-checksums.log`
- `docs/evidence/C09/package.log`
- `docs/evidence/C09/plan-metadata.log`
- `docs/evidence/C09/plan.log`
- `docs/evidence/C09/python-tests.log`
- `docs/evidence/C09/red.log`
- `docs/evidence/C09/repository.log`
- `docs/evidence/C09/resources.log`
- `docs/evidence/C09/review-red-reverted-matcher.log`
- `docs/evidence/C09/snapshot.json`
- `docs/evidence/C09/source-files.json`
- `docs/evidence/C09/standard-tests.log`
- `docs/evidence/C09/vet.log`
- `internal/pki/identity.go`
- `plans/commits/C09.md`
- `plans/progress.json`
- `scripts/verify-engine-tests.mjs`
- `tests/engineering/engine-tests.test.mjs`
- `tests/fixtures/miragemesh/C09/expected-output.json`
- `tests/fixtures/miragemesh/C09/invalid.json`
- `tests/fixtures/miragemesh/C09/positive.json`
- `tests/mtls_test.go`
- `tests/web/oss-tooling.test.mjs`

## Limits and recovery

Remote GitHub Actions are unverified. The authenticated ingest endpoint (C16),
certificate rotation (C24), decoy isolation (C13), physical power-loss
durability, C28 capacity and C30/C40 readiness remain outside this proof.
Revocation trusts a locally delivered signed CRL and the local clock; hostile
host-clock rollback and network revocation transports are outside this scope.
The guard honors its documented single revocation authority: only chains
directly issued by a configured anchor are accepted, so revocation coverage of
a second issuer requires that issuer's own CRL, which the single
`RevocationListPEM` option cannot carry today. The guard is process-local state
with no durable writes: an invalid or stale reconfiguration fails closed at
construction and already-ingested events and prior receipts stay valid; a later
revocation is enforced by configuration-only change on the next connection.
SQL schemas, migrations, environment files, Dockerfiles and dependency/toolchain
locks were not changed.
