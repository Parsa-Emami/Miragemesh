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
the checkout stays clean) reviewed the delivered guard
`c89127f8f7c20e0b1f65cabcfbc96185a009845c` and then the round-one fix. Round
one found a valid must-fix: CRL membership was matched by serial number alone
although RFC 5280 identifies a revoked certificate by (issuer, serial), while
`New` only accepted CRLs signed by a configured anchor and
intermediate-including chains still executed. The round-one fix implements
the reviewer's smallest suitable option plus issuer-keyed membership:

- `Verify` rejects client chains that are not exactly `[leaf, terminal
  anchor]` with the leaf issued directly by that anchor
  (typed `ErrUntrusted`), so an intermediate-issued collector that would
  only be revocable through its intermediate's CRL is structural out of
  scope and can never bypass revocation by presenting a chain x509 itself
  labels as verified.
- CRL membership is matched per certificate on `(issuer, serial)`, never on
  the serial alone.
- Both round-one reviewer regressions were reproduced against the pre-fix
  matcher by temporarily reverting the matcher in the worktree only
  (`docs/evidence/C09/review-red-reverted-matcher.log`); after restoring the
  fix both tests pass, as do all anchors before. The restriction and the
  RFC source are documented in `IDENTITY.md` and the C09 card.

The round-two follow-up review confirmed the resolved parts and found the
remaining security gap: the guard accepts client certificates from a second
configured anchor while certifying only one CRL, so that issuer's collectors
authenticate although their revocation can never be represented. The
committed round-two fix chooses the reviewer's smallest suitable option
again — reject leaves whose issuer is not the CRL issuer:

- `New` records the SHA-256 fingerprint of the configured anchor that
  verified the CRL (the revocation authority) and `Verify` rejects any
  `[leaf, anchor]` chain whose terminal anchor is not that authority with
  typed `ErrUntrusted`: the accepted client-issuer set is exactly the CRL
  issuer population, so every accepted collector stays revocable and
  uncovered issuers fail closed.
- The rewritten cross-issuer regression
  (`TestMTLSRejectsIssuersWithoutRevocationCoverage`) asserts the contract
  across a real dual-anchor listener: the secondary-issued collector whose
  serial appears on the primary CRL is denied typed `ErrUntrusted` — never
  `ErrRevoked` — while the covered primary-issued collector still
  authenticates and ingests and the primary-issued same-serial collector
  stays revoked with zero new receipts.
- Both contract-bearing tests were run against the reverted pre-fix
  matcher and failed exactly on the finding
  (`docs/evidence/C09/review-red-uncovered-issuer.log`): the uncovered
  colliding collector authenticated and ingested under the old code
  (identities=2 receipts=2, zero denials). The CRL issuer is matched by
  key (anchor fingerprint), not by subject DN, so two CAs sharing one
  subject name can never apply each other's membership; issuer-plus-serial
  matching is preserved.

## Validation

- Go: 146 test run/pass events, no failures; uncached race run and ordinary run.
- Discovery guard: 4 required suites, 22 executed anchors.
- mTLS: trusted collector ingests C07 event bytes through the real sensor/store
  pipeline with durable receipts; missing/untrusted/expired/wrong-EKU/revoked,
  intermediate-issued and uncovered-issuer chains are denied, typed verdicts
  are evaluated on captured real ConnectionState transcripts, the issuer
  coverage contract is proven across a real dual-anchor listener (secondary
  -issued serial 7004 denied as untrusted; covered collector ingests;
  primary-issued same serial stays revoked), a
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
- Focused mTLS test binary under strace: 14 connect() syscalls, all loopback
  AF_INET 127.0.0.1 listeners; no external destination or other connect socket
  family.
- Security review: unanchored chains, direct-issuance violations, expired
  leaves, CRL signature/structure/staleness failures, issuer-matched revoked
  serials, uncovered issuers, scope mismatches and invalid local
  configurations are covered with typed verdicts that precede decode and
  scope enforcement before any ingest side effect.

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

- Source identity: `sha256:d1a815b9e433dea184856c0d61bd241e1441f25cdc37825062e9b7f71696cff1`
  (evidence, plans/progress.json and docs/agents/SESSION_HANDOFF.json excluded;
  recomputable from `docs/evidence/C09/source-files.json`).
- Implementation base: `a746af65eb4b1796c3e71e19d85d93feb199fc79`; round-one
  review fix: `d1eebc79bc24455b6f1907e3b343c8effc255800` (review base for the
  round-two follow-up); this commit carries the round-two fix with subject
  `fix(pki): require CRL issuer coverage for client chains`.
- Verification used an isolated temporary snapshot object
  (`8c5aef00bb526eb96cd7ba340af9a0b693b64d57`, tree
  `0be5ddd33eece53091bb255e8f5aba9706605968`) without changing any branch,
  remote ref or the user's staging area; the clean clone and diff check ran
  against that candidate. No push or publication.
- Progress: C09 verified locally; next task C10; coreReady remains false.

## Changed files

No task files were deleted. This list includes the round-two review-fix
implementation, tests, the updated expected fixture verdicts, guards,
documentation/status, and the evidence artifacts refreshed by this revision:

- `docs/agents/SESSION_HANDOFF.json`
- `docs/architecture/IDENTITY.md`
- `docs/engineering/ENGINE_TESTS.md`
- `docs/evidence/C09.json`
- `docs/evidence/C09/REPORT.md`
- `docs/evidence/C09/all-race.log`
- `docs/evidence/C09/browser.log`
- `docs/evidence/C09/check.log`
- `docs/evidence/C09/clone.log`
- `docs/evidence/C09/engine-tests.jsonl`
- `docs/evidence/C09/green.log`
- `docs/evidence/C09/install.log`
- `docs/evidence/C09/network-check.log`
- `docs/evidence/C09/network-tests.log`
- `docs/evidence/C09/network.trace`
- `docs/evidence/C09/python-tests.log`
- `docs/evidence/C09/review-red-uncovered-issuer.log`
- `docs/evidence/C09/snapshot.json`
- `docs/evidence/C09/source-files.json`
- `docs/evidence/C09/standard-tests.log`
- `internal/pki/identity.go`
- `plans/commits/C09.md`
- `plans/progress.json`
- `scripts/verify-engine-tests.mjs`
- `tests/engineering/engine-tests.test.mjs`
- `tests/fixtures/miragemesh/C09/expected-output.json`
- `tests/mtls_test.go`

## Limits and recovery

Remote GitHub Actions are unverified. The authenticated ingest endpoint (C16),
certificate rotation (C24), decoy isolation (C13), physical power-loss
durability, C28 capacity and C30/C40 readiness remain outside this proof.
Revocation trusts a locally delivered signed CRL and the local clock; hostile
host-clock rollback and network revocation transports are outside this scope.
The accepted client-issuer set is exactly the configured anchor that signed
the CRL; coverage of a second issuer requires that issuer's own CRL, which
the single `RevocationListPEM` option cannot carry today. The guard is
process-local state with no durable writes: an invalid or stale
reconfiguration fails closed at
construction and already-ingested events and prior receipts stay valid; a later
revocation is enforced by configuration-only change on the next connection.
SQL schemas, migrations, environment files, Dockerfiles and dependency/toolchain
locks were not changed.
