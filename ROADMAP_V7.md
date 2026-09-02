# MirageMesh — Definitive Sequential Roadmap v7

**Portfolio order:** 8 / 10
**Complexity:** Very high
**Planning estimate:** 14–20 focused weeks (not a promise; recalibrate after Phase 1)

**Why this order:** Useful but operationally complex; safe decoy isolation, signed desired state, PKI and fleet updates need mature primitives first.

## First executable proof
mTLS sensor enrollment → signed desired state → no-egress decoy → offline event spool → reconnect/replay/deduplicate → applied-state proof.

## Rules for this repository
- One phase at a time; no implementation work for phase N+1 before phase N exit evidence is merged.
- Contract/schema changes precede dependent implementation.
- Every retryable operation is idempotent.
- Every derived store/projection has a rebuild path.
- Negative and failure tests are part of the feature, not post-release hardening.
- Status claims must be evidence-backed.

## Phase 0 — Sensor identity/enrollment

**Implementation deliverables**
- Go sensor bootstrap
- One-time enrollment
- OpenBao-backed mTLS identity issuance/rotation
- Device identity binding

**Required verification**
- replay/expiry tests
- cert rotation tests
- stolen-token tests

**Definition of Done**
- Enrollment is single-use and subsequent control-plane access requires the issued sensor identity.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 1 — Desired/applied protocol

**Implementation deliverables**
- Version signed desired-state envelope
- Monotonic revision/fencing semantics
- Applied-state acknowledgements with reason codes
- Reject rollback/stale configuration

**Required verification**
- signature tests
- stale revision tests
- reorder/duplicate tests

**Definition of Done**
- Sensor never applies unsigned or older desired state and reports exact applied revision.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 2 — Event envelope/spool

**Implementation deliverables**
- Stable event IDs
- Bounded encrypted/local spool design
- Reconnect replay and deduplication
- Backpressure/drop policy with explicit counters

**Required verification**
- offline/reconnect tests
- duplicate event tests
- spool full tests

**Definition of Done**
- Network loss does not corrupt ordering/identity; overflow behavior is explicit and observable.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 3 — OCI decoy supervisor

**Implementation deliverables**
- Rootless Podman decoys
- No-egress default network
- Resource/capability limits
- Lifecycle cleanup/reconcile

**Required verification**
- egress denial
- resource exhaustion
- crash cleanup

**Definition of Done**
- Decoy cannot reach external network by default and is destroyed/reconciled without leaked runtime resources.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 4 — HTTP decoy plugin

**Implementation deliverables**
- Minimal safe HTTP decoy API
- No command execution or arbitrary file access
- Structured event emission
- Template/version pinning

**Required verification**
- abuse input tests
- event schema tests
- plugin isolation tests

**Definition of Done**
- HTTP interactions create events without creating a general-purpose remote execution surface.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 5 — Correlation/incident story

**Implementation deliverables**
- Correlate sensor/decoy events by stable IDs
- Incident timeline projection
- Evidence provenance and uncertainty markers
- Search without mutating raw evidence

**Required verification**
- correlation fixtures
- projection rebuild tests

**Definition of Done**
- Derived incident story can be discarded/rebuilt from immutable normalized events.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 6 — TUF updates/fleet rollout

**Implementation deliverables**
- TUF metadata/roles
- Signed sensor/decoy artifacts
- Staged rollout and rollback
- Expired metadata rejection

**Required verification**
- freeze/rollback attack tests
- staged rollout tests

**Definition of Done**
- Sensors reject expired/rollback update metadata and can return to prior known-good artifact safely.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 7 — Additional safe decoys

**Implementation deliverables**
- One protocol at a time behind plugin contract
- Threat model each protocol
- Strict resource/network boundary
- Protocol-specific event schemas

**Required verification**
- plugin contract suite
- protocol abuse fixtures

**Definition of Done**
- Each added decoy passes the common isolation contract before being enabled by default.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 8 — Hardening/public v1

**Implementation deliverables**
- Fleet failure drills
- PKI compromise/revocation runbook
- Load/backpressure benchmark
- Signed release/SBOM

**Required verification**
- revocation drill
- large fleet simulation
- clean install

**Definition of Done**
- Public v1 demonstrates safe degradation during control-plane loss and certificate revocation/re-enrollment.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Public v1 invariant
The project is not called production-ready merely because all phases are coded. `PUBLIC-V1-GO` requires the repository release gate, clean-install proof, security/recovery evidence and signed/verifiable release artifacts.
