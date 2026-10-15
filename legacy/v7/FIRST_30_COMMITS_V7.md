# MirageMesh — First 30 Commit Plan v7

These are atomic intent boundaries, not mandatory commit-message text. Do not combine unrelated items merely to hit a number.

1. chore: initialize toolchain manifests and lockfiles
2. ci: make repository validation executable
3. chore: add local development environment/health checks
4. test: add clean-bootstrap smoke test
5. docs: freeze Phase 0 invariants and ADR index
6. phase0: go sensor bootstrap
7. phase0: one-time enrollment
8. phase0: openBao-backed mTLS identity issuance/rotation
9. phase0: device identity binding
10. test(phase0): add replay/expiry tests
11. docs(phase0): record exit evidence and ADR updates
12. phase1: version signed desired-state envelope
13. phase1: monotonic revision/fencing semantics
14. phase1: applied-state acknowledgements with reason codes
15. phase1: reject rollback/stale configuration
16. test(phase1): add signature tests
17. docs(phase1): record exit evidence and ADR updates
18. phase2: stable event IDs
19. phase2: bounded encrypted/local spool design
20. phase2: reconnect replay and deduplication
21. phase2: backpressure/drop policy with explicit counters
22. test(phase2): add offline/reconnect tests
23. docs(phase2): record exit evidence and ADR updates
24. phase3: rootless Podman decoys
25. phase3: no-egress default network
26. phase3: resource/capability limits
27. phase3: lifecycle cleanup/reconcile
28. test(phase3): add egress denial
29. docs(phase3): record exit evidence and ADR updates
30. test: close Phase 0/1 regression or failure-proof gap before scope expansion
