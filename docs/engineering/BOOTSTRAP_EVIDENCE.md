# C03 bootstrap evidence

See docs/evidence/C03.json and its command logs for actual source identity, fixture hashes, tool/provider identities, command exits and limitations. The checked implementation prepares and supervises the local web and Go runtime; it does not certify event processing, storage, identity, segment rotation, provider isolation, C30 usability or publication.

Synthetic C03 fixtures are repository-authored under Apache-2.0. They cover runtime health and its rejected false product-readiness claim; the included sensor-event sample is not processed by C03. Lifecycle regressions run real Go processes and loopback sockets, including restart, signals, crash, parent death, cancellation, occupied ports and failed compilation preserving the previous binary.

Historical C01/C02 and W evidence retain their original source identities. Current C03 evidence excludes self-referential evidence/progress/handoff metadata as explicitly described in its checksum method. No branch commit or publication is part of this task. Strict commit-source verification is exercised in an isolated candidate snapshot, not relabelled as a clean parent checkout.
