# C22: local incident replay and triage

The Incidents page reads actual C17/C18 segment frames through a bounded engine
view. It lists C19 interaction and rate findings, replays each source event by
keyboard or table, and appends C20 status/reason records to C05. Request paths,
sensor IDs and review text render as text. They are never HTML, links to fetch,
file paths to open or commands to execute.

## Enable the local view

After preparing an existing C05 store and projecting its events with
`--project-segments`, start the supervised web and engine with explicit limits.
The following limits are example operator policy, not measured capacity:

```sh
npm start -- \
  --incident-state-dir /absolute/private/state \
  --incident-segments-dir /absolute/private/segments \
  --incident-max-operations 128 \
  --incident-max-bytes 2097152 \
  --incident-max-manifest-bytes 131072 \
  --incident-segments-max-count 16 \
  --incident-segments-max-records 2 \
  --incident-segments-max-bytes 32768 \
  --incident-rate-limit 2 \
  --incident-window-seconds 60
```

Open `http://127.0.0.1:4173/#incidents`. Every flag above is required. Missing,
overlapping, unsafe or locked storage fails startup. No event source, key or
policy is downloaded. The view uses existing local stores; it does not create
synthetic product results. The Apache-2.0 fixture seeder in
`tests/fixtures/miragemesh/C22/seed.go` is a test utility only.

When Sensors and Incidents are enabled together, both must use the same absolute
C05 directory and identical storage quotas. The engine shares its existing
single writer. Segment startup uses C17 recovery: a torn active tail can be
renamed to its preserved incomplete form. HTTP reads never append events,
project new events, delete segments or acknowledge collector batches.

## Source and coverage

`GET /api/v1/incidents` returns schema version `1`, the explicit rate policy,
coverage, the count of C05 events absent from the segment index, and findings.
Each source includes sensor ID, event ID, sequence, segment ID, one-based record
and SHA-256 of the exact original event payload. Replay reads through the
confined segment adapter, decodes both legacy and multiline frames, and checks
the payload against the rebuilt index before exposing the typed event.
When C05 retains the same event, its exact normalized payload digest must also
agree. Rebuilding the index after a valid-but-changed segment cannot silently
replace the accepted C05 source.

Incident IDs are `incident-` plus SHA-256 of the canonical C19 finding. Sources
and rate policy therefore participate in identity. IDs survive restart and
active-to-sealed renames; changing a rate finding's source set yields a distinct
incident. This is a local finding collection, not cross-sensor correlation.
C15 spool losses remain separate on Sensors because lost bytes have no source
segment to replay.

Missing ordinals, incomplete segments and unprojected events remain explicit.
Complete available segment coverage does not establish a complete history of
traffic. Corrupt, missing or changed indexed bytes return unavailable instead
of an empty or clean result. The view accepts at most 256 indexed events and a
1 MiB serialized snapshot. Exceeding a view limit returns unavailable without
truncating or deleting evidence; pagination is not implemented. The source
stores retain their explicit operator quotas.

## Local mutation boundary

`POST /api/v1/incidents/{incident}/triage` is enabled only with the local view.
Host must name loopback at the listener port. Origin is mandatory for a write
and must exactly match that HTTP authority. The web proxy forwards only the
exact route to its owned loopback engine. It never follows upstream redirects.
This is a single-host local operator boundary; it does not authenticate remote
or multiple users and does not change the local-private readiness gate.

The body remains exactly C20's `status` and `reason`, with an `Idempotency-Key`
and `application/json`. Unknown or duplicate fields, malformed input, over-bound
bodies, unsupported methods and unknown source-backed incident IDs are rejected
before mutation. HTTP acceptance is `202` only after C05 returns the durable
receipt. Same-key replay returns that receipt; changed input returns `409`.
History exposes status, reason and UTC timestamp, without raw keys or key
digests. Source segments and observed event records remain unchanged.

The browser retains a pending operation's original key and exact body after an
interrupted or ambiguous save. Inputs and incident switching are locked until
the user retries the same operation or receives a definitive rejection.
Pending retry state lasts while that page remains mounted; it is not persisted
in browser storage. A successful refresh reads authoritative durable history.
Refresh failure retains the last snapshot with an explicit stale warning.

## Verification

`internal/incidentview/view_test.go` checks exact source digests, real C05
history and replay after restart, conflict and unknown-incident rejection,
unchanged segments, missing/tampered sources, cancellation, unprojected coverage
and bounded views. `cmd/miragemesh/incidents_test.go` checks the real loopback
HTTP boundary and rejects invalid requests without changing the manifest.
The discovery guard requires these anchors in engine CI.

`apps/web/tests/incidents.spec.ts` seeds real temporary stores and segments,
launches the actual supervised engine, navigates and saves by keyboard at
360px, restarts it, and reads durable history. It also discards a real committed
write response and proves same-key retry produces one history entry. Synthetic
HTML sentinels remain inert and the browser makes no external request. Separate
negative tests exercise disabled, invalid, empty, interrupted and stale states.
