# C19: explainable alerts

C19 derives read-only findings during the existing one-shot `--project-segments`
workflow. It adds no listener, endpoint, schema, migration, or dependency. The
existing C18 index is rebuilt from committed segment files on each run and
provides every source reference in an alert.

## Explicit rate policy

Rate derivation is opt-in. Pass both `--alerts-rate-limit N` and
`--alerts-window-seconds S`; there is no implicit threshold or window. Values
must be positive, and the window is an integer number of seconds. Supplying only
one flag or an invalid value fails with `error_kind:"invalid_input"`.

For each sensor, C19 sorts accepted HTTP request events by their validated
`observed_at` timestamp and finds the largest set whose first and last times
are no more than the configured window apart (the boundary is inclusive). If
that set reaches the configured count, the result includes one `attack_signal`
with its count, observed interval, and exact C18 source references. This is a
signal for review, not proof of an attack. Each accepted event also has an
`interaction` finding referencing that event. Event content and request paths
are not copied into the alert output.

## Sensor health and evidence limits

`sensor_health` findings are derived only from validated durable C15 spool gap
records. They report the dropped count and gap sequence numbers separately from
rate signals. Missing indexed events, incomplete segment tails, or missing
segment ordinals do not create a health alert and do not prove that an event
never occurred. `coverage_complete` carries the C18 index coverage status so a
consumer can see when the available source set is incomplete.

The CLI emits typed JSON with the explicit policy, findings, and source
references (`sensor_id`, `event_id`, `sequence`, `segment`, `record`, and
payload `digest`). C20 owns triage, C21 owns health presentation, and C22 owns
the user-facing segment trace.

## Fixtures and checks

Repository-authored Apache-2.0 synthetic examples and expected outcomes are in
`tests/fixtures/miragemesh/C19/`. Rule tests validate source identity/digests,
require an explicit policy, retain incomplete coverage, and distinguish durable
loss evidence from observed interactions. A subprocess test runs projection,
reopens the persistent segments, and checks that the same alerts and source
references are reproduced without changing C05 records.
