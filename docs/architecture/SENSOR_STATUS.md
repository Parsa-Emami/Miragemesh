# C21: Local sensor status projection

C21 exposes a read-only `GET /api/v1/sensors` endpoint on the engine's existing
loopback listener. It builds each response from committed C05 records and C11's
signature-verified applied configuration. It does not accept events, write
records, expose event metadata, or claim a live network connection.

The versioned response is:

```json
{
  "schema_version": "1",
  "offline_after_seconds": 300,
  "sensors": [
    {
      "sensor_id": "sensor-01",
      "last_event_at": "2026-10-21T00:00:00Z",
      "offline": true,
      "config_status": "expired",
      "dropped_event_count": 1
    }
  ]
}
```

Sensors are listed in identifier order and are discovered from committed event,
gap and applied-configuration records. A sensor with no event is offline and
has `last_event_at: null`. Otherwise it is offline only when its highest
accepted sequence has an event timestamp more than five minutes before the
snapshot clock. `config_status` is `missing`, `expired` or `current`; `expired`
uses the expiry in the verified signed desired-state document. Dropped events
count durable C15 gap markers, not inferred sequence holes.

## Local runtime configuration

Status is disabled by default. Set all listed options to enable it; partial
configuration makes the engine exit with a configuration error. Values are
deployment policy and have no built-in limits:

- `--sensor-status-dir`, `--sensor-status-max-operations`,
  `--sensor-status-max-bytes`, `--sensor-status-max-manifest-bytes` configure
  the existing C05 store and its explicit quotas.
- `--sensor-config-public-key` points to a file containing exactly the raw
  32-byte Ed25519 public key. The private signing key is never read by the
  engine or browser.
- `--sensor-config-max-sensors` and the six
  `--sensor-config-{min,max}-{heartbeat-seconds,spool-limit-events,event-batch-limit}`
  options provide the explicit C10 verifier limits.

The same options can be passed to `npm start`; the local supervisor forwards
them directly to its engine child without a shell. The engine binds the same
loopback-only listener as its health endpoint and holds the C05 store lock for
its lifetime. Without status configuration, the exact endpoint returns 503
with `sensor_status_unavailable`. It returns only a complete typed snapshot;
storage, recovery or verification errors also return that generic failure.

The web proxy permits only GET for this exact path, uses no-store responses,
rejects malformed or oversized upstream JSON, and contacts only the verified
loopback engine address. The browser validates the schema before rendering it.
The UI refreshes the snapshot every five seconds. Enrollment, ingest and
configuration writes remain outside C21.

## HTTP authority and refresh failures

Both the engine and local web server accept only `127.0.0.1`, `localhost` or
`[::1]` on their listener port. An absent Origin is allowed for the local proxy
and operator tools; a present Origin must exactly match `http://` plus the
request authority. Foreign hosts, foreign origins and opaque `null` origins
return 403 with `{"error":"forbidden_origin"}` before reading local state.
This is a loopback boundary, not remote authentication or multi-user access.
DNS-rebinding browser exploitation has not been certified; the negative tests
exercise actual HTTP Host/Origin rejection at both listeners.

The implemented collection route and typed 200/403/405/503 responses are recorded
in both OpenAPI representations. Other planned routes do not become implemented
because they appear there. The disabled default engine returns a typed 503;
an absent provider is not passed as a typed nil pointer into the reader interface.

After a successful refresh, the UI keeps the last valid snapshot and its receipt
time if a later refresh fails. An alert marks the entire displayed snapshot as
stale and automatic retries continue. Initial unavailability, access denial,
invalid JSON/schema and network failure produce explicit errors. Recovery
replaces the snapshot, updates the receipt time and clears the stale alert.
The retained values are never asserted to be current during a failed refresh.
The refresh effect remains cancellation-safe, following the
[React effect cleanup contract](https://react.dev/reference/react/useEffect).
