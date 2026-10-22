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
