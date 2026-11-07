# Private team monitoring

MirageMesh records interactions with HTTP decoys that you operate. A sensor writes each accepted observation to a private disk spool and delivers it over mutual TLS. The collector acknowledges durable evidence, maintains a rolling timeline, and serves a separately authenticated workspace for analysts.

The source build includes this profile. Release `v0.0.1` contains the original single-operator profile. The team profile uses a separate state directory and follows the existing v1 event contract. GitHub Pages presents the public product workspace.

## Run the loopback lab

On Linux with Go 1.27.2, Node 24, npm 11.9.0 and OpenSSL, run the following from the repository root.

```sh
npm ci --ignore-scripts
npm run build
bash scripts/monitor-lab.sh
```

Run the printed collector and sensor commands in separate terminals. The script writes a private temporary directory and binds the lab to loopback. Send an observation with the printed curl command. The inspect command uses the analyst certificate to return a page of observations. In a disposable browser profile, trust the lab's `operator/ca.crt` and import `operator/analyst.p12` with an empty password. Open the printed workspace URL, select the observation and save a decision.

To test interrupted delivery, stop the collector, send another request to the sensor and inspect its loopback health endpoint. Restart the collector and refresh the workspace. Stop both processes and remove the lab certificates from the disposable browser profile when finished.

## Deploy on a private network

Use separate certificate authorities for sensor and operator traffic. Give each sensor or operator its own directly issued client-auth certificate. Issue a server-auth certificate with the appropriate DNS or IP SAN for each listener, and generate a signed, current CRL for each authority. Keep CA private keys on the issuing host. Compute a client fingerprint over its DER certificate.

```sh
openssl x509 -in client.crt -outform DER | sha256sum
```

The following collector configuration uses sample addresses and fingerprints. Replace them with the site's private addresses, real fingerprints and absolute certificate paths. The service accepts TLS 1.3 and checks certificate validity, CRL freshness and the certificate-to-scope mapping on requests. Reloading credential policy requires a service restart. Plan renewal before the certificates or CRLs expire.

```json
{
  "state_dir": "/var/lib/miragemesh-monitor",
  "web_dir": "/opt/miragemesh/dist/web",
  "retention_hours": 48,
  "max_events_per_hour": 12000,
  "max_event_age_minutes": 60,
  "requests_per_hour_alert": 25,
  "workspace_origin": "https://monitor.example.internal:9444",
  "collector": {
    "listen": "10.24.0.10:9443",
    "certificate": "/etc/miragemesh-monitor/collector.crt",
    "key": "/etc/miragemesh-monitor/collector.key",
    "ca": "/etc/miragemesh-monitor/sensors-ca.crt",
    "crl": "/etc/miragemesh-monitor/sensors.crl"
  },
  "workspace": {
    "listen": "10.24.0.10:9444",
    "certificate": "/etc/miragemesh-monitor/workspace.crt",
    "key": "/etc/miragemesh-monitor/workspace.key",
    "ca": "/etc/miragemesh-monitor/operators-ca.crt",
    "crl": "/etc/miragemesh-monitor/operators.crl"
  },
  "sensors": {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": ["edge-01"]
  },
  "operators": {
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
      "id": "analyst-01",
      "role": "analyst",
      "sensors": ["edge-01"]
    }
  }
}
```

A `viewer` can read assigned sensors and evidence. An `analyst` can also append a decision for assigned evidence. The persisted actor comes from the certificate mapping. Keep operator IDs stable across credential rotations and unique across people.

Configure each HTTP sensor separately.

```json
{
  "sensor_id": "edge-01",
  "listen": "10.24.0.20:9080",
  "health_listen": "127.0.0.1:9081",
  "spool_dir": "/var/lib/miragemesh-sensor",
  "queue_limit": 1000,
  "collector_origin": "https://collector.example.internal:9443",
  "ca": "/etc/miragemesh-sensor/sensors-ca.crt",
  "certificate": "/etc/miragemesh-sensor/client.crt",
  "key": "/etc/miragemesh-sensor/client.key"
}
```

Create the dedicated service accounts named in the units and install the source build under `/opt/miragemesh`. Make configuration and certificates readable by the corresponding account. Restrict each private key to its owner with mode `0600`. Place the JSON files at the locations in the units. Systemd creates the private state directories. Use private routing and firewall policy to limit the collector to sensor networks, the workspace to operator networks, and the sensor's outbound connections to the collector and required infrastructure. Keep browser TLS client authentication on the workspace connection.

```sh
sudo install -m 0644 ops/monitor/miragemesh-monitor.service /etc/systemd/system/
sudo install -m 0644 ops/monitor/miragemesh-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now miragemesh-monitor
sudo systemctl enable --now miragemesh-sensor
```

Install only the unit appropriate to each host. The workspace `GET /readyz` probe uses an operator certificate. The sensor's loopback `GET /readyz` returns 503 for a full spool, held observations, or a delivery failure. `GET /healthz` returns queue counts and the current delivery status. The built-in sensor sends an authenticated heartbeat and its spool counts every 15 seconds. The workspace shows heartbeats as overdue after 45 seconds. After a collector restart, the connection indicator awaits the next heartbeat.

## Ingest and workspace API

The collector accepts one existing v1 `http.request` JSON event per `POST /api/ingest/v1/events`. It accepts up to 8 KiB, a positive sequence, and a URL path of up to 512 bytes. Sensor certificates only admit events for mapped sensor IDs. The built-in sensor records its request path, a generated ID, sequence and observation time. Keep sensitive values out of decoy paths.

The successful receipt includes `event_id`, `sequence` and `sha256`. A new event returns 201. An exact replay returns 200 with the original receipt. Keep the same event ID, sequence and bytes on retry. The collector removes trailing LF characters before hashing. The sensor checks the receipt before removing an event from its spool.

For liveness, scoped sensors can also send JSON `{"sensor_id":"edge-01","pending":0,"held":0}` to `POST /api/ingest/v1/heartbeat`. The collector returns 204 and records its receipt time in memory.

| Response | Handling |
|---|---|
| `403 forbidden_sensor` | Check the client identity's configured sensor scope. |
| `409 event_conflict` | Inspect the reused event ID or sequence. Preserve the original observation. |
| `422 event_outside_window` | The sensor moves the record to its private held queue for review. |
| `422 event_from_future` | Check time synchronization. The sensor retains the record for retry. |
| `503 collector_capacity` | Retry with backoff. Capacity resets at the UTC hour boundary. |

The workspace listener serves same-origin APIs and the built console.

| Method and path | Access and behavior |
|---|---|
| `GET /api/team/v1/session` | Current operator ID, role and assigned sensors. |
| `GET /api/team/v1/sensors` | Hourly interaction count, recent activity and rate signal per assigned sensor. |
| `GET /api/team/v1/incidents?limit=20` | Newest first. Optional `sensor` filter and opaque `before` from `next_cursor`. Limit 1–50. |
| `GET /api/team/v1/incidents/{id}` | Evidence, exact payload hash and decision history for an assigned sensor. |
| `POST /api/team/v1/incidents/{id}/triage` | Analyst only. Send the exact workspace `Origin`, a stable 16–128 character `Idempotency-Key` and JSON with `status` and `reason`. Status is `investigating`, `resolved` or `dismissed`. Reason is up to 1024 UTF-8 bytes. |

The hourly rate signal identifies a sensor that reached the configured interaction count within a UTC receipt hour. It is an input to analyst review.

## Retention, recovery and operating limits

- Set 2–168 retention hours and up to 60,000 events per UTC hour. The product of the two limits is capped at one million retained observations. These are configuration ceilings. Measure the actual workload on your storage and hardware.
- The collector keeps the current and configured preceding UTC hour partitions. It expires old partitions and their triage records while running. The admission window must be shorter than the retained hours excluding the current hour. Exact retries can recover a receipt while the event's partition is retained.
- Evidence segments are flushed before acknowledgement. On restart the collector rebuilds its index from segment files. It reports incomplete partitions in the timeline. The sensor uses a private bounded spool and retains expired observations as held files. A full spool rejects new requests with 503. Inspect and archive held files with the sensor stopped before removing them from the spool.
- Keep system time synchronized. The collector fails closed if its clock moves behind the active UTC hour. Monitor readiness, free disk, spool pressure and CRL expiry with the site's alerting system.
- Back up the collector state directory, sensor spool and identity configuration separately. Stop the writer for a consistent file copy, preserve permissions and verify a restore into new private directories before use. Protect disk and backups with the site's encryption and access policy.

This profile targets a single Linux collector per state directory. Each process uses an exclusive lock. Plan workload validation, backup recovery and service monitoring on the intended host before admitting operational traffic.
