# C12: metadata-only HTTP decoy

The internal decoy answers one HTTP request with a fixed answer and records one
bounded observation of it. The only observed request field is the path. The
decoy never executes a command, never opens a file, never contacts a remote
service and never echoes request content back to the caller. It is a component
of the engine, not a published surface: no listener is added here and no
container isolation is proven here.

```go
service, err := decoy.New(ctx, store, decoy.Options{ // same C05 store
    SensorID:        "decoy-01",
    MaxRequestBytes: 1024,
    MaxPathBytes:    256,
    Clock:           clock,
})
service.ServeHTTP(response, request)
```

`New` requires an open C05 store and the explicit bounds of the deployment.
The engine ships no default: a missing store, a missing clock, an invalid
identity or a bound outside the version 1 event payload limit returns
`decoy.ErrInvalidInput` instead of a decoy without limits.

## Observed request

| Request | Status | Body | Recorded |
| --- | --- | --- | --- |
| Allowed method, valid path, body inside the bound | 200 | `{"status":"ok"}` | One observation |
| Path empty, too long, not valid UTF-8 or with a control character | 400 | `{"error":"invalid_request"}` | No |
| Method outside `GET`, `HEAD`, `POST` | 405 with `Allow` | `{"error":"method_not_allowed"}` | No |
| Declared or observed body above the request bound | 413 | `{"error":"request_too_large"}` | No |
| Store or acceptance failure | 503 | `{"error":"unavailable"}` | No |

Every response carries `Content-Type: application/json`,
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. The bodies are
fixed constants: they contain no request-derived value, no internal state and
no error detail. A `HEAD` request is answered with the status and the headers
only. The query string, the headers and the body are discarded; the body is
read only to enforce the bound.

A rejected request is not an observation. The decoy reports a failure it did
not durably record, and it never reports a success it did not record: the
store error path answers 503 instead of the accepted body.

## Recorded observation

The observation is the existing version 1 event: `schema_version`, `sensor_id`,
`event_id`, `sequence`, `observed_at`, `kind` of `http.request` and a
`metadata` object with the single `path` member. The decoy validates it with
the C04 contract and commits it through `sensor.Accept`, so the durable store,
the replay rules and the sequence rules stay unchanged. No second event format
and no new record type are introduced.

The identity of the decoy is separate from a device identity. Decoy
observations are recorded under `decoy-01` and never share the sequence space
of the reported sensor events, so an accepted device event and an accepted
decoy observation can live in the same store.

The event identifier is derived from the identity and the sequence of the
observation. The sequence advances only after the store accepted the record,
so a failed observation leaves no gap in the accepted history.

## Restart and recovery

`New` reads the durable history and continues the sequence of the accepted
observations of its identity. A decoy rebuilt on the reopened store continues
at the next sequence: no duplicate and no gap. A history that is not
contiguous fails closed with `storage.ErrRecovery` instead of being
renumbered.

The observation timestamp is the trusted local clock of the deployment, as in
C07 and C11. A host clock rollback is not defended against.

## Not proven here

No engine listener is published, no container is started and no egress is
denied: the isolation and the runtime limits are the C13 work. The decoy
package imports only the standard HTTP, hashing and JSON packages and the
existing contract, sensor and storage packages; it cannot open a file, run a
process or dial a remote service. The recorded path is never resolved against
a file, a command or a URL. The regression anchor of the package parses every
file of it: it requires the exact import set, resolves the local name of the
`net/http` import from its declaration, rejects a dot import and admits only
the handler API, so an outbound client call fails the anchor whatever name it
uses.

No database schema, migration, environment file, Dockerfile, public API,
dependency or product setting limit changes. After observations are accepted,
keep the directory and a C12-compatible reader; an older reader rejects the
decoy identity and do not restore an older backup to make a rollback succeed.

The request bound follows the Go standard library
[request body limits](https://pkg.go.dev/net/http#MaxBytesReader); the event
contract follows [Go JSON byte encoding](https://pkg.go.dev/encoding/json#Marshal).
