# MirageMesh local event contract v1 (C04)

`input.schema.json` and `result.schema.json` define Draft 2020-12 documents for a **local, stateless event validator**. The shared Go package `internal/contracts` implements the boundary. A valid document is not an enrolled/authenticated sensor, accepted collector observation, durable write, deduplicated event or completed product workflow. HTTP exposes runtime health, the opt-in C21 sensor status collection and the opt-in C22 local incident replay/triage view; browser file preview remains a local structural preview. The sensor API is documented in `openapi.v1.json` and `docs/architecture/SENSOR_STATUS.md`; it does not add event admission.

## Run and reuse

```sh
npx --yes --package=npm@11.9.0 --call 'npm run build:engine'
./dist/engine/miragemesh --validate-event < tests/fixtures/miragemesh/C04/valid-event.txt
npx --yes --package=npm@11.9.0 --call 'npm run test:contracts'
```

The flag must be used alone: no --listen, --version, file arguments or network destinations. stdin is consumed only by validation, before the service supervisor's stdin watcher is installed. stdout contains one result JSON document; stderr is reserved for usage/output failures. Exit 0 means valid structure, exit 1 means rejected input/read failure/cancellation/deadline, and exit 2 means invalid CLI usage. A two-second deadline covers reading and validation. SIGINT/SIGTERM cancel it; missing EOF times out. No provider, network, filesystem storage, shell or payload execution is part of validation.

Engine consumers reuse `DecodeEvent(context, boundedBytes)` and typed `Event`/`HTTPMetadata`; it checks cancellation and limits without owning a reader. `Validate(context, io.ReadCloser, engineVersion)` owns and closes the reader, including on cancellation. Its reader must unblock on Close (as the CLI's stdin and Go pipes do); future adapters that own their I/O should call DecodeEvent instead. The CLI supplies the two-second context; shared callers must supply their own bounded operation context.

## Input

All seven fields are required and unknown names/casing are rejected:

| Field | Contract |
|---|---|
| schema_version | String `"1"` only |
| sensor_id, event_id | Nonempty opaque strings, at most 128 Unicode code points; no registration/existence or UUID assumption |
| sequence | Exact integer from 0 through 9007199254740991; no monotonicity, allocation or replay claim |
| observed_at | Valid RFC3339 calendar/time with uppercase T/Z, explicit zone, seconds 00–59 and optional decimal fractions; Go validates the calendar and preserves the input string |
| kind | `http.request` only |
| metadata | Object with only required nonempty string `path`; no nested object/array, headers or credential fields |

The entire raw document, including whitespace, is at most **8192 UTF-8 bytes**, matching the declared 8 KiB product payload limit. Limits are checked before parsing. Invalid UTF-8, unpaired UTF-16 escapes, repeated keys (including escaped spellings), trailing JSON/data and non-object roots are rejected. No key/value coercion or automatic data removal occurs. Path is inert metadata, never a file or URL to read or execute; this structural contract is not the capture/redaction policy that C12 must implement.

Schema validation operates on JSON values. Byte size, duplicate-key rejection, valid Unicode escapes and exact numeric lexemes additionally require the Go decoder: JavaScript JSON.parse can round a fractional/oversized number before JSON Schema sees it. Integer-valued decimal/exponent forms such as 1.0 and 1e0 are accepted exactly; fractional, out-of-range and nonzero extreme exponents are rejected without float rounding or unbounded exponent allocation.

## Result

The existing envelope names are retained with schema_version `"1"`, the actual engine_version, input_digest, result and warnings (always `[]` in C04).

- Success has status `unverified` and result `{ "valid": true, "sensor_id": "sensor-01", "event_id": "event-01", "sequence": 1 }`. It verifies syntax/shape only.
- Failure has status `failed` and result `{ "valid": false, "error": { "code": "INVALID_INPUT", "field": "metadata" } }`. field is optional and limited to known top-level contract names; unknown field names and offending values are never echoed. No generic data/result object or successful processing status is returned.
- input_digest is lowercase SHA-256 over **exact complete input bytes**, including whitespace, on success or complete-document rejection. It is null for oversize, read failure, cancellation or timeout; it never describes a partial input as complete. It is not a signature or authenticity proof.

| Code | Meaning |
|---|---|
| INVALID_JSON | Invalid JSON/UTF-8/Unicode escape, root shape, duplicate keys or trailing input |
| UNSUPPORTED_VERSION | Missing, incorrectly typed or unsupported schema_version |
| INVALID_INPUT | Missing/wrong field types, unknown/case-mismatched names or domain bounds/kind/metadata/time violation |
| INPUT_TOO_LARGE | More than 8192 raw input bytes; digest unavailable |
| INPUT_READ_FAILED | Read did not finish successfully; no raw I/O diagnostics or digest |
| CANCELLED | Context or termination signal cancelled validation; digest unavailable |
| TIMEOUT | Reading/validation deadline expired; digest unavailable |

## Compatibility, fixtures and test discovery

Version 0 was an unpublished planning draft and has no automatic migration or live compatibility promise. Fixtures explicitly prove v0/missing/future versions are rejected. Historical C01–C03 fixtures/evidence retain their original meanings. Future kinds or metadata changes need an explicit compatible contract review and fixtures; they must not silently widen this decoder. C05 owns durable state, C07 identity/sequence generation and C12 metadata capture/redaction.

C04 fixture manifests record repository authorship and Apache-2.0 licensing under tests/fixtures/miragemesh/C04. That provenance also covers valid-event.txt, the exact raw wire input paired with the independent expected digest. No real sensor/traffic data is used.

`npm test` collects tests/contracts/*.test.mjs alongside the existing web tests. Tests run the built actual Go binary and execute both schemas using pinned development-only Ajv 8.20.0 and ajv-formats 3.0.1. `npm run test:contracts` builds that binary first. Go tests run with `go test ./...`; fuzz seeds and a bounded fuzz campaign cover hostile bytes. This is local validation proof, not the provider/durable workflow integration CI reserved for C06.

Official references: [Go JSON decoding and its default replacement/matching behavior](https://pkg.go.dev/encoding/json), [Go context](https://pkg.go.dev/context), [Ajv Draft 2020-12](https://ajv.js.org/json-schema.html#draft-2020-12), [format validation](https://ajv.js.org/guide/formats.html). The schemas are local resources; tests do not fetch remote schema references.

C22 adds the source-backed local `GET /api/v1/incidents` snapshot and implements the existing triage body contract over loopback. Its exact local Origin checks, response bounds, durable idempotency and limitations are documented in `docs/architecture/INCIDENT_REPLAY.md` and OpenAPI. Event admission and remote multi-user management remain unavailable.

C23 adds optional `retained_events` and `coverage.retention_gaps` to local incident snapshots. Retention summaries include segment identity, counts, hash, cutoff, decision time and reason. Any retention gaps mean incomplete coverage; this adds no HTTP deletion endpoint.
