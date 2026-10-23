# Sensor certificate rotation (C24)

C24 rotates sensor client leaf certificates under the existing directly issuing C09 authority. The old and new credentials have an explicit overlap deadline; the old credential is rejected at that instant, including after restart. An offline sensor can recover with a fresh signed CSR and a short-lived, sensor-scoped C08 enrollment token. Recovery immediately replaces the current credential and atomically claims its token.

This extends the existing C09 mTLS guard. Use `pki.Options.Rotation` when constructing the guard; the configured rotation ledger takes precedence over static scopes for every managed fingerprint. An unavailable or corrupt ledger fails authentication closed. Unmanaged C09 identities retain their existing scope behavior. CA migration, listener-certificate rotation, remote enrollment/ingest and the full C30 workflow remain separate work.

## Boundaries

| Component | Responsibility |
| --- | --- |
| `internal/pki/rotate.go` | Certificate policy, CSR proof, revision state machine, overlap and recovery rules, signed certificate issuance and owned status snapshots |
| `crypto.Signer` argument | Trusted issuer signing operation, supplied only for a new local issuance; no private key is retained by the rotator |
| `internal/contracts/rotation.go` | Bounded canonical version 1 internal envelopes and stable request digests |
| Existing C05 `Store.Update` | Serialize against the complete durable history, publish one record and acknowledge only after the existing file/manifest/directory flush protocol |
| Existing C08 enrollment | Issue a random scoped token; both ordinary consumption and certificate recovery honor the same atomic claim |
| C09 `Guard` | Enforce chain, expiry and locally signed CRL checks before applying current rotation authorization on every new handshake and `Allows` call |
| Operator CLI | Register existing identities, rotate, provision a private recovery-token file, recover and inspect status |
| Read-only HTTP and web | Show actual revisions, fingerprints, expiry, overlap deadlines and available recovery; no signing keys, CSRs, tokens or certificate mutation endpoints |

`NewRotator(ctx, store, options)` needs a public self-signed issuing CA, a trusted clock, explicit maximum sensor count, certificate lifetime, overlap and recovery-token TTL. The issuer must have certificate-signing and CRL-signing usage. Durations use whole seconds; the maximum overlap is shorter than the maximum certificate lifetime. The reader does not require a signing key.

`Register` is a trusted local operator action that binds an already issued valid client certificate to exactly one sensor. `Rotate` and `Recover` require an expected revision, a stable idempotency key and a CSR whose signature proves possession of its private key. The CSR has only a common name equal to the opaque sensor ID; SANs and extra extensions are rejected. The issuer builds a fixed non-CA, digital-signature, client-authentication certificate and never copies requested privilege extensions. Supported subject keys are Ed25519, P-256/P-384/P-521 and RSA 2048–4096. The signing public key must match the configured CA. Serial numbers and subject public keys cannot be reused in the ledger.

The Go implementation checks the CSR using [CertificateRequest.CheckSignature](https://pkg.go.dev/crypto/x509#CertificateRequest.CheckSignature), issues using [CreateCertificate](https://pkg.go.dev/crypto/x509#CreateCertificate) and configures [TLS VerifyConnection](https://pkg.go.dev/crypto/tls#Config) for authoritative policy checks. Managed guards use the same configured clock for TLS certificate checks; session tickets remain disabled. No external OCSP, CRL, AIA, network fetch or process execution is added.

## Overlap and authorization

After registration the first fingerprint is current. Rotation increments the revision and activates the new fingerprint immediately. The previous fingerprint remains authorized only while `now < overlap_until`. The deadline cannot exceed the old certificate's validity and must precede the new certificate's expiry. At most two fingerprints are eligible at one time; an ordinary second rotation during overlap is rejected. Older generations remain retired permanently in the retained history. A changed key, sequence/revision or request body cannot revive one.

`Guard.Verify` and `Guard.Allows` read the current durable policy; an already captured connection state is rejected after its old identity retires. Applications must call `Allows` before each protected action, as in the existing C09 ingest test boundary. This is per-action authorization and new-handshake enforcement, not a background process that forcibly closes every existing socket at the cutoff. The local HTTP status server is not an authenticated collector ingest listener.

An exact idempotency key and canonical intent replay the original public certificate, deadline and C05 receipt without signing again, even after the token or returned certificate expires. Replay never extends validity. A changed intent with the same key is `ErrRotationConflict`. A new issuance requires the current revision; stale intent is rejected. Public snapshots are rebuilt from the bounded C05 history and own their returned slices. A closed, poisoned, over-quota or semantically forged history never becomes an empty successful status.

## Offline recovery and one atomic publication

Recovery is available after a previous overlap has ended or the registered current certificate has expired. It does not accept the retired certificate as a recovery credential.

1. The local operator checks the sensor identity and provisions a fresh, short-lived C08 token scoped to it.
2. The sensor creates a new private key locally and supplies only its signed CSR through the operator's trusted transfer process.
3. `Recover` validates the token's original issue record, exact scope, expiry, unused state, configured TTL limit and expected revision while holding the C05 writer transaction.
4. The issuer signs the replacement; cancellation, validity and token expiry are checked again after signing and before publication.
5. One `certificate.recover` record commits the new certificate and the token claim together. Ordinary C08 `Consume` recognizes this claim; a concurrent consume and recovery cannot both succeed.

A failure before manifest publication leaves both the old current revision and the token claim unchanged. A published recovery survives restart with both facts present. A lost reply replays the exact committed certificate and receipt. C05 uncertainty poisons the live writer and authentication/status fails closed until recovery. There is no two-transaction gap between consuming the token and publishing the certificate.

## Local operator commands

Stop the supervisor before mutating its C05 directory. The store lock rejects a concurrent operator writer. Supply actual deployment quotas and policy; these small values are a synthetic example:

```sh
args=(--rotate-certificates
  --rotation-state-dir /absolute/private/state
  --rotation-issuer-file /absolute/private/issuer.pem
  --rotation-max-operations 128
  --rotation-max-bytes 2097152
  --rotation-max-manifest-bytes 131072
  --rotation-max-sensors 16
  --rotation-max-lifetime-seconds 86400
  --rotation-max-overlap-seconds 3600
  --rotation-max-recovery-ttl-seconds 900)

dist/engine/miragemesh "${args[@]}" --rotation-action register \
  --rotation-sensor sensor-24 --rotation-certificate-file /absolute/private/client.pem \
  --rotation-idempotency-key operator-register-sensor-24

dist/engine/miragemesh "${args[@]}" --rotation-action rotate \
  --rotation-sensor sensor-24 --rotation-expected-revision 1 \
  --rotation-csr-file /absolute/private/new-client.csr \
  --rotation-key-file /absolute/private/issuer-key.pem \
  --rotation-lifetime-seconds 86400 --rotation-overlap-seconds 3600 \
  --rotation-idempotency-key operator-rotate-sensor-24

dist/engine/miragemesh "${args[@]}" --rotation-action status

dist/engine/miragemesh "${args[@]}" --rotation-action issue-token \
  --rotation-sensor sensor-24 --rotation-token-ttl-seconds 600 \
  --rotation-token-file /absolute/private/recovery-token

dist/engine/miragemesh "${args[@]}" --rotation-action recover \
  --rotation-sensor sensor-24 --rotation-expected-revision 2 \
  --rotation-csr-file /absolute/private/recovery-client.csr \
  --rotation-key-file /absolute/private/issuer-key.pem \
  --rotation-token-file /absolute/private/recovery-token \
  --rotation-lifetime-seconds 86400 --rotation-idempotency-key operator-recover-sensor-24
```

`register` can create the private C05 directory; the other actions require an existing store. Input files are bounded regular files, with no symlinks, multiple hard links or group/other write access. Secret signing-key and token files must belong to the current operator and have no group/other permissions. Signing keys use unencrypted PKCS8 `PRIVATE KEY` PEM; the CLI does not generate or print private keys. Public certificate results go to stdout as JSON. Install the returned certificate on the sensor with the matching locally retained key using its existing provisioning process.

`issue-token` creates a new `0600` file exclusively in an operator-owned `0700` directory, syncs it and its directory, and never prints the token. It never overwrites a file. Token issue itself is intentionally not an idempotent certificate action: if a crash or I/O error prevents delivery of its file, the unreachable issued token expires. Provision a fresh token to a new private path; no certificate was changed by token issue. Do not treat an uncertain or partial output file as a completed delivery.

`register`, `rotate` and `recover` require 16–128 character idempotency keys; only their hash is stored. Only action-relevant flags are accepted. Missing or malformed configuration exits 2, runtime conflicts, locks, signer and recovery failures exit 1, success exits 0. JSON `error_kind` is explicit and never includes private key bytes or host paths. Exact issuance replay can be retrieved through the Go service without the issuer signer; the CLI also permits omitting the signing-key flag when recovering an existing idempotent result.

## Read-only web status

The supervisor forwards the following complete configuration to enable `GET /api/v1/certificates` and the Certificates page:

```sh
npm start -- --rotation-state-dir /absolute/private/state \
  --rotation-issuer-file /absolute/private/issuer.pem \
  --rotation-max-operations 128 --rotation-max-bytes 2097152 \
  --rotation-max-manifest-bytes 131072 --rotation-max-sensors 16 \
  --rotation-max-lifetime-seconds 86400 --rotation-max-overlap-seconds 3600 \
  --rotation-max-recovery-ttl-seconds 900
```

Direct engine startup uses `--certificate-status` plus those same policy flags. Sensor, incident and certificate views can share one store only with identical absolute directory and C05 quotas. Status requires the public issuer only; operator signing and recovery-token flags are rejected in HTTP mode. Host and optional Origin must match the loopback listener; mutation methods are rejected. Disabled/unavailable status returns a typed 503 rather than an empty list. The proxy rejects redirects, malformed and oversized responses. The existing response limit is 1 MiB, with explicit failure instead of truncation.

The UI reports the server-observed time, exact fingerprints, revision, validity and old-credential cutoff. Refresh errors retain an explicitly stale snapshot. Keyboard-accessible details, inert identifiers and the 360px layout are tested. Browser validation preserves RFC3339 nanosecond precision at the overlap boundary. Lifecycle status does not certify CRL freshness or a live connection.

## Evidence, limits and rollback

The audit stores public certificate/CSR DER, issuer and prior fingerprint, revision, policy times and hashed request/key/token identifiers. It stores no private keys or raw tokens. Sensor event sequencing and segment projection skip these internal records; event bytes, incident labels and retention decisions remain unchanged. No schema, migration, `.env`, Dockerfile, external dependency or mandatory cloud provider is added.

Tests use synthetic Apache-2.0 fixtures with ephemeral signing material, real TLS 1.3 handshakes, the before/exact/after cutoff, transcript reauthorization, restart, scoped/expired/consumed tokens, concurrent issuance and cross-service token consumption, forged history, quotas, signer delay/cancellation, five SIGKILL publication boundaries and nine syscall faults. CLI and real supervisor/browser tests cover recovery and restart. Full provider-dependent regression execution belongs to the unchanged hosted CI prerequisites; target capacity is unmeasured until C28.

This is one trusted local operator, one issuing authority and a bounded append-only C05 history. It relies on an authoritative wall clock and the latest accepted store, rather than an independent anti-rollback clock or checkpoint. Retain that complete store and a compatible C24 reader when backing up or changing versions. Old readers reject the new internal record kinds; do not overwrite newer accepted state with an older backup. Full power-loss, restore and C30/C40 workflow/release proof remain separate gates.
