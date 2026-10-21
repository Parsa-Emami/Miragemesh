# C09: mTLS collector identity guard

The owner-approved C09/F03 scope is an internal Go guard that authenticates
collector traffic against locally configured trust state: a set of
self-signed CA anchors, one listener certificate, a locally delivered signed
CRL and an operator-authored fingerprint-to-sensor-scope mapping. There is no
HTTP, CLI or UI surface in C09; the real ingest endpoint lands in C16 and the
engine owns all domain integration, UI work stays in `apps/web`, and adapters
sit at the boundaries per ADR-0003.

## Trusted in-process interface

```go
guard, err := pki.New(pki.Options{
    Anchors:              anchorPEMs,
    ServerCertificatePEM: listenerCertPEM,
    ServerKeyPEM:         listenerKeyPEM,
    RevocationListPEM:    crlPEM,
    Scopes:               map[string][]string{fingerprint: {"sensor-01"}},
    MaxAnchors:           maxAnchors,
    MaxScopes:            maxScopes,
    MaxScopesPerIdentity: maxScopesPerIdentity,
    Clock:                time.Now,
})
tlsConfig := guard.TLSConfig()
identity, err := guard.Authenticate(tlsConn)
identity, err := guard.Verify(state)
err := guard.Allows(state, sensorID)
```

`pki.New` fails closed on the first configuration anomaly and returns typed
errors; partial configurations never produce a guard. Anchor parsing is
strict: exactly one `CERTIFICATE` PEM block per anchor, a self-signed CA
certificate with certificate-signing and CRL-signing key usage. The listener
certificate must chain to the configured anchors for server authentication at
process start. Scopes are keyed by the lowercase hex SHA-256 fingerprint of a
certificate's DER bytes and every mapped sensor ID is validated with the C04
rules. A configuration without a revocation list is incomplete and rejected.

## Verdicts are typed and clock-authoritative

`ErrInvalidInput`, `ErrMissingIdentity`, `ErrUntrusted`, `ErrExpired`,
`ErrRevoked`, `ErrRevocationListInvalid`, `ErrRevocationListStale` and
`ErrScope` are the regimes a caller can assert against with
`errors.Is`. Verify requires a presented client certificate; the terminal
certificate of the verified chain must be one of the configured anchors and
the chain must be exactly `[leaf, anchor]` — the leaf must be issued directly
by that anchor, so client chains carrying intermediate CAs are rejected with
`ErrUntrusted` (RFC 5280 identifies a certificate by issuer and serial
number; the guard supports exactly one revocation authority — the locally
delivered CRL signed by a configured anchor — and cannot load intermediate
CRLs, therefore intermediate-issued collectors are structurally out of
scope and can never bypass revocation by presenting a chain that x509
itself labels as verified); the terminal anchor must be the configured
anchor that signed the guard's CRL, so leaves issued by any other configured
anchor fail closed with `ErrUntrusted`: the guard carries a single CRL and
authenticates only issuers it can revoke; the leaf validity window must
hold at the clock
(`ErrExpired` for both not-yet-valid and expired certificates); the CRL must
be fresh at the clock with `ErrRevocationListStale` after its NextUpdate
(passes) and `ErrRevocationListInvalid` before its ThisUpdate or for any
structure, type, numbering or signature failure; and every chain
certificate the CRL issuer itself issued must carry a serial absent from
the CRL (`ErrRevoked`) — matching is by issuer and serial, never by serial
alone. `Allows` performs the
identity verdict first and then enforces the operator's scope mapping with a
typed `ErrScope` before any ingest work.

This is the C09 restriction documented to reviewers as the smallest suitable
fix for RFC 5280 issuer-blind CRL matching ([RFC 5280 section 5](https://www.rfc-editor.org/rfc/rfc5280.html)):
the revocation authority is a single issuer, keyed by the fingerprint of the
anchor that signed the CRL, and the accepted client-issuer set equals that
authority's population. Anchors without CRL coverage remain in the trust
pool only for listener chain verification and future multi-CRL work
(C24); until an issuer's own CRL is delivered, the guard refuses to
authenticate anything that issuer signed rather than accepting a collector
whose revocation it could never enforce. Fail-closed chain shape plus
issuer-keyed membership keeps every accepted collector inside the one
revocation authority the guard can verify.

`New` validates the CRL against the construction clock — a stale list cannot
be configured — and `Verify` rechecks the same freshness window on every
verdict, so a list that expires while a guard is running fails closed.
The clock is trusted application configuration, never a field supplied by an
untrusted connection. Tests pass controlled clocks; production passes
`time.Now`. Wall-clock checks are UTC and reject zero/unrepresentable times.
Server certificate chain validation at `New` uses process start time, because
it is a stop-the-line deployment check; identity verdicts use the configured
guard clock.

## Transport policy

`TLSConfig` returns a fresh listener configuration on every call:
`RequireAndVerifyClientCert`, the local anchor pool as its only `ClientCAs`,
TLS 1.3 only, session tickets disabled, and `VerifyConnection` wired to the
same authoritative verdict. Go invokes `VerifyConnection` for every
connection, including resumed ones, so no accepted connection skips the
guard. `Authenticate` handshakes the connection first; handshake-level
transport failures are returned unchanged, while identity verdicts stay
typed. A certificate that becomes revoked between handshakes can no longer
authorize any later connection and cannot ingest events before the verdict
runs, because the verdict precedes the event decode and scope enforcement.

The intended engine flow is: authenticate → read one framed event → decode →
`Allows` (scope gate) → `sensor.Accept` (the C07 storage boundary). The guard
never reads storage state and has no dependency on storage or sensor
packages; it imports only the standard library and `internal/contracts`.

## What is not in C09

There is no certificate issuance, no key generation for operators, no OCSP or
other network revocation transport: revocation is a locally delivered,
locally signed RFC 5280 CRL verified against the configured anchors. There
is no owner/tenant model — the fingerprint mapping is the only trust binding.
C24 owns `internal/pki/rotate.go` for certificate recovery and rotation.
No database schema, migration, environment file, Dockerfile, dependency or
provider pin changes; the C07 event contract and receipts are unchanged.

## Verification and limits

`tests/mtls_test.go` uses real loopback TLS listeners and clients against the
actual filesystem-backed store: six anchors cover trusted acceptance with
durable receipts, transport denial for missing/untrusted/expired/wrong-EKU/
revoked and intermediate-issued chains with typed `ErrUntrusted`, typed
verdicts evaluated on captured real ConnectionState
transcripts (including a later revocation update of a previously trusted
identity and a scope mismatch rejected before side effects), the issuer
coverage contract on a real dual-anchor listener (secondary-issued collector
with a colliding revoked serial rejected as untrusted while the covered
primary-issued collector ingests and the primary-issued same-serial stays
revoked), the replay of a
revoked identity into a reconfigured listener, and 15 invalid configuration
fixture rows. The Go discovery guard requires the C09 anchors. A focused
syscall trace of the mTLS test binary must show loopback connections only; it
does not certify decoy isolation (C13), full-domain workflow, physical
power-loss recovery, remote Actions or C30/C40 usability. Exact commands and
observations belong to `docs/evidence/C09.json`.

Official standard-library sources:
[Configure a server to require and verify clients](https://pkg.go.dev/crypto/tls#Config.ClientAuth),
[VerifyConnection on every connection](https://pkg.go.dev/crypto/tls#Config.VerifyConnection),
[X509KeyPair](https://pkg.go.dev/crypto/tls#X509KeyPair),
[x509.ParseRevocationList](https://pkg.go.dev/crypto/x509#ParseRevocationList),
[RevocationList.CheckSignatureFrom](https://pkg.go.dev/crypto/x509#RevocationList.CheckSignatureFrom),
[Certificate.Verify](https://pkg.go.dev/crypto/x509#Certificate.Verify),
[RFC 5280 (X.509 PKI certificate and CRL profile)](https://www.rfc-editor.org/rfc/rfc5280.html).
Implementation is checked against the repository-locked Go 1.27.2 source.
