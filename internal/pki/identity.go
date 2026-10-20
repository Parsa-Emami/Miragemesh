// Package pki authenticates collector traffic against locally configured
// certificate authorities, a locally delivered signed revocation list and
// per-identity sensor scope mappings. The guard fails closed on every
// configuration or transport anomaly and never consults external services.
package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

var (
	ErrInvalidInput          = errors.New("pki: local identity configuration is invalid")
	ErrMissingIdentity       = errors.New("pki: connection presented no client certificate")
	ErrUntrusted             = errors.New("pki: certificate chain is not anchored to a configured authority")
	ErrExpired               = errors.New("pki: certificate validity window failed")
	ErrRevoked               = errors.New("pki: certificate is revoked by the configured list")
	ErrRevocationListInvalid = errors.New("pki: revocation list failed validation")
	ErrRevocationListStale   = errors.New("pki: revocation list is stale")
	ErrScope                 = errors.New("pki: sensor scope is not assigned to the identity")
)

// Options describes the complete self-contained local identity
// configuration. Anchor and scope mappings are operator-authored local
// state keyed by the SHA-256 fingerprint of the certificate DER bytes; the
// revocation list is a signed RFC 5280 CRL delivered locally, verified
// against the configured anchors and rechecked against the authoritative
// clock on every verdict.
type Options struct {
	Anchors              []string
	ServerCertificatePEM string
	ServerKeyPEM         string
	RevocationListPEM    string
	Scopes               map[string][]string
	MaxAnchors           int
	MaxScopes            int
	MaxScopesPerIdentity int
	Clock                func() time.Time
}

// Identity is the verdict about one connection: the fingerprint of the
// presented leaf certificate, its serial number and the sensor scopes the
// operator assigned to that fingerprint.
type Identity struct {
	Fingerprint   string
	SerialNumber  string
	AllowedScopes []string
}

// Guard authenticates collector connections against the configured local
// trust state. Guard values are immutable after New; TLSConfig shares the
// immutable certificate pool with every generated listener configuration.
type Guard struct {
	clock   func() time.Time
	pool    *x509.CertPool
	anchors map[string]*x509.Certificate
	server  tls.Certificate
	crl     *x509.RevocationList
	revoked map[string]bool
	scopes  map[string][]string
}

// New validates the complete local identity configuration and fails closed
// on the first anomaly. Anchor parsing is strict: the PEM must be exactly
// one self-signed CA certificate with certificate-signing and CRL-signing
// key usage. The listener certificate must chain to the configured anchors
// for server authentication at process start; identity verdicts are then
// re-evaluated on every connection against the authoritative clock.
func New(options Options) (*Guard, error) {
	if options.Clock == nil {
		return nil, ErrInvalidInput
	}
	now := options.Clock()
	if now.IsZero() || now.Year() < 1000 {
		return nil, ErrInvalidInput
	}
	if options.MaxAnchors <= 0 || options.MaxScopes <= 0 || options.MaxScopesPerIdentity <= 0 {
		return nil, ErrInvalidInput
	}
	if len(options.Anchors) == 0 || len(options.Anchors) > options.MaxAnchors {
		return nil, ErrInvalidInput
	}
	anchors := make(map[string]*x509.Certificate, len(options.Anchors))
	pool := x509.NewCertPool()
	for _, anchorPEM := range options.Anchors {
		cert, err := parseCertificatePEM(anchorPEM)
		if err != nil {
			return nil, ErrInvalidInput
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, ErrInvalidInput
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
			return nil, ErrInvalidInput
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, ErrInvalidInput
		}
		fingerprint := fingerprintOf(cert.Raw)
		if _, duplicate := anchors[fingerprint]; duplicate {
			return nil, ErrInvalidInput
		}
		anchors[fingerprint] = cert
		pool.AddCert(cert)
	}
	if options.ServerCertificatePEM == "" || options.ServerKeyPEM == "" {
		return nil, ErrInvalidInput
	}
	server, err := tls.X509KeyPair([]byte(options.ServerCertificatePEM), []byte(options.ServerKeyPEM))
	if err != nil || len(server.Certificate) == 0 {
		return nil, ErrInvalidInput
	}
	serverLeaf, err := x509.ParseCertificate(server.Certificate[0])
	if err != nil {
		return nil, ErrInvalidInput
	}
	if _, err := serverLeaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, ErrInvalidInput
	}
	if len(options.Scopes) > options.MaxScopes {
		return nil, ErrInvalidInput
	}
	scopes := make(map[string][]string, len(options.Scopes))
	for fingerprint, list := range options.Scopes {
		if !validFingerprint(fingerprint) {
			return nil, ErrInvalidInput
		}
		if len(list) > options.MaxScopesPerIdentity {
			return nil, ErrInvalidInput
		}
		seen := make(map[string]bool, len(list))
		scopes[fingerprint] = make([]string, 0, len(list))
		for _, sensorID := range list {
			if !contracts.ValidSensorID(sensorID) || seen[sensorID] {
				return nil, ErrInvalidInput
			}
			seen[sensorID] = true
			scopes[fingerprint] = append(scopes[fingerprint], sensorID)
		}
	}
	if options.RevocationListPEM == "" {
		return nil, ErrInvalidInput
	}
	block, rest := pem.Decode([]byte(options.RevocationListPEM))
	if block == nil || block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrRevocationListInvalid
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, ErrRevocationListInvalid
	}
	verified := false
	for _, candidate := range anchors {
		if bytes.Equal(candidate.RawSubject, crl.RawIssuer) && crl.CheckSignatureFrom(candidate) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrRevocationListInvalid
	}
	if crl.Number == nil {
		return nil, ErrRevocationListInvalid
	}
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || crl.ThisUpdate.After(crl.NextUpdate) {
		return nil, ErrRevocationListInvalid
	}
	if now.After(crl.NextUpdate) {
		return nil, ErrRevocationListStale
	}
	if now.Before(crl.ThisUpdate) {
		return nil, ErrRevocationListInvalid
	}
	revoked := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			return nil, ErrRevocationListInvalid
		}
		revoked[serialText(entry.SerialNumber)] = true
	}
	return &Guard{
		clock:   options.Clock,
		pool:    pool,
		anchors: anchors,
		server:  server,
		crl:     crl,
		revoked: revoked,
		scopes:  scopes,
	}, nil
}

// TLSConfig builds a fresh listener configuration with mandatory and
// verified client certificates, TLS 1.3 only and no session reuse: every
// connection re-runs the authoritative verdict through VerifyConnection.
func (g *Guard) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates:           []tls.Certificate{g.server},
		ClientCAs:              g.pool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := g.Verify(state)
			return err
		},
	}
}

// Authenticate handshakes one connection and returns its authoritative
// identity verdict. Handshake level transport failures are returned
// unchanged; identity verdicts are typed errors.
func (g *Guard) Authenticate(conn *tls.Conn) (Identity, error) {
	if conn == nil {
		return Identity{}, ErrMissingIdentity
	}
	if err := conn.Handshake(); err != nil {
		return Identity{}, err
	}
	return g.Verify(conn.ConnectionState())
}

// Verify re-evaluates one captured or live TLS handshake state against the
// local trust state and the authoritative clock. The terminal certificate
// must be one of the configured anchors, the leaf validity window must
// hold, the revocation list must be fresh and the presented chain must not
// contain a revoked serial number. States observed through VerifyConnection
// during a TLS 1.3 handshake are accepted: the transport gate already
// guarantees the chain was produced by this guard's listeners.
func (g *Guard) Verify(state tls.ConnectionState) (Identity, error) {
	now := g.clock()
	if now.IsZero() || now.Year() < 1000 {
		return Identity{}, ErrInvalidInput
	}
	if len(state.PeerCertificates) == 0 {
		return Identity{}, ErrMissingIdentity
	}
	if len(state.VerifiedChains) == 0 {
		return Identity{}, ErrUntrusted
	}
	chain := state.VerifiedChains[0]
	terminal := chain[len(chain)-1]
	if _, anchored := g.anchors[fingerprintOf(terminal.Raw)]; !anchored {
		return Identity{}, ErrUntrusted
	}
	leaf := chain[0]
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return Identity{}, ErrExpired
	}
	if now.After(g.crl.NextUpdate) {
		return Identity{}, ErrRevocationListStale
	}
	if now.Before(g.crl.ThisUpdate) {
		return Identity{}, ErrRevocationListInvalid
	}
	for _, cert := range chain {
		if g.revoked[serialText(cert.SerialNumber)] {
			return Identity{}, ErrRevoked
		}
	}
	list := g.scopes[fingerprintOf(leaf.Raw)]
	allowed := make([]string, len(list))
	copy(allowed, list)
	return Identity{
		Fingerprint:   fingerprintOf(leaf.Raw),
		SerialNumber:  serialText(leaf.SerialNumber),
		AllowedScopes: allowed,
	}, nil
}

// Allows authenticates the transcript state first and then enforces the
// operator's fingerprint to sensor scope mapping. Without a valid identity
// it returns the typed verdict of Verify; with one it returns ErrScope when
// the sensor is not assigned to the identity.
func (g *Guard) Allows(state tls.ConnectionState, sensorID string) error {
	identity, err := g.Verify(state)
	if err != nil {
		return err
	}
	for _, scope := range identity.AllowedScopes {
		if scope == sensorID {
			return nil
		}
	}
	return ErrScope
}

// parseCertificatePEM accepts exactly one CERTIFICATE PEM block containing
// a parseable certificate.
func parseCertificatePEM(text string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("pki: malformed certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// fingerprintOf is the operator mapping key: SHA-256 over the certificate
// DER bytes, hex encoded.
func fingerprintOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validFingerprint(candidate string) bool {
	if len(candidate) != 64 {
		return false
	}
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func serialText(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return serial.Text(10)
}
