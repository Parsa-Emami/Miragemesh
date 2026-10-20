package tests

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// The C09 fixtures carry repository-authored synthetic collector identity
// material; event bytes come from the unchanged C07 positive fixture.
type c09Bounds struct {
	MaxAnchors           int `json:"max_anchors"`
	MaxScopes            int `json:"max_scopes"`
	MaxScopesPerIdentity int `json:"max_scopes_per_identity"`
}

type c09Anchor struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
}

type c09IdentityMaterial struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Serial      string `json:"serial"`
}

type c09Data struct {
	FixtureVersion int                            `json:"fixture_version"`
	License        string                         `json:"license"`
	Provenance     string                         `json:"provenance"`
	Now            string                         `json:"now"`
	Bounds         c09Bounds                      `json:"bounds"`
	SensorID       string                         `json:"sensor_id"`
	Scopes         map[string][]string            `json:"scopes"`
	Anchors        []c09Anchor                    `json:"anchors"`
	CollectorFP    string                         `json:"collector_fingerprint"`
	Identities     map[string]c09IdentityMaterial `json:"identities"`
	RevocationList string                         `json:"revocation_list"`
	CollectorCRL   string                         `json:"collector_revocation_list"`
	ExtendedCRL    string                         `json:"extended_revocation_list"`
	StaleCRL       string                         `json:"stale_revocation_list"`
	ForgedCRL      string                         `json:"forged_revocation_list"`
	Limits         storage.Limits                 `json:"limits"`
}

type c09Expected struct {
	FixtureVersion    int               `json:"fixture_version"`
	License           string            `json:"license"`
	Provenance        string            `json:"provenance"`
	AcceptedSequences []int             `json:"accepted_sequences"`
	ExpectedVerdicts  map[string]string `json:"expected_verdicts"`
}

type c09InvalidCase struct {
	Name              string              `json:"name"`
	Definition        string              `json:"definition"`
	Expected          string              `json:"expected"`
	Anchors           []string            `json:"anchors,omitempty"`
	ServerCertificate string              `json:"server_certificate,omitempty"`
	ServerKey         string              `json:"server_key,omitempty"`
	RevocationList    string              `json:"revocation_list,omitempty"`
	Scopes            map[string][]string `json:"scopes,omitempty"`
	Bounds            *c09Bounds          `json:"bounds,omitempty"`
	Clock             bool                `json:"clock"`
}

type c09Invalid struct {
	FixtureVersion int              `json:"fixture_version"`
	License        string           `json:"license"`
	Provenance     string           `json:"provenance"`
	GoodBounds     c09Bounds        `json:"good_bounds"`
	Cases          []c09InvalidCase `json:"cases"`
}

func c09Files(t *testing.T) (*c09Data, *c09Expected, []c09InvalidCase) {
	t.Helper()
	var f c09Data
	var e c09Expected
	var invalid c09Invalid
	load := func(path string, target any) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, target); err != nil || target == nil {
			t.Fatalf("malformed fixture %s: %v", path, err)
		}
	}
	load("fixtures/miragemesh/C09/positive.json", &f)
	load("fixtures/miragemesh/C09/expected-output.json", &e)
	load("fixtures/miragemesh/C09/invalid.json", &invalid)
	if f.FixtureVersion != 1 || e.FixtureVersion != 1 || invalid.FixtureVersion != 1 || f.License != "Apache-2.0" || e.License != "Apache-2.0" || invalid.License != "Apache-2.0" || f.Provenance == "" || e.Provenance == "" || invalid.Provenance == "" {
		t.Fatal("invalid C09 fixture metadata")
	}
	return &f, &e, invalid.Cases
}

func c09IdentityPEMs(t *testing.T, fixture *c09Data, name string) tls.Certificate {
	t.Helper()
	material, exists := fixture.Identities[name]
	if !exists || len(material.Certificate) == 0 || len(material.Key) == 0 {
		t.Fatalf("missing fixture identity %s", name)
	}
	cert, err := tls.X509KeyPair([]byte(material.Certificate), []byte(material.Key))
	if err != nil || len(cert.Certificate) != 1 {
		t.Fatalf("fixture identity %s: %v", name, err)
	}
	return cert
}

func c09Anchors(fixture *c09Data, names ...string) []string {
	var anchors []string
	for _, anchor := range fixture.Anchors {
		for _, name := range names {
			if anchor.Name == name {
				anchors = append(anchors, anchor.Certificate)
			}
		}
	}
	return anchors
}

func c09Options(t *testing.T, fixture *c09Data, mutate func(*pki.Options)) pki.Options {
	t.Helper()
	engine := fixture.Identities["engine"]
	options := pki.Options{
		Anchors:              c09Anchors(fixture, "primary"),
		ServerCertificatePEM: engine.Certificate,
		ServerKeyPEM:         engine.Key,
		RevocationListPEM:    fixture.RevocationList,
		Scopes:               fixture.Scopes,
		MaxAnchors:           fixture.Bounds.MaxAnchors,
		MaxScopes:            fixture.Bounds.MaxScopes,
		MaxScopesPerIdentity: fixture.Bounds.MaxScopesPerIdentity,
		Clock:                func() time.Time { return time.Now().UTC() },
	}
	if mutate != nil {
		mutate(&options)
	}
	return options
}

func c09FixedNow(fixture *c09Data) time.Time {
	parsed, err := time.Parse(time.RFC3339, fixture.Now)
	if err != nil {
		return time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	}
	return parsed
}

func c09Guard(t *testing.T, options pki.Options) *pki.Guard {
	t.Helper()
	guard, err := pki.New(options)
	if err != nil {
		t.Fatalf("guard construction: %v", err)
	}
	return guard
}

func c09ClientConfig(t *testing.T, fixture *c09Data, identityName string) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	for _, anchor := range fixture.Anchors {
		if !pool.AppendCertsFromPEM([]byte(anchor.Certificate)) {
			t.Fatalf("client rejected %s anchor", anchor.Name)
		}
	}
	config := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if identityName != "" {
		config.Certificates = []tls.Certificate{c09IdentityPEMs(t, fixture, identityName)}
	}
	return config
}

type c09Outcome struct {
	mu         sync.Mutex
	states     []tls.ConnectionState
	identities []pki.Identity
	failures   []error
	receipts   []storage.Receipt
}

func (o *c09Outcome) fail(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = append(o.failures, err)
}

func (o *c09Outcome) scene(state tls.ConnectionState, identity pki.Identity) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.states = append(o.states, state)
	o.identities = append(o.identities, identity)
}

func (o *c09Outcome) record(state tls.ConnectionState, receipt storage.Receipt) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.states = append(o.states, state)
	o.receipts = append(o.receipts, receipt)
}

func (o *c09Outcome) snapshot() ([]tls.ConnectionState, []pki.Identity, []error, []storage.Receipt) {
	o.mu.Lock()
	defer o.mu.Unlock()
	states := make([]tls.ConnectionState, len(o.states))
	copy(states, o.states)
	identities := make([]pki.Identity, len(o.identities))
	copy(identities, o.identities)
	failures := make([]error, len(o.failures))
	copy(failures, o.failures)
	receipts := make([]storage.Receipt, len(o.receipts))
	copy(receipts, o.receipts)
	return states, identities, failures, receipts
}

func c09ManifestDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// c09Listener runs one real loopback TLS listener. Each connection is
// authenticated through the guard; when event payloads are configured the
// boundary decodes them, enforces the scope mapping and only then accepts
// events through the real sensor/store pipeline.
func c09Listener(t *testing.T, guard *pki.Guard, events [][]byte, store *storage.Store) (string, *c09Outcome) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	outcome := &c09Outcome{}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := tls.Server(conn, guard.TLSConfig())
				if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					outcome.fail(err)
					return
				}
				identity, authErr := guard.Authenticate(tlsConn)
				if authErr != nil {
					outcome.fail(authErr)
					return
				}
				outcome.scene(tlsConn.ConnectionState(), identity)
				for _, event := range events {
					payload := make([]byte, len(event))
					if _, readErr := io.ReadFull(tlsConn, payload); readErr != nil {
						outcome.fail(readErr)
						return
					}
					decoded, decodeErr := contracts.DecodeEvent(context.Background(), payload)
					if decodeErr != nil {
						outcome.fail(decodeErr)
						return
					}
					if scopeErr := guard.Allows(tlsConn.ConnectionState(), decoded.SensorID); scopeErr != nil {
						outcome.fail(scopeErr)
						return
					}
					receipt, acceptErr := sensor.Accept(context.Background(), store, payload)
					if acceptErr != nil {
						outcome.fail(acceptErr)
						return
					}
					outcome.record(tlsConn.ConnectionState(), receipt)
				}
			}()
		}
	}()
	return listener.Addr().String(), outcome
}

func c09Wait(t *testing.T, outcome *c09Outcome, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			states, identities, failures, receipts := outcome.snapshot()
			t.Fatalf("timeout waiting for %s: states=%d identities=%d receipts=%d failures=%v",
				what, len(states), len(identities), len(receipts), failures)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// c09Dial performs one real TLS connection attempt. When payload is set the
// bytes are written after the handshake and the write half is closed so a
// server side ingest boundary observes one complete framed message.
func c09Dial(t *testing.T, address string, config *tls.Config, payload []byte) error {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	if payload != nil {
		if _, err := tlsConn.Write(payload); err != nil {
			return err
		}
		if err := tlsConn.CloseWrite(); err != nil {
			return err
		}
	}
	return nil
}

func c09SensorEvents(t *testing.T) [][]byte {
	t.Helper()
	events, _, _ := sensorEvents(t)
	return events
}

func TestMTLSTrustedCollectorAcceptsEvents(t *testing.T) {
	fixture, expected, _ := c09Files(t)
	guard := c09Guard(t, c09Options(t, fixture, nil))
	config := guard.TLSConfig()
	if config.ClientAuth != tls.RequireAndVerifyClientCert || !config.SessionTicketsDisabled || config.MinVersion != tls.VersionTLS13 {
		t.Fatalf("collector transport policy drifted: %+v", config)
	}
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	events := c09SensorEvents(t)
	address, outcome := c09Listener(t, guard, events[:1], store)
	if dialErr := c09Dial(t, address, c09ClientConfig(t, fixture, "collector"), events[0]); dialErr != nil {
		t.Fatalf("trusted collector handshake: %v", dialErr)
	}
	c09Wait(t, outcome, func() bool {
		_, identities, _, receipts := outcome.snapshot()
		return len(identities) == 1 && len(receipts) == 1
	}, "one accepted event")
	_, identities, _, receipts := outcome.snapshot()
	identity := identities[0]
	if identity.Fingerprint != fixture.CollectorFP || identity.SerialNumber != fixture.Identities["collector"].Serial {
		t.Fatalf("verified identity drifted: %+v", identity)
	}
	if len(identity.AllowedScopes) != 1 || identity.AllowedScopes[0] != fixture.SensorID {
		t.Fatalf("identity scopes drifted: %+v", identity)
	}
	if len(identity.AllowedScopes) > fixture.Bounds.MaxScopesPerIdentity {
		t.Fatalf("identity scopes exceeded bound: %+v", identity)
	}
	if receipts[0].Generation != 1 {
		t.Fatalf("first accepted event receipt: %+v", receipts[0])
	}
	sum := sha256.Sum256([]byte(fixture.SensorID))
	wantID := "sensor/" + hex.EncodeToString(sum[:]) + "/1"
	if followed, err := store.Read(context.Background(), wantID); err != nil || followed.Receipt.InputDigest != receipts[0].InputDigest {
		t.Fatalf("accepted event not durable: %v", err)
	}
	if verdict := expected.ExpectedVerdicts["collector"]; verdict != "IDENTITY_OK" {
		t.Fatalf("fixture verdict drift: %s", verdict)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMTLSRejectsUntrustedExpiredWrongEKUAndRevokedIdentity(t *testing.T) {
	fixture, expected, _ := c09Files(t)
	guard := c09Guard(t, c09Options(t, fixture, nil))
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	events := c09SensorEvents(t)
	before := c09ManifestDigest(t, path)
	for _, name := range []string{"", "untrusted", "expired", "server_only", "revoked"} {
		address, outcome := c09Listener(t, guard, events[:1], store)
		c09Dial(t, address, c09ClientConfig(t, fixture, name), events[0])
		label := name
		if label == "" {
			label = "missing"
		}
		// In TLS 1.3 the client handshake finishes before the server has
		// examined the client certificate; the authoritative rejection is
		// therefore observed on the listener side.
		c09Wait(t, outcome, func() bool {
			_, _, failures, receipts := outcome.snapshot()
			return len(failures) >= 1 && len(receipts) == 0
		}, fmt.Sprintf("%s transport denial", label))
		_, _, _, receipts := outcome.snapshot()
		if len(receipts) != 0 {
			t.Fatalf("%s identity produced receipts: %+v", label, receipts)
		}
		if after := c09ManifestDigest(t, path); after != before {
			t.Fatalf("%s identity changed durable state", label)
		}
	}
	if expected.ExpectedVerdicts["revoked"] != "IDENTITY_REVOKED" {
		t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["revoked"])
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMTLSTypedVerdictsUseRealHandshakeTranscripts(t *testing.T) {
	fixture, expected, _ := c09Files(t)
	deployed := c09Guard(t, c09Options(t, fixture, nil))
	events := c09SensorEvents(t)
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	before := c09ManifestDigest(t, path)

	// Capture real transcripts: the trusted collector under the deployed
	// guard and the CA2-scoped collector under a real dual-anchor listener.
	captureAddress, capture := c09Listener(t, deployed, nil, nil)
	if dialErr := c09Dial(t, captureAddress, c09ClientConfig(t, fixture, "collector"), nil); dialErr != nil {
		t.Fatal("trusted capture dial failed")
	}
	c09Wait(t, capture, func() bool {
		states, _, _, _ := capture.snapshot()
		return len(states) == 1
	}, "trusted capture")
	states, _, _, _ := capture.snapshot()
	trustedState := states[0]

	dualGuard := c09Guard(t, c09Options(t, fixture, func(options *pki.Options) {
		options.Anchors = c09Anchors(fixture, "primary", "secondary")
		options.RevocationListPEM = fixture.RevocationList
		options.Scopes = fixture.Scopes
	}))
	dualAddress, dualCapture := c09Listener(t, dualGuard, nil, nil)
	if dialErr := c09Dial(t, dualAddress, c09ClientConfig(t, fixture, "untrusted"), nil); dialErr != nil {
		t.Fatal("untrusted capture dial failed")
	}
	c09Wait(t, dualCapture, func() bool {
		states, _, _, _ := dualCapture.snapshot()
		return len(states) == 1
	}, "untrusted capture")
	dualStates, _, _, _ := dualCapture.snapshot()
	untrustedState := dualStates[0]

	if _, err := deployed.Verify(untrustedState); !errors.Is(err, pki.ErrUntrusted) {
		t.Fatalf("CA2 chain passed under deployed guard: %v", err)
	}
	if expected.ExpectedVerdicts["untrusted"] != "IDENTITY_UNTRUSTED" {
		t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["untrusted"])
	}
	future := c09Guard(t, c09Options(t, fixture, func(options *pki.Options) {
		options.Clock = func() time.Time { return c09FixedNow(fixture).AddDate(26, 0, 0) }
		options.RevocationListPEM = fixture.ExtendedCRL
	}))
	if _, err := future.Verify(trustedState); !errors.Is(err, pki.ErrExpired) {
		t.Fatalf("future clock accepted transcript: %v", err)
	}
	if expected.ExpectedVerdicts["expired"] != "IDENTITY_EXPIRED" {
		t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["expired"])
	}
	revoking := c09Guard(t, c09Options(t, fixture, func(options *pki.Options) {
		options.RevocationListPEM = fixture.CollectorCRL
	}))
	if _, err := revoking.Verify(trustedState); !errors.Is(err, pki.ErrRevoked) {
		t.Fatalf("revocation re-evaluation accepted transcript: %v", err)
	}
	if expected.ExpectedVerdicts["revoked"] != "IDENTITY_REVOKED" {
		t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["revoked"])
	}
	if err := deployed.Allows(trustedState, "sensor-02"); !errors.Is(err, pki.ErrScope) {
		t.Fatalf("unrelated sensor scope allowed: %v", err)
	}
	if err := deployed.Allows(trustedState, fixture.SensorID); err != nil {
		t.Fatalf("bound sensor scope denied: %v", err)
	}
	if expected.ExpectedVerdicts["scope_mismatch"] != "IDENTITY_SCOPE" {
		t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["scope_mismatch"])
	}

	// The ingest boundary itself must fail on an unrelated sensor scope before
	// any storage side effect with a real collector connection.
	address, boundary := c09Listener(t, deployed, events[3:4], store)
	if dialErr := c09Dial(t, address, c09ClientConfig(t, fixture, "collector"), events[3]); dialErr != nil {
		t.Fatalf("scope probe handshake: %v", dialErr)
	}
	c09Wait(t, boundary, func() bool {
		_, _, failures, receipts := boundary.snapshot()
		return len(failures) >= 1 && len(receipts) == 0
	}, "scope denial before ingest")
	_, _, failures, _ := boundary.snapshot()
	found := false
	for _, failure := range failures {
		if errors.Is(failure, pki.ErrScope) {
			found = true
		}
	}
	if !found {
		t.Fatalf("scope denial was not typed: %v", failures)
	}
	if after := c09ManifestDigest(t, path); after != before {
		t.Fatalf("scope denial changed durable state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects proves a
// collector whose certificate is revoked between handshakes cannot ingest
// events afterwards: a new real listener with the updated revocation state
// rejects the replayed identity before the ingest boundary can run.
func TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects(t *testing.T) {
	fixture, _, _ := c09Files(t)
	guard := c09Guard(t, c09Options(t, fixture, func(options *pki.Options) {
		options.RevocationListPEM = fixture.CollectorCRL
	}))
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	events := c09SensorEvents(t)
	before := c09ManifestDigest(t, path)
	address, outcome := c09Listener(t, guard, events[:1], store)
	// In TLS 1.3 the client handshake finishes before the server examines
	// the replayed client certificate; the authoritative rejection is
	// therefore observed on the listener side.
	c09Dial(t, address, c09ClientConfig(t, fixture, "collector"), events[0])
	c09Wait(t, outcome, func() bool {
		_, _, failures, receipts := outcome.snapshot()
		return len(failures) >= 1 && len(receipts) == 0
	}, "replayed identity denial")
	_, _, failures, _ := outcome.snapshot()
	typed := false
	for _, failure := range failures {
		if errors.Is(failure, pki.ErrRevoked) {
			typed = true
		}
	}
	if !typed {
		t.Fatalf("replayed identity denial was not typed: %v", failures)
	}
	if after := c09ManifestDigest(t, path); after != before {
		t.Fatalf("replayed identity changed durable state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMTLSRejectsInvalidLocalIdentityConfigurations(t *testing.T) {
	fixture, expected, cases := c09Files(t)
	if len(cases) != 15 {
		t.Fatalf("fixture rows drifted: %d", len(cases))
	}
	verdicts := map[string]error{
		"CONFIGURATION_INVALID":   pki.ErrInvalidInput,
		"REVOCATION_LIST_INVALID": pki.ErrRevocationListInvalid,
		"REVOCATION_LIST_STALE":   pki.ErrRevocationListStale,
	}
	for _, c := range cases {
		want, known := verdicts[c.Expected]
		if !known {
			t.Fatalf("unknown expected verdict %s", c.Expected)
		}
		bounds := fixture.Bounds
		if c.Bounds != nil {
			bounds = *c.Bounds
		}
		clock := func() time.Time { return time.Now().UTC() }
		if !c.Clock {
			clock = nil
		}
		options := pki.Options{
			Anchors:              c.Anchors,
			ServerCertificatePEM: c.ServerCertificate,
			ServerKeyPEM:         c.ServerKey,
			RevocationListPEM:    c.RevocationList,
			Scopes:               c.Scopes,
			MaxAnchors:           bounds.MaxAnchors,
			MaxScopes:            bounds.MaxScopes,
			MaxScopesPerIdentity: bounds.MaxScopesPerIdentity,
			Clock:                clock,
		}
		guard, err := pki.New(options)
		if !errors.Is(err, want) {
			t.Fatalf("row %s: %v, want %v", c.Name, err, want)
		}
		if guard != nil {
			t.Fatalf("row %s constructed a guard", c.Name)
		}
		switch c.Name {
		case "forged_revocation_list":
			if expected.ExpectedVerdicts["forged_crl"] != "REVOCATION_LIST_INVALID" {
				t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["forged_crl"])
			}
		case "stale_revocation_list":
			if expected.ExpectedVerdicts["stale_crl"] != "REVOCATION_LIST_STALE" {
				t.Fatalf("fixture verdict drift: %s", expected.ExpectedVerdicts["stale_crl"])
			}
		}
	}
}
