package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
)

// The C10 fixtures carry repository-authored synthetic desired-state
// documents. No key material is committed: every test creates one ephemeral
// in-memory Ed25519 key pair and never writes it to the filesystem.
type c10Limits struct {
	MaxPayloadBytes int `json:"max_payload_bytes"`
	MaxSensors      int `json:"max_sensors"`
}

type c10Range struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type c10Bounds struct {
	HeartbeatSeconds c10Range `json:"heartbeat_seconds"`
	SpoolLimitEvents c10Range `json:"spool_limit_events"`
	EventBatchLimit  c10Range `json:"event_batch_limit"`
}

type c10Positive struct {
	FixtureVersion   int               `json:"fixture_version"`
	License          string            `json:"license"`
	Provenance       string            `json:"provenance"`
	BoundsProvenance string            `json:"bounds_provenance"`
	Now              string            `json:"now"`
	SensorID         string            `json:"sensor_id"`
	Limits           c10Limits         `json:"limits"`
	Bounds           c10Bounds         `json:"bounds"`
	TightBounds      c10Bounds         `json:"tight_bounds"`
	WideBounds       c10Bounds         `json:"wide_bounds"`
	WidePayload      string            `json:"wide_payload"`
	Payloads         map[string]string `json:"payloads"`
	Expected         struct {
		InitialRevision int64           `json:"initial_revision"`
		NextRevision    int64           `json:"next_revision"`
		SensorID        string          `json:"sensor_id"`
		Settings        config.Settings `json:"settings"`
	} `json:"expected"`
}

type c10Case struct {
	Name          string `json:"name"`
	Definition    string `json:"definition"`
	Mode          string `json:"mode"`
	Build         string `json:"build"`
	Payload       string `json:"payload"`
	SignedPayload string `json:"signed_payload"`
	Expected      string `json:"expected"`
}

type c10Invalid struct {
	FixtureVersion int       `json:"fixture_version"`
	License        string    `json:"license"`
	Provenance     string    `json:"provenance"`
	Cases          []c10Case `json:"cases"`
}

type c10Expected struct {
	FixtureVersion   int               `json:"fixture_version"`
	License          string            `json:"license"`
	Provenance       string            `json:"provenance"`
	ExpectedVerdicts map[string]string `json:"expected_verdicts"`
	ExpectedActive   struct {
		SensorID string `json:"sensor_id"`
		Revision int64  `json:"revision"`
	} `json:"expected_active"`
	ExpectedSettings config.Settings `json:"expected_settings"`
}

func c10Files(t *testing.T) (*c10Positive, *c10Invalid, *c10Expected) {
	t.Helper()
	var positive c10Positive
	var invalid c10Invalid
	var expected c10Expected
	load := func(path string, target any) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, target); err != nil {
			t.Fatalf("malformed fixture %s: %v", path, err)
		}
	}
	load("fixtures/miragemesh/C10/positive.json", &positive)
	load("fixtures/miragemesh/C10/invalid.json", &invalid)
	load("fixtures/miragemesh/C10/expected-output.json", &expected)
	if positive.FixtureVersion != 1 || invalid.FixtureVersion != 1 || expected.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || invalid.License != "Apache-2.0" || expected.License != "Apache-2.0" ||
		positive.Provenance == "" || invalid.Provenance == "" || expected.Provenance == "" {
		t.Fatal("invalid C10 fixture metadata")
	}
	if positive.Limits.MaxPayloadBytes != 8192 || positive.Limits.MaxSensors <= 0 {
		t.Fatalf("unexpected C10 limits: %+v", positive.Limits)
	}
	if positive.BoundsProvenance == "" {
		t.Fatal("the C10 fixture does not record the provenance of the proposed bounds")
	}
	if len(positive.Payloads) != 2 || positive.Payloads["initial"] == "" || positive.Payloads["next"] == "" {
		t.Fatal("C10 positive fixture is missing a desired-state document")
	}
	return &positive, &invalid, &expected
}

func c10CaseByName(t *testing.T, invalid *c10Invalid, name string) c10Case {
	t.Helper()
	for _, testCase := range invalid.Cases {
		if testCase.Name == name {
			return testCase
		}
	}
	t.Fatalf("missing C10 case %s", name)
	return c10Case{}
}

// c10Key creates one ephemeral signing key pair. The private key stays in
// memory for the lifetime of the test and is never persisted.
func c10Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

// c10Verifier builds the trusted local configuration of one deployment from
// the fixture. The accepted range of every setting is explicit deployment
// policy: the engine ships no product limit of its own.
func c10Verifier(t *testing.T, fixture *c10Positive, public ed25519.PublicKey, bounds c10Bounds) config.Verifier {
	t.Helper()
	now, err := time.Parse(time.RFC3339, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	return config.Verifier{
		PublicKey:  public,
		Clock:      func() time.Time { return now },
		MaxSensors: fixture.Limits.MaxSensors,
		Bounds: config.Bounds{
			MinHeartbeatSeconds: bounds.HeartbeatSeconds.Min,
			MaxHeartbeatSeconds: bounds.HeartbeatSeconds.Max,
			MinSpoolLimitEvents: bounds.SpoolLimitEvents.Min,
			MaxSpoolLimitEvents: bounds.SpoolLimitEvents.Max,
			MinEventBatchLimit:  bounds.EventBatchLimit.Min,
			MaxEventBatchLimit:  bounds.EventBatchLimit.Max,
		},
	}
}

func c10Service(t *testing.T, fixture *c10Positive, public ed25519.PublicKey) *config.Service {
	t.Helper()
	service, err := config.New(c10Verifier(t, fixture, public, fixture.Bounds))
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	return service
}

// c10Verdicts maps the fixture verdict names to the typed engine errors.
func c10Verdicts() map[string]error {
	return map[string]error{
		"INVALID_INPUT":     config.ErrInvalidInput,
		"UNSIGNED":          config.ErrUnsigned,
		"INVALID_SIGNATURE": config.ErrInvalidSignature,
		"EXPIRED":           config.ErrExpired,
		"NOT_YET_VALID":     config.ErrNotYetValid,
		"STALE":             config.ErrStale,
		"CONFLICT":          config.ErrConflict,
	}
}

// c10Payload returns the exact bytes a case submits.
func c10Payload(t *testing.T, testCase c10Case) []byte {
	t.Helper()
	switch testCase.Build {
	case "":
		return []byte(testCase.Payload)
	case "oversized":
		// A syntactically valid document above the shared payload cap.
		return []byte(`{"schema_version":"1","sensor_id":"` + strings.Repeat("a", 9000) +
			`","revision":3,"issued_at":"2026-10-21T00:00:00Z","expires_at":"2026-11-21T00:00:00Z",` +
			`"settings":{"heartbeat_seconds":30,"spool_limit_events":4096,"event_batch_limit":64}}`)
	default:
		t.Fatalf("unknown C10 build %s", testCase.Build)
		return nil
	}
}

// c10Signature returns the signature a case submits. The engine never
// re-serializes a document, so a signature always covers exact bytes.
func c10Signature(t *testing.T, testCase c10Case, own, other ed25519.PrivateKey) []byte {
	t.Helper()
	switch testCase.Mode {
	case "unsigned":
		return nil
	case "other_key":
		return ed25519.Sign(other, c10Payload(t, testCase))
	case "tampered", "reserialized":
		return ed25519.Sign(own, []byte(testCase.SignedPayload))
	case "signed", "build":
		return ed25519.Sign(own, c10Payload(t, testCase))
	default:
		t.Fatalf("unknown C10 case mode %s", testCase.Mode)
		return nil
	}
}

// c10Active applies the fixture documents and returns the active revision.
func c10Active(t *testing.T, service *config.Service, private ed25519.PrivateKey, payload string) int64 {
	t.Helper()
	signature, err := config.Sign([]byte(payload), private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	applied, err := service.Apply(context.Background(), []byte(payload), signature)
	if err != nil {
		t.Fatalf("apply desired state: %v", err)
	}
	return applied.Revision
}

func TestConfigSignedDesiredStateBecomesActive(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if !bytes.Equal(signature, ed25519.Sign(private, payload)) {
		t.Fatal("the operator signature does not cover the exact payload bytes")
	}
	applied, err := service.Apply(context.Background(), payload, signature)
	if err != nil {
		t.Fatalf("apply desired state: %v", err)
	}
	if applied.SensorID != fixture.Expected.SensorID || applied.Revision != fixture.Expected.InitialRevision {
		t.Fatalf("applied %+v", applied)
	}
	if !bytes.Equal(applied.Payload, payload) {
		t.Fatal("the active payload differs from the submitted bytes")
	}
	active, ok := service.Active(fixture.Expected.SensorID)
	if !ok || active.Revision != fixture.Expected.InitialRevision || !bytes.Equal(active.Payload, payload) {
		t.Fatalf("active %+v present=%v", active, ok)
	}
	next := []byte(fixture.Payloads["next"])
	nextSignature, err := config.Sign(next, private)
	if err != nil {
		t.Fatalf("sign next desired state: %v", err)
	}
	applied, err = service.Apply(context.Background(), next, nextSignature)
	if err != nil {
		t.Fatalf("apply next desired state: %v", err)
	}
	if applied.Revision != fixture.Expected.NextRevision || !bytes.Equal(applied.Payload, next) {
		t.Fatalf("applied %+v", applied)
	}
	active, ok = service.Active(fixture.Expected.SensorID)
	if !ok || active.Revision != fixture.Expected.NextRevision || !bytes.Equal(active.Payload, next) {
		t.Fatalf("active %+v present=%v", active, ok)
	}
	// The exact redelivery of the active revision is an idempotent no-op: it
	// neither fails nor replaces the active configuration.
	again, err := service.Apply(context.Background(), next, nextSignature)
	if err != nil {
		t.Fatalf("redeliver active desired state: %v", err)
	}
	if again.Revision != applied.Revision || !again.AppliedAt.Equal(applied.AppliedAt) || !bytes.Equal(again.Payload, next) {
		t.Fatalf("redelivery %+v differs from %+v", again, applied)
	}
	after, _ := service.Active(fixture.Expected.SensorID)
	if !bytes.Equal(after.Payload, next) {
		t.Fatal("the redelivery changed the active payload")
	}
}

func TestConfigRejectsUnsignedDesiredState(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	payload := []byte(fixture.Payloads["initial"])
	c10Active(t, service, private, fixture.Payloads["initial"])
	before, ok := service.Active(fixture.Expected.SensorID)
	if !ok {
		t.Fatal("the signed desired state did not become active")
	}
	for _, signature := range [][]byte{nil, {}} {
		if _, err := service.Apply(context.Background(), payload, signature); !errors.Is(err, config.ErrUnsigned) {
			t.Fatalf("unsigned desired state error = %v, want %v", err, config.ErrUnsigned)
		}
		after, present := service.Active(fixture.Expected.SensorID)
		if !present || after.Revision != before.Revision || !bytes.Equal(after.Payload, before.Payload) {
			t.Fatalf("the unsigned rejection replaced the active configuration: %+v", after)
		}
	}
}

func TestConfigRejectsStaleDesiredStateWithoutReplacingActiveConfig(t *testing.T) {
	fixture, invalid, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	c10Active(t, service, private, fixture.Payloads["initial"])
	c10Active(t, service, private, fixture.Payloads["next"])
	before, ok := service.Active(fixture.Expected.SensorID)
	if !ok || before.Revision != fixture.Expected.NextRevision {
		t.Fatalf("active %+v", before)
	}
	for _, name := range []string{"stale_revision", "expired_document", "not_yet_valid_document", "conflicting_revision"} {
		testCase := c10CaseByName(t, invalid, name)
		signature := c10Signature(t, testCase, private, private)
		if _, err := service.Apply(context.Background(), c10Payload(t, testCase), signature); !errors.Is(err, c10Verdicts()[testCase.Expected]) {
			t.Fatalf("%s error = %v, want %v", name, err, c10Verdicts()[testCase.Expected])
		}
		after, present := service.Active(fixture.Expected.SensorID)
		if !present || after.Revision != before.Revision || !bytes.Equal(after.Payload, before.Payload) {
			t.Fatalf("%s replaced the active configuration: %+v", name, after)
		}
	}
}

func TestConfigRejectsInvalidDesiredStateDocuments(t *testing.T) {
	fixture, invalid, expected := c10Files(t)
	public, private := c10Key(t)
	_, other := c10Key(t)
	service := c10Service(t, fixture, public)
	c10Active(t, service, private, fixture.Payloads["initial"])
	c10Active(t, service, private, fixture.Payloads["next"])
	before, ok := service.Active(fixture.Expected.SensorID)
	if !ok {
		t.Fatal("the signed desired state did not become active")
	}
	verdicts := c10Verdicts()
	if len(invalid.Cases) != 17 {
		t.Fatalf("C10 fixture rows drifted: %d", len(invalid.Cases))
	}
	for _, testCase := range invalid.Cases {
		want, known := verdicts[testCase.Expected]
		if !known {
			t.Fatalf("unknown expected verdict %s", testCase.Expected)
		}
		if expected.ExpectedVerdicts[testCase.Name] != testCase.Expected {
			t.Fatalf("expected-output verdict drift for %s", testCase.Name)
		}
		signature := c10Signature(t, testCase, private, other)
		if _, err := service.Apply(context.Background(), c10Payload(t, testCase), signature); !errors.Is(err, want) {
			t.Errorf("%s error = %v, want %v", testCase.Name, err, want)
		}
		after, present := service.Active(fixture.Expected.SensorID)
		if !present || after.Revision != before.Revision || !bytes.Equal(after.Payload, before.Payload) {
			t.Fatalf("%s replaced the active configuration: %+v", testCase.Name, after)
		}
	}
	if expected.ExpectedActive.Revision != before.Revision || expected.ExpectedActive.SensorID != before.SensorID {
		t.Fatalf("expected-output active drift: %+v", expected.ExpectedActive)
	}
}

func TestConfigSignatureCoversExactPayloadBytes(t *testing.T) {
	fixture, invalid, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if _, err = service.Apply(context.Background(), payload, signature); err != nil {
		t.Fatalf("apply desired state: %v", err)
	}
	reserialized := c10CaseByName(t, invalid, "reserialized_document")
	if _, err = service.Apply(context.Background(), c10Payload(t, reserialized), c10Signature(t, reserialized, private, private)); !errors.Is(err, config.ErrInvalidSignature) {
		t.Fatalf("re-serialized desired state error = %v, want %v", err, config.ErrInvalidSignature)
	}
	tampered := c10CaseByName(t, invalid, "tampered_document")
	if _, err = service.Apply(context.Background(), c10Payload(t, tampered), c10Signature(t, tampered, private, private)); !errors.Is(err, config.ErrInvalidSignature) {
		t.Fatalf("tampered desired state error = %v, want %v", err, config.ErrInvalidSignature)
	}
	active, ok := service.Active(fixture.Expected.SensorID)
	if !ok || active.Revision != fixture.Expected.InitialRevision || !bytes.Equal(active.Payload, payload) {
		t.Fatalf("active %+v present=%v", active, ok)
	}
}

func TestConfigRejectsMissingPrerequisites(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	base := c10Verifier(t, fixture, public, fixture.Bounds)
	now := base.Clock()
	invalid := []config.Verifier{
		{PublicKey: nil, Clock: base.Clock, MaxSensors: 1, Bounds: base.Bounds},
		{PublicKey: ed25519.PublicKey(public[:31]), Clock: base.Clock, MaxSensors: 1, Bounds: base.Bounds},
		{PublicKey: public, Clock: nil, MaxSensors: 1, Bounds: base.Bounds},
		{PublicKey: public, Clock: base.Clock, MaxSensors: 0, Bounds: base.Bounds},
		// An unset or inverted settings range is an incomplete configuration.
		{PublicKey: public, Clock: base.Clock, MaxSensors: 1},
		{PublicKey: public, Clock: base.Clock, MaxSensors: 1, Bounds: config.Bounds{
			MinHeartbeatSeconds: 10, MaxHeartbeatSeconds: 5,
			MinSpoolLimitEvents: 1, MaxSpoolLimitEvents: 10,
			MinEventBatchLimit: 1, MaxEventBatchLimit: 10,
		}},
	}
	for _, verifier := range invalid {
		service, err := config.New(verifier)
		if !errors.Is(err, config.ErrInvalidInput) {
			t.Fatalf("invalid configuration error = %v, want %v", err, config.ErrInvalidInput)
		}
		if service != nil {
			t.Fatal("an invalid configuration constructed a service")
		}
	}
	if now.IsZero() {
		t.Fatal("the fixture clock is not usable")
	}
	if _, err := config.Sign([]byte(fixture.Payloads["initial"]), ed25519.PrivateKey(private[:31])); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatalf("short signing key error = %v, want %v", err, config.ErrInvalidInput)
	}
	if _, err := config.Sign([]byte(`{"schema_version":"2"}`), private); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatalf("invalid document signature error = %v, want %v", err, config.ErrInvalidInput)
	}
	var missing *config.Service
	signature := ed25519.Sign(private, []byte(fixture.Payloads["initial"]))
	if _, err := missing.Apply(context.Background(), []byte(fixture.Payloads["initial"]), signature); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatalf("missing service error = %v, want %v", err, config.ErrInvalidInput)
	}
	service := c10Service(t, fixture, public)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Apply(cancelled, []byte(fixture.Payloads["initial"]), ed25519.Sign(private, []byte(fixture.Payloads["initial"]))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled apply error = %v, want %v", err, context.Canceled)
	}
}

func TestConfigRejectsDesiredStateSensorQuota(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	verifier := c10Verifier(t, fixture, public, fixture.Bounds)
	verifier.MaxSensors = 1
	service, err := config.New(verifier)
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	c10Active(t, service, private, fixture.Payloads["initial"])
	other := []byte(`{"schema_version":"1","sensor_id":"sensor-02","revision":1,"issued_at":"2026-10-21T00:00:00Z","expires_at":"2026-11-21T00:00:00Z","settings":{"heartbeat_seconds":30,"spool_limit_events":4096,"event_batch_limit":64}}`)
	signature, err := config.Sign(other, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if _, err = service.Apply(context.Background(), other, signature); !errors.Is(err, config.ErrQuota) {
		t.Fatalf("sensor quota error = %v, want %v", err, config.ErrQuota)
	}
	if _, ok := service.Active("sensor-02"); ok {
		t.Fatal("the rejected desired state became the active configuration")
	}
	active, ok := service.Active(fixture.Expected.SensorID)
	if !ok || active.Revision != fixture.Expected.InitialRevision {
		t.Fatalf("active %+v present=%v", active, ok)
	}
}

// TestConfigAppliedPayloadCannotMutateActiveState proves the active
// configuration owns its own bytes: a caller that mutates the payload
// returned by Apply cannot change the stored signed configuration.
func TestConfigAppliedPayloadCannotMutateActiveState(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	applied, err := service.Apply(context.Background(), payload, signature)
	if err != nil {
		t.Fatalf("apply desired state: %v", err)
	}
	if len(applied.Payload) == 0 {
		t.Fatal("the applied payload is empty")
	}
	applied.Payload[0] = 'X'
	active, ok := service.Active(fixture.Expected.SensorID)
	if !ok {
		t.Fatal("the signed desired state did not become active")
	}
	if !bytes.Equal(active.Payload, payload) {
		t.Fatal("the applied result aliased the active configuration")
	}
	if active.Revision != fixture.Expected.InitialRevision {
		t.Fatalf("active revision %d", active.Revision)
	}
}

// TestConfigTrustedKeyIsCopiedAtConstruction proves the trust anchor cannot
// change after construction: mutating the caller's key slice leaves the
// configured signer authoritative.
func TestConfigTrustedKeyIsCopiedAtConstruction(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	verifier := c10Verifier(t, fixture, public, fixture.Bounds)
	service, err := config.New(verifier)
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	// The caller overwrites the key bytes it handed to the service.
	for i := range public {
		public[i] = 0
	}
	if _, err = service.Apply(context.Background(), payload, signature); err != nil {
		t.Fatalf("apply desired state after the key bytes changed: %v", err)
	}
	// A document signed by the overwritten key is not trusted.
	other, otherPrivate := c10Key(t)
	for i := range other {
		other[i] = 0
	}
	foreign, err := config.Sign(payload, otherPrivate)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if _, err = service.Apply(context.Background(), payload, foreign); !errors.Is(err, config.ErrInvalidSignature) {
		t.Fatalf("foreign signature error = %v, want %v", err, config.ErrInvalidSignature)
	}
}

// TestConfigExpiryIsRecheckedAtAcceptanceTime proves the validity window is
// judged at the moment the document becomes the active configuration: a
// document that expires while the service waits for the state lock is
// rejected and never replaces the active configuration.
func TestConfigExpiryIsRecheckedAtAcceptanceTime(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	verifier := c10Verifier(t, fixture, public, fixture.Bounds)
	issued, err := time.Parse(time.RFC3339, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	// The clock reads the instant before the window on the first call and the
	// expiry instant on every later call: the document is valid when it is
	// verified and expired when it would become the active configuration.
	var window struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(fixture.Payloads["initial"]), &window); err != nil {
		t.Fatalf("malformed fixture document: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, window.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	verifier.Clock = func() time.Time {
		reads++
		if reads == 1 {
			return issued
		}
		return expires
	}
	service, err := config.New(verifier)
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if _, err = service.Apply(context.Background(), payload, signature); !errors.Is(err, config.ErrExpired) {
		t.Fatalf("expired desired state error = %v, want %v", err, config.ErrExpired)
	}
	if _, ok := service.Active(fixture.Expected.SensorID); ok {
		t.Fatal("the expired desired state became the active configuration")
	}
}

// TestConfigSettingsBoundsAreDeploymentPolicy proves the accepted range of
// the settings is explicit deployment policy: the engine ships no product
// limit, and a deployment with tighter bounds rejects a document that a
// deployment with wider bounds accepts.
func TestConfigSettingsBoundsAreDeploymentPolicy(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	payload := []byte(fixture.Payloads["initial"])
	signature, err := config.Sign(payload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	proposed := c10Service(t, fixture, public)
	if _, err = proposed.Apply(context.Background(), payload, signature); err != nil {
		t.Fatalf("apply desired state: %v", err)
	}
	tightVerifier := c10Verifier(t, fixture, public, fixture.TightBounds)
	tight, err := config.New(tightVerifier)
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	if _, err = tight.Apply(context.Background(), payload, signature); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatalf("out of policy desired state error = %v, want %v", err, config.ErrInvalidInput)
	}
	if _, ok := tight.Active(fixture.Expected.SensorID); ok {
		t.Fatal("the rejected desired state became the active configuration")
	}
	// A deployment that states a wider range accepts a document the proposed
	// policy rejects: the engine ships no limit of its own.
	wideVerifier := c10Verifier(t, fixture, public, fixture.WideBounds)
	wider, err := config.New(wideVerifier)
	if err != nil {
		t.Fatalf("config service: %v", err)
	}
	widePayload := []byte(fixture.WidePayload)
	wideSignature, err := config.Sign(widePayload, private)
	if err != nil {
		t.Fatalf("sign desired state: %v", err)
	}
	if _, err = wider.Apply(context.Background(), widePayload, wideSignature); err != nil {
		t.Fatalf("apply desired state within the deployment policy: %v", err)
	}
	strict := c10Service(t, fixture, public)
	if _, err = strict.Apply(context.Background(), widePayload, wideSignature); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatalf("out of policy desired state error = %v, want %v", err, config.ErrInvalidInput)
	}
}

func TestConfigFreshServiceHasNoRememberedActiveState(t *testing.T) {
	fixture, _, _ := c10Files(t)
	public, private := c10Key(t)
	service := c10Service(t, fixture, public)
	c10Active(t, service, private, fixture.Payloads["initial"])
	if _, ok := service.Active(fixture.Expected.SensorID); !ok {
		t.Fatal("the signed desired state did not become active")
	}
	// A restarted service owns no durable applied revision in C10: the
	// documented recovery outcome is that the operator re-applies the latest
	// signed desired state. C11 owns the durable applied revision.
	restarted := c10Service(t, fixture, public)
	if _, ok := restarted.Active(fixture.Expected.SensorID); ok {
		t.Fatal("a fresh service remembered an applied revision")
	}
	if _, err := restarted.Apply(context.Background(), []byte(fixture.Payloads["initial"]), nil); !errors.Is(err, config.ErrUnsigned) {
		t.Fatalf("unsigned desired state error = %v, want %v", err, config.ErrUnsigned)
	}
	if _, ok := restarted.Active(fixture.Expected.SensorID); ok {
		t.Fatal("a rejected desired state became the active configuration")
	}
	revision := c10Active(t, restarted, private, fixture.Payloads["initial"])
	if revision != fixture.Expected.InitialRevision {
		t.Fatalf("re-applied revision %d", revision)
	}
}
