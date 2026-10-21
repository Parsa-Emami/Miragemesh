// Package config verifies and applies signed versioned desired state.
//
// The service validates one strictly typed desired-state document, verifies
// its Ed25519 signature over the exact submitted payload bytes and keeps the
// accepted document as the active configuration of the running process. The
// active configuration is process state: C11 owns the durable applied
// revision and the convergence of a config apply after a crash.
//
// The signing key is trusted local configuration and is independent from the
// mTLS collector certificate authorities and revocation material. This
// package never creates, stores, rotates or recovers key material, never
// re-serializes a signed document and never contacts a network service.
package config

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

var (
	ErrInvalidInput     = errors.New("config: invalid desired state input")
	ErrUnsigned         = errors.New("config: desired state is not signed")
	ErrInvalidSignature = errors.New("config: desired state signature is invalid")
	ErrExpired          = errors.New("config: desired state expired")
	ErrNotYetValid      = errors.New("config: desired state is not valid yet")
	ErrStale            = errors.New("config: desired state revision is stale")
	ErrConflict         = errors.New("config: desired state conflicts with the active revision")
	ErrQuota            = errors.New("config: desired state sensor quota exceeded")
)

// The version 1 desired-state settings carry no hidden default: the accepted
// range of every setting is explicit deployment policy (see Bounds) and the
// engine ships no product limit of its own.
var (
	documentFields = []string{"schema_version", "sensor_id", "revision", "issued_at", "expires_at", "settings"}
	settingsFields = []string{"heartbeat_seconds", "spool_limit_events", "event_batch_limit"}
)

// Settings are the versioned desired-state settings of one sensor.
type Settings struct {
	HeartbeatSeconds int `json:"heartbeat_seconds"`
	SpoolLimitEvents int `json:"spool_limit_events"`
	EventBatchLimit  int `json:"event_batch_limit"`
}

// Document is the typed desired state carried by one signed payload. The
// schema version describes the document format and is independent from the
// operational revision.
type Document struct {
	SchemaVersion string
	SensorID      string
	Revision      int64
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Settings      Settings
}

// Applied is the active desired state of one sensor.
type Applied struct {
	SensorID  string
	Revision  int64
	Payload   []byte
	AppliedAt time.Time
}

// Bounds are the explicit deployment limits for the version 1 desired-state
// settings. They are trusted local configuration: the engine ships no hidden
// default and no product policy of its own, and a deployment states the
// accepted range of every setting. The C10 values are proposed policy, not an
// already accepted product limit; see docs/architecture/DESIRED_STATE.md.
type Bounds struct {
	MinHeartbeatSeconds int
	MaxHeartbeatSeconds int
	MinSpoolLimitEvents int
	MaxSpoolLimitEvents int
	MinEventBatchLimit  int
	MaxEventBatchLimit  int
}

// Verifier is the trusted local configuration of the desired-state
// authority: the signing public key, the authoritative clock, the bound on
// tracked sensors and the accepted range of every setting.
type Verifier struct {
	PublicKey  ed25519.PublicKey
	Clock      func() time.Time
	MaxSensors int
	Bounds     Bounds
}

type active struct {
	revision int64
	payload  []byte
	applied  time.Time
}

// Service verifies desired state and owns the active configuration.
type Service struct {
	verifier Verifier
	mu       sync.Mutex
	active   map[string]*active
}

// New validates the trusted local configuration and fails closed on an
// incomplete one. The public key length is checked here because the standard
// library panics on a public key of the wrong size. The key bytes are copied
// into service-owned memory: the caller's slice must not stay able to change
// which signer the service trusts after construction.
func New(verifier Verifier) (*Service, error) {
	if len(verifier.PublicKey) != ed25519.PublicKeySize || verifier.Clock == nil || verifier.MaxSensors <= 0 {
		return nil, ErrInvalidInput
	}
	if !validBounds(verifier.Bounds) {
		return nil, ErrInvalidInput
	}
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(key, verifier.PublicKey)
	verifier.PublicKey = key
	return &Service{verifier: verifier, active: make(map[string]*active)}, nil
}

// validBounds requires an explicit, positive and ordered range for every
// setting. There is no default, no empty range and no unlimited mode.
func validBounds(bounds Bounds) bool {
	for _, entry := range []struct{ lower, upper int }{
		{bounds.MinHeartbeatSeconds, bounds.MaxHeartbeatSeconds},
		{bounds.MinSpoolLimitEvents, bounds.MaxSpoolLimitEvents},
		{bounds.MinEventBatchLimit, bounds.MaxEventBatchLimit},
	} {
		if entry.lower < 1 || entry.upper < entry.lower {
			return false
		}
	}
	return true
}

// Sign returns the Ed25519 signature of the exact payload bytes. This is the
// operator side: it refuses to sign a structurally invalid document. The
// accepted range of the settings is deployment policy, so only the receiving
// deployment can judge it. The engine never re-serializes a document, so a
// signature always covers the bytes that were submitted.
func Sign(payload []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidInput
	}
	if _, err := Parse(payload); err != nil {
		return nil, err
	}
	return ed25519.Sign(privateKey, payload), nil
}

// Apply verifies one signed desired state and makes it the active
// configuration of its sensor. The order is fixed: a missing signature
// fails first, then the signature over the exact bytes, then the document
// fields, then the settings against the deployment bounds, then the validity
// window and finally the monotonic revision. The validity window is rechecked
// under the state lock, so a document that expires while the service waits
// cannot become the active configuration. A rejected document never replaces
// the active configuration.
func (s *Service) Apply(ctx context.Context, payload, signature []byte) (Applied, error) {
	if s == nil {
		return Applied{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Applied{}, err
	}
	if len(signature) == 0 {
		return Applied{}, ErrUnsigned
	}
	if !ed25519.Verify(s.verifier.PublicKey, payload, signature) {
		return Applied{}, ErrInvalidSignature
	}
	document, err := Parse(payload)
	if err != nil {
		return Applied{}, err
	}
	if !s.boundsAllow(document.Settings) {
		return Applied{}, ErrInvalidInput
	}
	now := s.verifier.Clock().UTC()
	if now.IsZero() || now.Year() < 1000 {
		return Applied{}, ErrInvalidInput
	}
	if now.Before(document.IssuedAt) {
		return Applied{}, ErrNotYetValid
	}
	if !now.Before(document.ExpiresAt) {
		return Applied{}, ErrExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recheck the authoritative clock and the validity window under the state
	// lock: the document must still be valid at the moment it becomes the
	// active configuration.
	now = s.verifier.Clock().UTC()
	if now.IsZero() || now.Year() < 1000 {
		return Applied{}, ErrInvalidInput
	}
	if now.Before(document.IssuedAt) {
		return Applied{}, ErrNotYetValid
	}
	if !now.Before(document.ExpiresAt) {
		return Applied{}, ErrExpired
	}
	current, exists := s.active[document.SensorID]
	if exists {
		if document.Revision < current.revision {
			return Applied{}, ErrStale
		}
		if document.Revision == current.revision {
			if !bytes.Equal(current.payload, payload) {
				return Applied{}, ErrConflict
			}
			// The exact redelivery of the active revision is an idempotent
			// no-op: it applies nothing and changes nothing.
			return Applied{
				SensorID:  document.SensorID,
				Revision:  current.revision,
				Payload:   append([]byte(nil), current.payload...),
				AppliedAt: current.applied,
			}, nil
		}
	} else if len(s.active) >= s.verifier.MaxSensors {
		return Applied{}, ErrQuota
	}
	applied := Applied{
		SensorID:  document.SensorID,
		Revision:  document.Revision,
		Payload:   append([]byte(nil), payload...),
		AppliedAt: now,
	}
	// The active state owns its own copy: a caller that mutates the returned
	// payload must not be able to change the stored active configuration.
	s.active[document.SensorID] = &active{
		revision: applied.Revision,
		payload:  append([]byte(nil), payload...),
		applied:  applied.AppliedAt,
	}
	return applied, nil
}

// boundsAllow reports whether every setting is inside the deployment policy.
func (s *Service) boundsAllow(settings Settings) bool {
	bounds := s.verifier.Bounds
	return settings.HeartbeatSeconds >= bounds.MinHeartbeatSeconds && settings.HeartbeatSeconds <= bounds.MaxHeartbeatSeconds &&
		settings.SpoolLimitEvents >= bounds.MinSpoolLimitEvents && settings.SpoolLimitEvents <= bounds.MaxSpoolLimitEvents &&
		settings.EventBatchLimit >= bounds.MinEventBatchLimit && settings.EventBatchLimit <= bounds.MaxEventBatchLimit
}

// Active returns the active desired state of one sensor. The payload is a
// copy: a caller cannot mutate the active configuration.
func (s *Service) Active(sensorID string) (Applied, bool) {
	if s == nil {
		return Applied{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.active[sensorID]
	if !exists {
		return Applied{}, false
	}
	return Applied{
		SensorID:  sensorID,
		Revision:  current.revision,
		Payload:   append([]byte(nil), current.payload...),
		AppliedAt: current.applied,
	}, true
}

// Parse decodes and validates one desired-state payload. Unknown, duplicated
// and case-insensitively matched members are rejected so a signed payload has
// exactly one field reading. The payload is never re-serialized here.
func Parse(payload []byte) (Document, error) {
	if len(payload) == 0 || len(payload) > contracts.MaxInputBytes {
		return Document{}, ErrInvalidInput
	}
	if !utf8.Valid(payload) || !json.Valid(payload) || !validEscapes(payload) {
		return Document{}, ErrInvalidInput
	}
	fields, err := members(payload, documentFields)
	if err != nil {
		return Document{}, err
	}
	for _, name := range documentFields {
		if _, exists := fields[name]; !exists {
			return Document{}, ErrInvalidInput
		}
	}
	document := Document{}
	if json.Unmarshal(fields["schema_version"], &document.SchemaVersion) != nil || document.SchemaVersion != contracts.SchemaVersion {
		return Document{}, ErrInvalidInput
	}
	if json.Unmarshal(fields["sensor_id"], &document.SensorID) != nil || !contracts.ValidSensorID(document.SensorID) {
		return Document{}, ErrInvalidInput
	}
	revision, err := integer(fields["revision"])
	if err != nil || revision < 1 {
		return Document{}, ErrInvalidInput
	}
	document.Revision = revision
	issued, err := instant(fields["issued_at"])
	if err != nil {
		return Document{}, ErrInvalidInput
	}
	expires, err := instant(fields["expires_at"])
	if err != nil || !expires.After(issued) {
		return Document{}, ErrInvalidInput
	}
	document.IssuedAt = issued
	document.ExpiresAt = expires
	settings, err := parseSettings(fields["settings"])
	if err != nil {
		return Document{}, err
	}
	document.Settings = settings
	return document, nil
}

// members reads one JSON object and returns its exact member values.
// Unknown, duplicated and non-exact member names are rejected: the standard
// decoder alone would accept duplicates and case-insensitive matches.
func members(raw []byte, allowed []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, ErrInvalidInput
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidInput
		}
		name, ok := key.(string)
		if !ok {
			return nil, ErrInvalidInput
		}
		if _, exists := fields[name]; exists {
			return nil, ErrInvalidInput
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, ErrInvalidInput
		}
		known := false
		for _, field := range allowed {
			if name == field {
				known = true
				break
			}
		}
		if !known {
			return nil, ErrInvalidInput
		}
		fields[name] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, ErrInvalidInput
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	return fields, nil
}

// integer accepts one plain JSON integer literal: no fraction, no exponent
// and no sign beyond a single leading minus.
func integer(raw json.RawMessage) (int64, error) {
	number := strings.TrimSpace(string(raw))
	if number == "" {
		return 0, ErrInvalidInput
	}
	digits := number
	if digits[0] == '-' {
		digits = digits[1:]
	}
	if digits == "" {
		return 0, ErrInvalidInput
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, ErrInvalidInput
		}
	}
	value, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return 0, ErrInvalidInput
	}
	return value, nil
}

// instant parses an RFC 3339 timestamp with an explicit offset and returns
// the instant in UTC. The format carries its own time zone, so the value
// never depends on the host time zone.
func instant(raw json.RawMessage) (time.Time, error) {
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return time.Time{}, ErrInvalidInput
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.IsZero() || parsed.Year() < 1000 || parsed.Year() > 9999 {
		return time.Time{}, ErrInvalidInput
	}
	return parsed.UTC(), nil
}

// parseSettings reads the version 1 settings of one document. The values are
// parsed but not ranged here: the accepted range is deployment policy and is
// applied by the service against its configured bounds.
func parseSettings(raw json.RawMessage) (Settings, error) {
	fields, err := members(raw, settingsFields)
	if err != nil {
		return Settings{}, err
	}
	for _, name := range settingsFields {
		if _, exists := fields[name]; !exists {
			return Settings{}, ErrInvalidInput
		}
	}
	settings := Settings{}
	for _, entry := range []struct {
		name   string
		target *int
	}{
		{"heartbeat_seconds", &settings.HeartbeatSeconds},
		{"spool_limit_events", &settings.SpoolLimitEvents},
		{"event_batch_limit", &settings.EventBatchLimit},
	} {
		value, err := integer(fields[entry.name])
		if err != nil {
			return Settings{}, ErrInvalidInput
		}
		*entry.target = int(value)
	}
	return settings, nil
}

// validEscapes rejects unpaired UTF-16 escapes before decoding so two
// distinct malformed sensor identifiers cannot collapse into one value.
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		unit, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' || i+7 > len(data) {
				return false
			}
			low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
