package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

const EnrollmentIssue = "enrollment.issue"
const EnrollmentConsume = "enrollment.consume"

// ValidSensorID uses the same opaque identifier bounds as the C04 event contract.
func ValidSensorID(id string) bool {
	return utf8.ValidString(id) && utf8.RuneCountInString(id) >= 1 && utf8.RuneCountInString(id) <= 128
}

type EnrollmentRecord struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	SensorID      string `json:"sensor_id"`
	TokenHash     string `json:"token_hash"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	ConsumedAt    string `json:"consumed_at,omitempty"`
}

// DecodeEnrollment reads canonical internal storage records, not a public event format.
func DecodeEnrollment(ctx context.Context, raw []byte) (EnrollmentRecord, *ValidationError) {
	var r EnrollmentRecord
	invalid := &ValidationError{Code: InvalidInput}
	if failure := contextError(ctx); failure != nil {
		return r, failure
	}
	if len(raw) > MaxInputBytes {
		return r, &ValidationError{Code: InputTooLarge}
	}
	if !utf8.Valid(raw) || !json.Valid(raw) || !ValidUnicodeEscapes(raw) {
		return r, &ValidationError{Code: InvalidJSON}
	}
	if json.Unmarshal(raw, &r) != nil {
		return EnrollmentRecord{}, invalid
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) || r.SchemaVersion != SchemaVersion || !ValidSensorID(r.SensorID) || len(r.TokenHash) != 64 {
		return EnrollmentRecord{}, invalid
	}
	for _, c := range r.TokenHash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return EnrollmentRecord{}, invalid
		}
	}
	parse := func(s string) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339Nano, s)
		return t, err == nil && !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.UTC().Format(time.RFC3339Nano) == s
	}
	issued, ok := parse(r.IssuedAt)
	expires, valid := parse(r.ExpiresAt)
	if !ok || !valid || !expires.After(issued) {
		return EnrollmentRecord{}, invalid
	}
	switch r.Kind {
	case EnrollmentIssue:
		if r.ConsumedAt != "" {
			return EnrollmentRecord{}, invalid
		}
	case EnrollmentConsume:
		consumed, valid := parse(r.ConsumedAt)
		if !valid || consumed.Before(issued) || !consumed.Before(expires) {
			return EnrollmentRecord{}, invalid
		}
	default:
		return EnrollmentRecord{}, invalid
	}
	return r, nil
}
