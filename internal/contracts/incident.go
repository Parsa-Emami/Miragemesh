package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

const IncidentTriage = "incident.triage"

// MaxIncidentStatusRunes and MaxIncidentReasonRunes match the existing private
// triage contract in contracts/openapi.v1.json. They bound code points, not
// bytes; the C05 stored-record byte bound also applies.
const (
	MaxIncidentStatusRunes = 4096
	MaxIncidentReasonRunes = 4096
	MaxIncidentIDRunes     = 255
)

// IncidentTriageRecord is an append-only local incident label. It never
// contains observed event content; event bytes remain in their event records
// and immutable segments.
type IncidentTriageRecord struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	IncidentID    string `json:"incident_id"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	KeyDigest     string `json:"key_digest"`
	TriagedAt     string `json:"triaged_at"`
}

// DecodeIncidentTriage validates the canonical internal triage record.
func DecodeIncidentTriage(ctx context.Context, raw []byte) (IncidentTriageRecord, error) {
	invalid := &ValidationError{Code: InvalidInput}
	if ctx == nil {
		return IncidentTriageRecord{}, invalid
	}
	if err := ctx.Err(); err != nil {
		return IncidentTriageRecord{}, err
	}
	var record IncidentTriageRecord
	if len(raw) > MaxStoredInputBytes || !utf8.Valid(raw) || !json.Valid(raw) || !validEscapes(raw) {
		return IncidentTriageRecord{}, invalid
	}
	if json.Unmarshal(raw, &record) != nil {
		return IncidentTriageRecord{}, invalid
	}
	canonical, _ := json.Marshal(record)
	at, err := time.Parse(time.RFC3339Nano, record.TriagedAt)
	if !bytes.Equal(raw, canonical) || record.SchemaVersion != SchemaVersion || record.Kind != IncidentTriage ||
		!ValidIncidentID(record.IncidentID) || !validText(record.Status, MaxIncidentStatusRunes) ||
		!validText(record.Reason, MaxIncidentReasonRunes) || !validDigest(record.KeyDigest) ||
		err != nil || at.IsZero() || at.Year() < 1 || at.Year() > 9999 ||
		at.UTC().Format(time.RFC3339Nano) != record.TriagedAt {
		return IncidentTriageRecord{}, invalid
	}
	return record, nil
}

// ValidIncidentID applies the opaque path-identifier bound from the private
// triage contract.
func ValidIncidentID(id string) bool {
	return utf8.ValidString(id) && utf8.RuneCountInString(id) >= 1 && utf8.RuneCountInString(id) <= MaxIncidentIDRunes
}

func validText(value string, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= max
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
