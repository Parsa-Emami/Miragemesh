package contracts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const ConfigApplied = "config.applied"

// MaxStoredInputBytes includes the base64 envelope for an exact MaxInputBytes
// signed payload. Public event and desired-state input limits do not change.
const MaxStoredInputBytes = 2 * MaxInputBytes

// AppliedConfig is an internal durable record, not a public desired-state schema.
// Byte slices use JSON base64 so Marshal cannot reformat the signed payload.
// https://pkg.go.dev/encoding/json#Marshal
type AppliedConfig struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Payload       []byte `json:"payload"`
	Signature     []byte `json:"signature"`
	AppliedAt     string `json:"applied_at"`
}

// DecodeAppliedConfig validates the canonical storage envelope. Signer, document
// policy and revision checks belong to the config verifier and sensor applier.
func DecodeAppliedConfig(ctx context.Context, raw []byte) (AppliedConfig, error) {
	if err := ctx.Err(); err != nil {
		return AppliedConfig{}, err
	}
	var record AppliedConfig
	if len(raw) > MaxStoredInputBytes || json.Unmarshal(raw, &record) != nil {
		return AppliedConfig{}, &ValidationError{Code: InvalidInput}
	}
	canonical, _ := json.Marshal(record)
	at, err := time.Parse(time.RFC3339Nano, record.AppliedAt)
	if !bytes.Equal(raw, canonical) || record.SchemaVersion != SchemaVersion || record.Kind != ConfigApplied || len(record.Payload) == 0 || len(record.Payload) > MaxInputBytes || len(record.Signature) != ed25519.SignatureSize || err != nil || at.IsZero() || at.Year() < 1000 || at.Year() > 9999 || at.UTC().Format(time.RFC3339Nano) != record.AppliedAt {
		return AppliedConfig{}, &ValidationError{Code: InvalidInput}
	}
	return record, nil
}
