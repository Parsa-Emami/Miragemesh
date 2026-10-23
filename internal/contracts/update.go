package contracts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"
	"unicode/utf8"
)

const UpdateMetadata = "update.metadata"
const UpdateVerified = "update.verified"

type UpdateRecord struct {
	SchemaVersion        string `json:"schema_version"`
	Kind                 string `json:"kind"`
	SensorID             string `json:"sensor_id"`
	AcceptedAt           string `json:"accepted_at"`
	Payload              []byte `json:"payload,omitempty"`
	Signature            []byte `json:"signature,omitempty"`
	VerificationRevision uint64 `json:"verification_revision,omitempty"`
	MetadataRevision     uint64 `json:"metadata_revision,omitempty"`
	MetadataDigest       string `json:"metadata_digest,omitempty"`
	Version              uint64 `json:"version,omitempty"`
	ArtifactDigest       string `json:"artifact_digest,omitempty"`
	ArtifactLength       int64  `json:"artifact_length,omitempty"`
	RecoveryPayload      []byte `json:"recovery_payload,omitempty"`
	RecoverySignature    []byte `json:"recovery_signature,omitempty"`
}

func DecodeUpdate(ctx context.Context, raw []byte) (UpdateRecord, error) {
	invalid := func() (UpdateRecord, error) { return UpdateRecord{}, &ValidationError{Code: InvalidInput} }
	if ctx == nil {
		return invalid()
	}
	if err := ctx.Err(); err != nil {
		return UpdateRecord{}, err
	}
	var r UpdateRecord
	if len(raw) > MaxStoredInputBytes || !utf8.Valid(raw) || json.Unmarshal(raw, &r) != nil {
		return invalid()
	}
	canonical, _ := json.Marshal(r)
	at, err := time.Parse(time.RFC3339Nano, r.AcceptedAt)
	if !bytes.Equal(raw, canonical) || r.SchemaVersion != SchemaVersion || !ValidSensorID(r.SensorID) || err != nil || at.Year() < 1000 || at.UTC().Format(time.RFC3339Nano) != r.AcceptedAt {
		return invalid()
	}
	if r.Kind == UpdateMetadata {
		if len(r.Payload) == 0 || len(r.Payload) > MaxInputBytes || len(r.Signature) != ed25519.SignatureSize || r.VerificationRevision != 0 || r.MetadataRevision != 0 || r.MetadataDigest != "" || r.Version != 0 || r.ArtifactDigest != "" || r.ArtifactLength != 0 || len(r.RecoveryPayload) != 0 || len(r.RecoverySignature) != 0 {
			return invalid()
		}
	} else if r.Kind == UpdateVerified {
		if r.VerificationRevision < 1 || r.VerificationRevision > uint64(MaxSequence) || len(r.Payload) != 0 || len(r.Signature) != 0 || r.MetadataRevision < 1 || r.MetadataRevision > uint64(MaxSequence) || !validDigest(r.MetadataDigest) || r.Version < 1 || r.Version > uint64(MaxSequence) || !validDigest(r.ArtifactDigest) || r.ArtifactLength < 1 || r.ArtifactLength > 67108864 || len(r.RecoveryPayload) > 2048 || len(r.RecoveryPayload) == 0 && len(r.RecoverySignature) != 0 || len(r.RecoveryPayload) > 0 && len(r.RecoverySignature) != ed25519.SignatureSize {
			return invalid()
		}
	} else {
		return invalid()
	}
	return r, nil
}
