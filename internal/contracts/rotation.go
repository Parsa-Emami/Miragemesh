package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"
	"unicode/utf8"
)

const CertificateRegister = "certificate.register"
const CertificateRotate = "certificate.rotate"
const CertificateRecover = "certificate.recover"
const MaxCertificateRevision = 9007199254740991

type CertificateRotationRecord struct {
	SchemaVersion       string `json:"schema_version"`
	Kind                string `json:"kind"`
	SensorID            string `json:"sensor_id"`
	Revision            uint64 `json:"revision"`
	IssuerFingerprint   string `json:"issuer_fingerprint"`
	CertificateDER      []byte `json:"certificate_der"`
	PreviousFingerprint string `json:"previous_fingerprint,omitempty"`
	AcceptedAt          string `json:"accepted_at"`
	OverlapUntil        string `json:"overlap_until,omitempty"`
	LifetimeSeconds     int64  `json:"lifetime_seconds,omitempty"`
	OverlapSeconds      int64  `json:"overlap_seconds,omitempty"`
	CSRDER              []byte `json:"csr_der,omitempty"`
	TokenHash           string `json:"token_hash,omitempty"`
	KeyDigest           string `json:"key_digest"`
	RequestDigest       string `json:"request_digest"`
}

func CertificateIntentDigest(r CertificateRotationRecord) string {
	type intent struct {
		Kind             string
		SensorID         string
		ExpectedRevision uint64
		CertificateDER   []byte
		CSRDER           []byte
		LifetimeSeconds  int64
		OverlapSeconds   int64
		TokenHash        string
	}
	var certificate []byte
	if r.Kind == CertificateRegister {
		certificate = r.CertificateDER
	}
	previous := uint64(0)
	if r.Revision > 0 {
		previous = r.Revision - 1
	}
	raw, _ := json.Marshal(intent{r.Kind, r.SensorID, previous, certificate, r.CSRDER, r.LifetimeSeconds, r.OverlapSeconds, r.TokenHash})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func DecodeCertificateRotation(ctx context.Context, raw []byte) (CertificateRotationRecord, error) {
	invalid := func() (CertificateRotationRecord, error) {
		return CertificateRotationRecord{}, &ValidationError{Code: InvalidInput}
	}
	if ctx == nil {
		return invalid()
	}
	if err := ctx.Err(); err != nil {
		return CertificateRotationRecord{}, err
	}
	var r CertificateRotationRecord
	if len(raw) > MaxInputBytes || !utf8.Valid(raw) || json.Unmarshal(raw, &r) != nil {
		return invalid()
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) || r.SchemaVersion != SchemaVersion || !ValidSensorID(r.SensorID) || r.Revision < 1 || r.Revision > MaxCertificateRevision || !validDigest(r.IssuerFingerprint) || !validDigest(r.KeyDigest) || r.RequestDigest != CertificateIntentDigest(r) || len(r.CertificateDER) == 0 || len(r.CertificateDER) > 4096 {
		return invalid()
	}
	accepted, err := time.Parse(time.RFC3339Nano, r.AcceptedAt)
	if err != nil || accepted.IsZero() || accepted.Year() < 1000 || accepted.UTC().Format(time.RFC3339Nano) != r.AcceptedAt {
		return invalid()
	}
	if r.Kind == CertificateRegister {
		if r.Revision != 1 || r.PreviousFingerprint != "" || r.OverlapUntil != "" || r.LifetimeSeconds != 0 || r.OverlapSeconds != 0 || len(r.CSRDER) != 0 || r.TokenHash != "" {
			return invalid()
		}
		return r, nil
	}
	if r.Kind != CertificateRotate && r.Kind != CertificateRecover || r.Revision < 2 || !validDigest(r.PreviousFingerprint) || len(r.CSRDER) == 0 || len(r.CSRDER) > 4096 || r.LifetimeSeconds < 1 || r.LifetimeSeconds > math.MaxInt64/int64(time.Second) || r.OverlapSeconds < 0 || r.OverlapSeconds >= r.LifetimeSeconds {
		return invalid()
	}
	if r.Kind == CertificateRotate && (r.OverlapSeconds < 1 || r.TokenHash != "") || r.Kind == CertificateRecover && (r.OverlapSeconds != 0 || !validDigest(r.TokenHash)) {
		return invalid()
	}
	deadline := accepted.Add(time.Duration(r.OverlapSeconds) * time.Second)
	if deadline.Year() > 9999 || deadline.UTC().Format(time.RFC3339Nano) != r.OverlapUntil {
		return invalid()
	}
	return r, nil
}
