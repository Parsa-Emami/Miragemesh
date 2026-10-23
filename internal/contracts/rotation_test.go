package contracts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCertificateRotationRecordValidation(t *testing.T) {
	initial := CertificateRotationRecord{SchemaVersion: "1", Kind: CertificateRegister, SensorID: "sensor-24", Revision: 1, IssuerFingerprint: strings.Repeat("a", 64), CertificateDER: []byte{1, 2, 3}, AcceptedAt: "2026-01-01T00:00:00Z", KeyDigest: strings.Repeat("b", 64)}
	initial.RequestDigest = CertificateIntentDigest(initial)
	rotated := initial
	rotated.Kind = CertificateRotate
	rotated.Revision = 2
	rotated.PreviousFingerprint = strings.Repeat("c", 64)
	rotated.CSRDER = []byte{4, 5, 6}
	rotated.LifetimeSeconds = 86400
	rotated.OverlapSeconds = 3600
	rotated.OverlapUntil = "2026-01-01T01:00:00Z"
	rotated.RequestDigest = CertificateIntentDigest(rotated)
	recovered := rotated
	recovered.Kind = CertificateRecover
	recovered.TokenHash = strings.Repeat("d", 64)
	recovered.OverlapSeconds = 0
	recovered.OverlapUntil = recovered.AcceptedAt
	recovered.RequestDigest = CertificateIntentDigest(recovered)
	for _, record := range []CertificateRotationRecord{initial, rotated, recovered} {
		raw, _ := json.Marshal(record)
		if _, err := DecodeCertificateRotation(context.Background(), raw); err != nil {
			t.Fatal("valid envelope rejected", err)
		}
	}
	for _, change := range []func(*CertificateRotationRecord){func(r *CertificateRotationRecord) { r.SchemaVersion = "2" }, func(r *CertificateRotationRecord) { r.SensorID = "" }, func(r *CertificateRotationRecord) { r.Revision = 0 }, func(r *CertificateRotationRecord) { r.IssuerFingerprint = "forged" }, func(r *CertificateRotationRecord) { r.OverlapUntil = r.AcceptedAt }, func(r *CertificateRotationRecord) { r.TokenHash = strings.Repeat("d", 64) }, func(r *CertificateRotationRecord) { r.CSRDER = nil }, func(r *CertificateRotationRecord) { r.LifetimeSeconds = 1 << 62 }, func(r *CertificateRotationRecord) { r.OverlapSeconds = r.LifetimeSeconds }} {
		invalid := rotated
		change(&invalid)
		invalid.RequestDigest = CertificateIntentDigest(invalid)
		raw, _ := json.Marshal(invalid)
		if _, err := DecodeCertificateRotation(context.Background(), raw); err == nil {
			t.Fatal("invalid rotation envelope accepted")
		}
	}
	raw, _ := json.Marshal(rotated)
	raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
	if _, err := DecodeCertificateRotation(context.Background(), raw); err == nil {
		t.Fatal("unknown field accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeCertificateRotation(ctx, raw); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
}
