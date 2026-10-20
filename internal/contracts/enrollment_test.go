package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestEnrollmentRecordValidation(t *testing.T) {
	valid := EnrollmentRecord{SchemaVersion: "1", Kind: EnrollmentIssue, SensorID: "sensor-01", TokenHash: strings.Repeat("a", 64), IssuedAt: "2026-10-20T00:00:00Z", ExpiresAt: "2026-10-20T00:01:00Z"}
	raw, _ := json.Marshal(valid)
	if _, failure := DecodeEnrollment(context.Background(), raw); failure != nil {
		t.Fatal(failure)
	}
	cases := []struct {
		name   string
		change func(*EnrollmentRecord)
	}{
		{"version", func(r *EnrollmentRecord) { r.SchemaVersion = "2" }},
		{"unknown-kind", func(r *EnrollmentRecord) { r.Kind = "enrollment.forged" }},
		{"empty-scope", func(r *EnrollmentRecord) { r.SensorID = "" }},
		{"overlong-scope", func(r *EnrollmentRecord) { r.SensorID = strings.Repeat("x", 129) }},
		{"invalid-hash", func(r *EnrollmentRecord) { r.TokenHash = strings.Repeat("G", 64) }},
		{"short-hash", func(r *EnrollmentRecord) { r.TokenHash = "a" }},
		{"invalid-time", func(r *EnrollmentRecord) { r.IssuedAt = "invalid" }},
		{"non-utc-time", func(r *EnrollmentRecord) { r.IssuedAt = "2026-10-20T00:00:00+00:00" }},
		{"zero-time", func(r *EnrollmentRecord) { r.IssuedAt = "0001-01-01T00:00:00Z" }},
		{"reversed-time", func(r *EnrollmentRecord) { r.ExpiresAt = r.IssuedAt }},
		{"issue-has-consumption", func(r *EnrollmentRecord) { r.ConsumedAt = r.IssuedAt }},
		{"missing-consumption", func(r *EnrollmentRecord) { r.Kind = EnrollmentConsume }},
		{"expired-consumption", func(r *EnrollmentRecord) { r.Kind = EnrollmentConsume; r.ConsumedAt = r.ExpiresAt }},
		{"early-consumption", func(r *EnrollmentRecord) { r.Kind = EnrollmentConsume; r.ConsumedAt = "2026-10-19T23:59:59Z" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := valid
			c.change(&r)
			data, _ := json.Marshal(r)
			if _, failure := DecodeEnrollment(context.Background(), data); failure == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	for _, data := range [][]byte{
		[]byte("{"), []byte("null"), bytes.Repeat([]byte("x"), MaxInputBytes+1),
		append(append([]byte{}, raw...), ' '),
		bytes.Replace(raw, []byte(`"schema_version":"1"`), []byte(`"schema_version":"1","schema_version":"1"`), 1),
		bytes.Replace(raw, []byte(`"sensor_id":"sensor-01"`), []byte(`"sensor_id":"\ud800"`), 1),
		bytes.Replace(raw, []byte(`"kind"`), []byte(`"Kind"`), 1),
		bytes.Replace(raw, []byte(`"kind"`), []byte(`"token":"secret-sentinel","kind"`), 1),
	} {
		if _, failure := DecodeEnrollment(context.Background(), data); failure == nil {
			t.Fatal("noncanonical or malformed bytes accepted")
		}
	}
	valid.Kind = EnrollmentConsume
	valid.ConsumedAt = "2026-10-20T00:00:01Z"
	raw, _ = json.Marshal(valid)
	if _, failure := DecodeEnrollment(context.Background(), raw); failure != nil {
		t.Fatal(failure)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, failure := DecodeEnrollment(ctx, raw); failure == nil || failure.Code != Cancelled {
		t.Fatal("cancellation ignored")
	}
}
