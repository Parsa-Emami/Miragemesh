package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestUpdateRecordRejectsAmbiguousAndIncompleteEvidence(t *testing.T) {
	r := UpdateRecord{SchemaVersion: "1", Kind: UpdateMetadata, SensorID: "sensor-25", AcceptedAt: "2026-01-01T00:00:00Z", Payload: []byte(`{}`), Signature: make([]byte, 64)}
	raw, _ := json.Marshal(r)
	if _, err := DecodeUpdate(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*UpdateRecord){func(r *UpdateRecord) { r.SchemaVersion = "2" }, func(r *UpdateRecord) { r.Signature = nil }, func(r *UpdateRecord) { r.AcceptedAt = "2026-01-01T00:00:00+00:00" }, func(r *UpdateRecord) { r.Version = 4 }, func(r *UpdateRecord) { r.Payload = make([]byte, 8193) }, func(r *UpdateRecord) { r.Kind = UpdateVerified }} {
		n := r
		change(&n)
		raw, _ := json.Marshal(n)
		if _, err := DecodeUpdate(context.Background(), raw); err == nil {
			t.Fatal("incomplete record accepted")
		}
	}
	raw, _ = json.Marshal(r)
	for _, invalid := range [][]byte{append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"schema_version":"1"`), []byte(`"schema_version":"1","schema_version":"1"`), 1), bytes.Replace(raw, []byte(`"kind":`), []byte(`"unknown":1,"kind":`), 1)} {
		if _, err := DecodeUpdate(context.Background(), invalid); err == nil {
			t.Fatal("ambiguous record accepted")
		}
	}
}
