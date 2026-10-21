package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestAppliedConfigRecordValidation(t *testing.T) {
	record := AppliedConfig{SchemaVersion: SchemaVersion, Kind: ConfigApplied, Payload: []byte("{\"signed\": true} \n"), Signature: bytes.Repeat([]byte{1}, 64), AppliedAt: "2026-10-21T00:00:00Z"}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAppliedConfig(context.Background(), raw)
	if err != nil || !bytes.Equal(got.Payload, record.Payload) || !bytes.Equal(got.Signature, record.Signature) {
		t.Fatal("exact payload or signature lost", err)
	}
	for _, kind := range []string{"version", "kind", "empty-payload", "oversized-payload", "short-signature", "invalid-time", "offset-time", "zero-time"} {
		t.Run(kind, func(t *testing.T) {
			bad := record
			switch kind {
			case "version":
				bad.SchemaVersion = "2"
			case "kind":
				bad.Kind = "event"
			case "empty-payload":
				bad.Payload = nil
			case "oversized-payload":
				bad.Payload = bytes.Repeat([]byte("x"), MaxInputBytes+1)
			case "short-signature":
				bad.Signature = []byte{1}
			case "invalid-time":
				bad.AppliedAt = "bad"
			case "offset-time":
				bad.AppliedAt = "2026-10-21T01:00:00+01:00"
			case "zero-time":
				bad.AppliedAt = "0001-01-01T00:00:00Z"
			}
			encoded, _ := json.Marshal(bad)
			if _, err := DecodeAppliedConfig(context.Background(), encoded); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("{"), append(append([]byte{}, raw...), ' '), bytes.Replace(raw, []byte(`"kind":"config.applied"`), []byte(`"kind":"config.applied","kind":"config.applied"`), 1), bytes.Replace(raw, []byte(`"kind":"config.applied"`), []byte(`"Kind":"config.applied"`), 1), bytes.Replace(raw, []byte(`"kind":"config.applied"`), []byte(`"kind":"config.applied","unexpected":true`), 1), bytes.Repeat([]byte(" "), MaxStoredInputBytes+1)} {
		if _, err := DecodeAppliedConfig(context.Background(), bad); err == nil {
			t.Fatal("noncanonical record accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeAppliedConfig(ctx, raw); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
}
