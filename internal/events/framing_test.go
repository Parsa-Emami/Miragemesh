package events

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

func TestEncodedFramePreservesPayload(t *testing.T) {
	raw := []byte("{\n\"schema_version\":\"1\",\"sensor_id\":\"sensor\",\"event_id\":\"event\",\"sequence\":1,\"observed_at\":\"2026-01-01T00:00:00Z\",\"kind\":\"http.request\",\"metadata\":{\"path\":\"/\"}}")
	frame, _ := json.Marshal(raw)
	got, err := decodeFrame(frame)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("decode: %q %v", got, err)
	}
	if _, failure := contracts.DecodeEvent(context.Background(), got); failure != nil {
		t.Fatal(failure)
	}
}

func TestEncodedFrameRejectsMalformedAndOversizedPayloads(t *testing.T) {
	for _, frame := range [][]byte{[]byte(`"***"`), []byte(`"e30="`), []byte(`"e30=" `)} {
		if _, err := decodeFrame(frame); err == nil {
			t.Fatalf("accepted malformed encoded frame %q", frame)
		}
	}
	frame, _ := json.Marshal(bytes.Repeat([]byte{'\n'}, contracts.MaxInputBytes+1))
	if _, err := decodeFrame(frame); err == nil {
		t.Fatal("accepted oversized decoded payload")
	}
}
