package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSpoolAckRecordValidation(t *testing.T) {
	valid := SpoolAckRecord{
		SchemaVersion: "1",
		Kind:          SpoolAck,
		SensorID:      "sensor-01",
		EventID:       "event-01",
		Sequence:      1,
		InputDigest:   strings.Repeat("a", 64),
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeSpoolAck(context.Background(), raw); err != nil || got != valid {
		t.Fatalf("valid ack: %+v %v", got, err)
	}
	for name, input := range map[string][]byte{
		"unsupported version": []byte(`{"schema_version":"2","kind":"spool.ack","sensor_id":"sensor-01","event_id":"event-01","sequence":1,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"wrong kind":          []byte(`{"schema_version":"1","kind":"spool.gap","sensor_id":"sensor-01","event_id":"event-01","sequence":1,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"empty sensor":        []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"","event_id":"event-01","sequence":1,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"empty event":         []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"sensor-01","event_id":"","sequence":1,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"invalid sequence":    []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"sensor-01","event_id":"event-01","sequence":0,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"invalid digest":      []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"sensor-01","event_id":"event-01","sequence":1,"input_digest":"not-a-digest"}`),
		"uppercase digest":    []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"sensor-01","event_id":"event-01","sequence":1,"input_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`),
		"unknown field":       []byte(`{"schema_version":"1","kind":"spool.ack","sensor_id":"sensor-01","event_id":"event-01","sequence":1,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}`),
		"non-canonical":       append(append([]byte(nil), raw...), ' '),
		"oversized":           []byte(strings.Repeat("a", MaxStoredInputBytes+1)),
	} {
		if _, err := DecodeSpoolAck(context.Background(), input); err == nil {
			t.Fatalf("%s: accepted invalid acknowledgement", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeSpoolAck(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}
