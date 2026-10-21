package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestSpoolGapRecordValidation(t *testing.T) {
	valid := SpoolGapRecord{SchemaVersion: "1", Kind: SpoolGap, SensorID: "sensor-01", EventID: "event-03", Sequence: 3, InputDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeSpoolGap(context.Background(), raw); err != nil || got != valid {
		t.Fatalf("valid gap: %+v %v", got, err)
	}
	for name, input := range map[string][]byte{
		"unsupported version": []byte(`{"schema_version":"2","kind":"spool.gap","sensor_id":"sensor-01","event_id":"event-03","sequence":3,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"invalid sequence":    []byte(`{"schema_version":"1","kind":"spool.gap","sensor_id":"sensor-01","event_id":"event-03","sequence":0,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		"invalid digest":      []byte(`{"schema_version":"1","kind":"spool.gap","sensor_id":"sensor-01","event_id":"event-03","sequence":3,"input_digest":"not-a-digest"}`),
		"unknown field":       []byte(`{"schema_version":"1","kind":"spool.gap","sensor_id":"sensor-01","event_id":"event-03","sequence":3,"input_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}`),
		"noncanonical":        append(append([]byte(nil), raw...), ' '),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSpoolGap(context.Background(), input); err == nil {
				t.Fatal("invalid gap accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeSpoolGap(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
