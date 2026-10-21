package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"unicode/utf8"
)

const SpoolAck = "spool.ack"

// SpoolAckRecord durably records that one accepted event was delivered to the
// collector. It is an append-only C05 record, not a replacement for the event.
type SpoolAckRecord struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	SensorID      string `json:"sensor_id"`
	EventID       string `json:"event_id"`
	Sequence      int64  `json:"sequence"`
	InputDigest   string `json:"input_digest"`
}

// DecodeSpoolAck validates the canonical internal acknowledgement record.
func DecodeSpoolAck(ctx context.Context, raw []byte) (SpoolAckRecord, error) {
	if err := ctx.Err(); err != nil {
		return SpoolAckRecord{}, err
	}
	var record SpoolAckRecord
	if len(raw) > MaxStoredInputBytes || json.Unmarshal(raw, &record) != nil {
		return SpoolAckRecord{}, &ValidationError{Code: InvalidInput}
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(raw, canonical) || record.SchemaVersion != SchemaVersion || record.Kind != SpoolAck || !ValidSensorID(record.SensorID) || utf8.RuneCountInString(record.EventID) < 1 || utf8.RuneCountInString(record.EventID) > 128 || record.Sequence < 1 || record.Sequence > MaxSequence || len(record.InputDigest) != 64 {
		return SpoolAckRecord{}, &ValidationError{Code: InvalidInput}
	}
	for _, c := range record.InputDigest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return SpoolAckRecord{}, &ValidationError{Code: InvalidInput}
		}
	}
	return record, nil
}
