package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"unicode/utf8"
)

const SpoolGap = "spool.gap"

// SpoolGapRecord durably records one event omitted by a full offline spool.
type SpoolGapRecord struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	SensorID      string `json:"sensor_id"`
	EventID       string `json:"event_id"`
	Sequence      int64  `json:"sequence"`
	InputDigest   string `json:"input_digest"`
}

// DecodeSpoolGap validates the canonical internal gap record.
func DecodeSpoolGap(ctx context.Context, raw []byte) (SpoolGapRecord, error) {
	if err := ctx.Err(); err != nil {
		return SpoolGapRecord{}, err
	}
	var record SpoolGapRecord
	if len(raw) > MaxStoredInputBytes || json.Unmarshal(raw, &record) != nil {
		return SpoolGapRecord{}, &ValidationError{Code: InvalidInput}
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(raw, canonical) || record.SchemaVersion != SchemaVersion || record.Kind != SpoolGap || !ValidSensorID(record.SensorID) || utf8.RuneCountInString(record.EventID) < 1 || utf8.RuneCountInString(record.EventID) > 128 || record.Sequence < 1 || record.Sequence > MaxSequence || len(record.InputDigest) != 64 {
		return SpoolGapRecord{}, &ValidationError{Code: InvalidInput}
	}
	for _, c := range record.InputDigest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return SpoolGapRecord{}, &ValidationError{Code: InvalidInput}
		}
	}
	return record, nil
}
