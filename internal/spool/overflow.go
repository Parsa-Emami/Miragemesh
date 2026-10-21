package spool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var ErrDropped = errors.New("spool dropped event at capacity")

type DroppedError struct {
	SensorID string
	EventID  string
	Sequence int64
}

func (e *DroppedError) Error() string {
	return fmt.Sprintf("%v: sensor %q sequence %d", ErrDropped, e.SensorID, e.Sequence)
}

func (e *DroppedError) Unwrap() error { return ErrDropped }

type GapRange struct {
	From    int64 `json:"from"`
	Through int64 `json:"through"`
}

type LossSummary struct {
	SensorID string     `json:"sensor_id"`
	Count    uint64     `json:"count"`
	Gaps     []GapRange `json:"gaps"`
}

// Losses rebuilds the per-sensor loss count and compact contiguous gap ranges
// from the C05 history, so the result survives process restart.
func (s *Store) Losses(ctx context.Context, sensorID string) (LossSummary, error) {
	if s == nil || s.store == nil || !contracts.ValidSensorID(sensorID) {
		return LossSummary{}, ErrInvalidInput
	}
	records, err := s.store.Records(ctx)
	if err != nil {
		return LossSummary{}, err
	}
	result := LossSummary{SensorID: sensorID, Gaps: []GapRange{}}
	for _, record := range records {
		if record.Gap == nil || record.Gap.SensorID != sensorID {
			continue
		}
		if record.Receipt.OperationID != sensor.GapOperationID(sensorID, record.Gap.Sequence) {
			return LossSummary{}, storage.ErrRecovery
		}
		result.Count++
		sequence := record.Gap.Sequence
		last := len(result.Gaps) - 1
		if last >= 0 && sequence == result.Gaps[last].Through+1 {
			result.Gaps[last].Through = sequence
		} else {
			result.Gaps = append(result.Gaps, GapRange{From: sequence, Through: sequence})
		}
	}
	return result, nil
}

// enqueueOverflow changes only the full-spool outcome; the admission,
// configuration and sequence checks remain in the shared sensor transaction.
func (s *Store) enqueueOverflow(ctx context.Context, input []byte) (storage.Receipt, error) {
	if s == nil || s.store == nil || s.applier == nil {
		return storage.Receipt{}, ErrInvalidInput
	}
	dropped := false
	var droppedEvent contracts.Event
	receipt, err := sensor.AcceptBoundedWithOverflow(ctx, s.store, input, s.applier, func(event contracts.Event, raw []byte) (string, []byte, error) {
		dropped = true
		droppedEvent = event
		digest := sha256.Sum256(raw)
		marker := contracts.SpoolGapRecord{
			SchemaVersion: contracts.SchemaVersion,
			Kind:          contracts.SpoolGap,
			SensorID:      event.SensorID,
			EventID:       event.EventID,
			Sequence:      event.Sequence,
			InputDigest:   hex.EncodeToString(digest[:]),
		}
		encoded, err := json.Marshal(marker)
		if err != nil {
			return "", nil, ErrInvalidInput
		}
		return sensor.GapOperationID(event.SensorID, event.Sequence), encoded, nil
	})
	if err != nil {
		return storage.Receipt{}, err
	}
	if dropped {
		return storage.Receipt{}, &DroppedError{SensorID: droppedEvent.SensorID, EventID: droppedEvent.EventID, Sequence: droppedEvent.Sequence}
	}
	return receipt, nil
}
