// Package collector accepts ordered sensor batches and durably acknowledges
// delivered events. It is an internal Go boundary: no transport, UI or
// authentication is added here.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidInput   = errors.New("collector: invalid input")
	ErrInvalidBatch   = errors.New("collector: invalid batch")
	ErrBatchTooLarge  = errors.New("collector: batch exceeds applied event_batch_limit")
	ErrSensorMismatch = errors.New("collector: event sensor does not match batch sensor")
)

// Batch is the internal delivery envelope. Its fields follow the existing
// OpenAPI batch contract, but Events carry the exact C04 bytes and are never
// re-marshaled. BatchID is correlation metadata; event identity is the dedup key.
type Batch struct {
	ID            string
	FirstSequence int64
	LastSequence  int64
	Events        [][]byte
}

type EventAcknowledgement struct {
	SensorID     string
	EventID      string
	Sequence     int64
	EventReceipt storage.Receipt
	AckReceipt   storage.Receipt
}

// Acknowledgement is returned only after every event and every ACK record is
// durable. A retry reconstructs the same per-event receipts.
type Acknowledgement struct {
	SensorID      string
	BatchID       string
	FirstSequence int64
	LastSequence  int64
	Events        []EventAcknowledgement
}

// Ingestor borrows its dependencies; their lifecycle remains with the caller.
type Ingestor struct {
	store   *storage.Store
	applier *sensor.Applier
}

func New(store *storage.Store, applier *sensor.Applier) (*Ingestor, error) {
	if store == nil || applier == nil || !applier.SameStore(store) {
		return nil, ErrInvalidInput
	}
	return &Ingestor{store: store, applier: applier}, nil
}

func validBatchID(id string) bool {
	return utf8.ValidString(id) && utf8.RuneCountInString(id) >= 1 && utf8.RuneCountInString(id) <= 4096
}

// Ingest validates the whole batch before the first visible write, accepts the
// events through the C07 identity rules and commits one durable spool.ack record
// per event. The spool event cap is intentionally not applied here: this path
// receives deliveries and acknowledges them, while spool.Enqueue owns the
// sensor-side pending bound.
func (i *Ingestor) Ingest(ctx context.Context, sensorID string, batch Batch) (Acknowledgement, error) {
	if i == nil || i.store == nil || i.applier == nil || !contracts.ValidSensorID(sensorID) {
		return Acknowledgement{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Acknowledgement{}, err
	}
	if !validBatchID(batch.ID) || len(batch.Events) == 0 ||
		batch.FirstSequence < 1 || batch.LastSequence < batch.FirstSequence ||
		batch.LastSequence > contracts.MaxSequence ||
		int64(len(batch.Events)) != batch.LastSequence-batch.FirstSequence+1 {
		return Acknowledgement{}, ErrInvalidBatch
	}

	// Own every input before validation so a caller cannot change bytes between
	// pre-validation, acceptance and acknowledgement.
	raw := make([][]byte, len(batch.Events))
	events := make([]contracts.Event, len(batch.Events))
	for n := range batch.Events {
		raw[n] = append([]byte(nil), batch.Events[n]...)
		event, failure := contracts.DecodeEvent(ctx, raw[n])
		if failure != nil {
			if ctx.Err() != nil {
				return Acknowledgement{}, ctx.Err()
			}
			return Acknowledgement{}, fmt.Errorf("%w: %w: %w", ErrInvalidBatch, sensor.ErrInvalidEvent, failure)
		}
		if event.Sequence < 1 {
			return Acknowledgement{}, fmt.Errorf("%w: %w", ErrInvalidBatch, sensor.ErrInvalidEvent)
		}
		if event.Sequence != batch.FirstSequence+int64(n) {
			return Acknowledgement{}, ErrInvalidBatch
		}
		if event.SensorID != sensorID {
			return Acknowledgement{}, fmt.Errorf("%w: %w", ErrInvalidBatch, ErrSensorMismatch)
		}
		events[n] = event
	}

	applied, exists, err := i.applier.Active(ctx, sensorID)
	if err != nil {
		return Acknowledgement{}, err
	}
	if !exists {
		return Acknowledgement{}, sensor.ErrUnconfigured
	}
	document, err := config.Parse(applied.Payload)
	if err != nil {
		return Acknowledgement{}, storage.ErrRecovery
	}
	if len(events) > document.Settings.EventBatchLimit {
		return Acknowledgement{}, ErrBatchTooLarge
	}

	records, err := i.store.Records(ctx)
	if err != nil {
		return Acknowledgement{}, err
	}
	if err := sensor.ValidateSequence(records, nil); err != nil {
		return Acknowledgement{}, err
	}

	type accepted struct {
		eventID string
		digest  string
	}
	stored := make(map[int64]accepted)
	for _, record := range records {
		if record.Event.SchemaVersion != "" && record.Event.SensorID == sensorID {
			stored[record.Event.Sequence] = accepted{eventID: record.Event.EventID, digest: record.Receipt.InputDigest}
		}
	}
	next := make([]contracts.Event, 0, len(events))
	digests := make([]string, len(events))
	for n, event := range events {
		sum := sha256.Sum256(raw[n])
		digests[n] = hex.EncodeToString(sum[:])
		if prior, ok := stored[event.Sequence]; ok {
			if prior.eventID != event.EventID || prior.digest != digests[n] {
				return Acknowledgement{}, fmt.Errorf("%w: %w", ErrInvalidBatch, storage.ErrConflict)
			}
			continue
		}
		next = append(next, event)
	}
	if err := sensor.ValidateSequence(records, next); err != nil {
		return Acknowledgement{}, fmt.Errorf("%w: %w", ErrInvalidBatch, err)
	}

	// Accept every event before acknowledging any of them. A storage failure can
	// leave a valid prefix, but no success result is returned until all ACKs below
	// are durable; a retry replays the prefix without creating duplicates.
	receipts := make([]storage.Receipt, len(events))
	for n := range events {
		if err := ctx.Err(); err != nil {
			return Acknowledgement{}, err
		}
		receipt, err := sensor.Accept(ctx, i.store, raw[n])
		if err != nil {
			return Acknowledgement{}, err
		}
		receipts[n] = receipt
	}

	ackReceipts := make([]storage.Receipt, len(events))
	for n, event := range events {
		if err := ctx.Err(); err != nil {
			return Acknowledgement{}, err
		}
		acknowledgement := contracts.SpoolAckRecord{
			SchemaVersion: contracts.SchemaVersion,
			Kind:          contracts.SpoolAck,
			SensorID:      event.SensorID,
			EventID:       event.EventID,
			Sequence:      event.Sequence,
			InputDigest:   digests[n],
		}
		encoded, err := json.Marshal(acknowledgement)
		if err != nil {
			return Acknowledgement{}, ErrInvalidInput
		}
		id := sensor.AckOperationID(event.SensorID, event.Sequence)
		receipt, err := i.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
			if err := sensor.ValidateSequence(records, nil); err != nil {
				return "", nil, err
			}
			found := false
			for _, record := range records {
				if record.Event.SchemaVersion != "" && record.Event.SensorID == event.SensorID && record.Event.Sequence == event.Sequence {
					if record.Event.EventID != event.EventID || record.Receipt.InputDigest != digests[n] {
						return "", nil, storage.ErrRecovery
					}
					found = true
					break
				}
			}
			if !found {
				return "", nil, storage.ErrRecovery
			}
			for _, record := range records {
				if record.Ack != nil && record.Ack.SensorID == event.SensorID && record.Ack.Sequence == event.Sequence {
					if record.Receipt.OperationID != id || record.Ack.EventID != event.EventID || record.Ack.InputDigest != digests[n] {
						return "", nil, storage.ErrConflict
					}
					return id, record.Input, nil
				}
			}
			return id, encoded, nil
		})
		if err != nil {
			return Acknowledgement{}, err
		}
		ackReceipts[n] = receipt
	}

	result := Acknowledgement{
		SensorID:      sensorID,
		BatchID:       batch.ID,
		FirstSequence: batch.FirstSequence,
		LastSequence:  batch.LastSequence,
		Events:        make([]EventAcknowledgement, len(events)),
	}
	for n, event := range events {
		result.Events[n] = EventAcknowledgement{
			SensorID:     event.SensorID,
			EventID:      event.EventID,
			Sequence:     event.Sequence,
			EventReceipt: receipts[n],
			AckReceipt:   ackReceipts[n],
		}
	}
	return result, nil
}
