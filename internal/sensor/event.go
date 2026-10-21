// Package sensor accepts validated sensor events into the existing local store.
package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidEvent = errors.New("invalid sensor event")
	ErrOutOfOrder   = errors.New("sensor sequence out of order")
	ErrUnconfigured = errors.New("spool has no applied configuration")
)

func operationID(sensorID string, sequence int64) string {
	sum := sha256.Sum256([]byte(sensorID))
	return "sensor/" + hex.EncodeToString(sum[:]) + "/" + strconv.FormatInt(sequence, 10)
}

// GapOperationID is stable across retries of one omitted sensor sequence.
func GapOperationID(sensorID string, sequence int64) string {
	sum := sha256.Sum256([]byte(sensorID))
	return "spool-gap/" + hex.EncodeToString(sum[:]) + "/" + strconv.FormatInt(sequence, 10)
}

func sequenceCheck() func(storage.Record) error {
	type state struct {
		sequence int64
		eventIDs map[string]struct{}
	}
	sensors := make(map[string]*state)
	return func(record storage.Record) error {
		if record.Enrollment != nil || record.Config != nil {
			return nil
		}
		if record.Gap != nil {
			if record.Receipt.OperationID != GapOperationID(record.Gap.SensorID, record.Gap.Sequence) {
				return storage.ErrRecovery
			}
			previous := sensors[record.Gap.SensorID]
			if previous == nil {
				previous = &state{eventIDs: make(map[string]struct{})}
				sensors[record.Gap.SensorID] = previous
			}
			if record.Gap.Sequence != previous.sequence+1 {
				return ErrOutOfOrder
			}
			if _, exists := previous.eventIDs[record.Gap.EventID]; exists {
				return storage.ErrConflict
			}
			previous.sequence = record.Gap.Sequence
			previous.eventIDs[record.Gap.EventID] = struct{}{}
			return nil
		}
		if record.Event.SchemaVersion == "" {
			return storage.ErrRecovery
		}
		previous := sensors[record.Event.SensorID]
		if previous == nil {
			previous = &state{eventIDs: make(map[string]struct{})}
			sensors[record.Event.SensorID] = previous
		}
		if record.Event.Sequence != previous.sequence+1 {
			return ErrOutOfOrder
		}
		if _, exists := previous.eventIDs[record.Event.EventID]; exists {
			return storage.ErrConflict
		}
		previous.sequence = record.Event.Sequence
		previous.eventIDs[record.Event.EventID] = struct{}{}
		return nil
	}
}

// Accept validates and durably records one event. Exact retries return the
// original receipt; a new event must immediately follow the persisted sequence.
func Accept(ctx context.Context, store *storage.Store, input []byte) (storage.Receipt, error) {
	if store == nil {
		return storage.Receipt{}, ErrInvalidEvent
	}
	event, err := decodeEvent(ctx, input)
	if err != nil {
		return storage.Receipt{}, err
	}
	return store.CommitChecked(ctx, operationID(event.SensorID, event.Sequence), input, sequenceCheck())
}

func decodeEvent(ctx context.Context, input []byte) (contracts.Event, error) {
	event, failure := contracts.DecodeEvent(ctx, input)
	if failure != nil {
		if ctx.Err() != nil {
			return contracts.Event{}, ctx.Err()
		}
		return contracts.Event{}, fmt.Errorf("%w: %v", ErrInvalidEvent, failure)
	}
	if event.Sequence < 1 {
		return contracts.Event{}, ErrInvalidEvent
	}
	return event, nil
}

// AcceptBounded uses the current authenticated applied setting and event count
// in one C05 writer transaction. The applier must belong to this same store.
func AcceptBounded(ctx context.Context, store *storage.Store, input []byte, applier *Applier) (storage.Receipt, error) {
	return AcceptBoundedWithOverflow(ctx, store, input, applier, nil)
}

// AcceptBoundedWithOverflow lets the spool persist a typed gap under the same
// C05 writer transaction when the signed per-sensor event limit is reached.
func AcceptBoundedWithOverflow(ctx context.Context, store *storage.Store, input []byte, applier *Applier, overflow func(contracts.Event, []byte) (string, []byte, error)) (storage.Receipt, error) {
	if store == nil || applier == nil || applier.store != store {
		return storage.Receipt{}, config.ErrInvalidInput
	}
	event, err := decodeEvent(ctx, input)
	if err != nil {
		return storage.Receipt{}, err
	}
	input = append([]byte(nil), input...)
	id := operationID(event.SensorID, event.Sequence)
	return store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		latest, err := applier.project(ctx, records)
		if err != nil {
			return "", nil, err
		}
		current, exists := latest[event.SensorID]
		if !exists {
			return "", nil, ErrUnconfigured
		}
		document, err := config.Parse(current.Config.Payload)
		if err != nil {
			return "", nil, storage.ErrRecovery
		}
		check := sequenceCheck()
		count, replay, droppedReplay := 0, false, false
		for _, record := range records {
			if err := check(record); err != nil {
				return "", nil, err
			}
			if record.Config == nil && record.Enrollment == nil && record.Gap == nil && record.Event.SensorID == event.SensorID {
				count++
			}
			replay = replay || record.Receipt.OperationID == id
			droppedReplay = droppedReplay || (record.Gap != nil && record.Gap.SensorID == event.SensorID && record.Gap.Sequence == event.Sequence)
		}
		if replay {
			return id, input, nil
		}
		if droppedReplay {
			if overflow == nil {
				return "", nil, ErrOutOfOrder
			}
			return overflow(event, input)
		}
		if err := check(storage.Record{Event: event}); err != nil {
			return "", nil, err
		}
		// All retained events are pending until C16 adds durable ACK/reclamation.
		if count >= document.Settings.SpoolLimitEvents {
			if overflow != nil {
				return overflow(event, input)
			}
			return "", nil, storage.ErrQuota
		}
		return id, input, nil
	})
}
