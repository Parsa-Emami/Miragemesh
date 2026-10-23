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

// AckOperationID is stable across retries of one delivered sensor sequence.
func AckOperationID(sensorID string, sequence int64) string {
	sum := sha256.Sum256([]byte(sensorID))
	return "spool-ack/" + hex.EncodeToString(sum[:]) + "/" + strconv.FormatInt(sequence, 10)
}

func sequenceCheck() func(storage.Record) error {
	type accepted struct {
		eventID string
		digest  string
	}
	type state struct {
		sequence int64
		eventIDs map[string]struct{}
		events   map[int64]accepted
		acked    map[int64]struct{}
	}
	sensors := make(map[string]*state)
	stateFor := func(sensorID string) *state {
		previous := sensors[sensorID]
		if previous == nil {
			previous = &state{eventIDs: make(map[string]struct{}), events: make(map[int64]accepted), acked: make(map[int64]struct{})}
			sensors[sensorID] = previous
		}
		return previous
	}
	return func(record storage.Record) error {
		if record.Enrollment != nil || record.Config != nil || record.Incident != nil || record.Rotation != nil {
			return nil
		}
		if record.Gap != nil {
			if record.Receipt.OperationID != GapOperationID(record.Gap.SensorID, record.Gap.Sequence) {
				return storage.ErrRecovery
			}
			previous := stateFor(record.Gap.SensorID)
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
		if record.Ack != nil {
			ack := record.Ack
			if record.Receipt.OperationID != AckOperationID(ack.SensorID, ack.Sequence) {
				return storage.ErrRecovery
			}
			previous := sensors[ack.SensorID]
			if previous == nil {
				return storage.ErrRecovery
			}
			event, exists := previous.events[ack.Sequence]
			if !exists || event.eventID != ack.EventID || event.digest != ack.InputDigest {
				return storage.ErrRecovery
			}
			if _, exists := previous.acked[ack.Sequence]; exists {
				return storage.ErrConflict
			}
			previous.acked[ack.Sequence] = struct{}{}
			return nil
		}
		if record.Event.SchemaVersion == "" {
			return storage.ErrRecovery
		}
		previous := stateFor(record.Event.SensorID)
		if record.Event.Sequence != previous.sequence+1 {
			return ErrOutOfOrder
		}
		if _, exists := previous.eventIDs[record.Event.EventID]; exists {
			return storage.ErrConflict
		}
		previous.sequence = record.Event.Sequence
		previous.eventIDs[record.Event.EventID] = struct{}{}
		previous.events[record.Event.Sequence] = accepted{eventID: record.Event.EventID, digest: record.Receipt.InputDigest}
		return nil
	}
}

// ValidateSequence checks persisted records followed by already-decoded, new
// events. Exact replays must be filtered by the caller before this check.
func ValidateSequence(records []storage.Record, next []contracts.Event) error {
	check := sequenceCheck()
	for _, record := range records {
		if err := check(record); err != nil {
			return err
		}
	}
	for _, event := range next {
		if event.SchemaVersion == "" {
			return ErrInvalidEvent
		}
		if err := check(storage.Record{Event: event}); err != nil {
			return err
		}
	}
	return nil
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
		pending, replay, droppedReplay := 0, false, false
		acked := make(map[int64]struct{})
		for _, record := range records {
			if err := check(record); err != nil {
				return "", nil, err
			}
			if record.Ack != nil && record.Ack.SensorID == event.SensorID {
				acked[record.Ack.Sequence] = struct{}{}
			}
			if record.Event.SchemaVersion != "" && record.Event.SensorID == event.SensorID {
				pending++
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
		// Only unacknowledged retained events consume the signed spool bound.
		// C16 ACK records are append-only checkpoints and never delete events.
		pending -= len(acked)
		if pending >= document.Settings.SpoolLimitEvents {
			if overflow != nil {
				return overflow(event, input)
			}
			return "", nil, storage.ErrQuota
		}
		return id, input, nil
	})
}
