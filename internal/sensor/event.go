// Package sensor accepts validated sensor events into the existing local store.
package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidEvent = errors.New("invalid sensor event")
	ErrOutOfOrder   = errors.New("sensor sequence out of order")
)

func operationID(sensorID string, sequence int64) string {
	sum := sha256.Sum256([]byte(sensorID))
	return "sensor/" + hex.EncodeToString(sum[:]) + "/" + strconv.FormatInt(sequence, 10)
}

func sequenceCheck() func(storage.Record) error {
	type state struct {
		sequence int64
		eventIDs map[string]struct{}
	}
	sensors := make(map[string]*state)
	return func(record storage.Record) error {
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
	event, failure := contracts.DecodeEvent(ctx, input)
	if failure != nil {
		if ctx.Err() != nil {
			return storage.Receipt{}, ctx.Err()
		}
		return storage.Receipt{}, fmt.Errorf("%w: %v", ErrInvalidEvent, failure)
	}
	if event.Sequence < 1 {
		return storage.Receipt{}, ErrInvalidEvent
	}
	return store.CommitChecked(ctx, operationID(event.SensorID, event.Sequence), input, sequenceCheck())
}
