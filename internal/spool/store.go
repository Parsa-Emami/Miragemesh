// Package spool retains bounded offline events through the existing C05 store.
package spool

import (
	"context"
	"errors"

	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidInput = errors.New("invalid spool input")
	ErrUnconfigured = sensor.ErrUnconfigured
)

// Store borrows its dependencies; their lifecycle remains with the caller.
type Store struct {
	store   *storage.Store
	applier *sensor.Applier
}

func New(store *storage.Store, applier *sensor.Applier) (*Store, error) {
	if store == nil || applier == nil {
		return nil, ErrInvalidInput
	}
	return &Store{store: store, applier: applier}, nil
}

// Enqueue returns a receipt only after durable publication. Exact retries
// reuse that receipt even at capacity; overflow never deletes accepted bytes.
func (s *Store) Enqueue(ctx context.Context, input []byte) (storage.Receipt, error) {
	if s == nil {
		return storage.Receipt{}, ErrInvalidInput
	}
	return s.enqueueOverflow(ctx, input)
}
