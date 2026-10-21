package storage

import (
	"context"
	"errors"
)

func (s *Store) recordsLocked(ctx context.Context) ([]Record, error) {
	if err := s.available(ctx); err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(s.state.Operations))
	for _, entry := range s.state.Operations {
		record, err := s.load(ctx, entry)
		if err != nil {
			if errors.Is(err, ErrRecovery) {
				s.poisoned = true
			}
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// Records returns an owned snapshot in generation order, bounded by store limits.
func (s *Store) Records(ctx context.Context) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordsLocked(ctx)
}

// Update selects a record against the full history under the writer lock, then
// uses the ordinary C05 publication path. The callback must not call this store.
// Returning an existing ID and identical bytes replays its original receipt.
func (s *Store) Update(ctx context.Context, choose func([]Record) (string, []byte, error)) (Receipt, error) {
	if choose == nil {
		return Receipt{}, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.recordsLocked(ctx)
	if err != nil {
		return Receipt{}, err
	}
	id, input, err := choose(records)
	if err != nil {
		return Receipt{}, err
	}
	return s.commitLocked(ctx, id, input, nil, false)
}
