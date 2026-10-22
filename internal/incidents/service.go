// Package incidents persists append-only incident triage labels. It never
// accepts or rewrites observed event content.
package incidents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidInput = errors.New("incidents: invalid input")
	ErrConflict     = errors.New("incidents: idempotency key reused for a different request")
)

const (
	minIdempotencyKeyRunes = 16
	maxIdempotencyKeyRunes = 128
)

// Entry is one durable triage label for an incident.
type Entry struct {
	IncidentID string
	Status     string
	Reason     string
	TriagedAt  time.Time
}

// Result is the typed outcome of a triage request. Replayed reports that an
// existing operation was returned without publishing a new generation.
type Result struct {
	Entry    Entry
	Receipt  storage.Receipt
	Replayed bool
}

// Service records triage labels through the existing C05 store. The store is
// the single authority; no incident content is cached in memory.
type Service struct {
	store *storage.Store
	now   func() time.Time
}

// New validates existing triage history before serving requests.
func New(ctx context.Context, store *storage.Store) (*Service, error) {
	if ctx == nil || store == nil {
		return nil, ErrInvalidInput
	}
	records, err := store.Records(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Incident == nil {
			continue
		}
		if err := validateStored(record); err != nil {
			return nil, err
		}
	}
	return &Service{store: store, now: time.Now}, nil
}

// Triage persists one status and reason for an incident. The request body uses
// the private contract's exact shape: only status and reason, at most 4096 code
// points each. Unknown or duplicate members are rejected, so event content
// cannot be smuggled into a triage request.
func (s *Service) Triage(ctx context.Context, incidentID, idempotencyKey string, body []byte) (Result, error) {
	if s == nil || s.store == nil || ctx == nil {
		return Result{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !contracts.ValidIncidentID(incidentID) || !validIdempotencyKey(idempotencyKey) {
		return Result{}, ErrInvalidInput
	}
	status, reason, err := decodeBody(ctx, body)
	if err != nil {
		return Result{}, err
	}
	keyHash := keyDigest(idempotencyKey)
	operation := operationID(incidentID, keyHash)
	var committed []byte
	replayed := false
	receipt, err := s.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		for _, record := range records {
			if record.Receipt.OperationID != operation {
				continue
			}
			if err := validateStored(record); err != nil {
				return "", nil, err
			}
			if record.Incident.IncidentID != incidentID || record.Incident.Status != status || record.Incident.Reason != reason {
				return "", nil, ErrConflict
			}
			replayed = true
			committed = append([]byte(nil), record.Input...)
			return operation, record.Input, nil
		}
		record := contracts.IncidentTriageRecord{
			SchemaVersion: contracts.SchemaVersion,
			Kind:          contracts.IncidentTriage,
			IncidentID:    incidentID,
			Status:        status,
			Reason:        reason,
			KeyDigest:     keyHash,
			TriagedAt:     s.now().UTC().Format(time.RFC3339Nano),
		}
		raw, err := json.Marshal(record)
		if err != nil || len(raw) > contracts.MaxStoredInputBytes {
			return "", nil, ErrInvalidInput
		}
		committed = raw
		return operation, raw, nil
	})
	if err != nil {
		return Result{}, err
	}
	record, err := contracts.DecodeIncidentTriage(context.Background(), committed)
	if err != nil {
		return Result{}, storage.ErrRecovery
	}
	at, err := time.Parse(time.RFC3339Nano, record.TriagedAt)
	if err != nil {
		return Result{}, storage.ErrRecovery
	}
	return Result{
		Entry: Entry{
			IncidentID: record.IncidentID,
			Status:     record.Status,
			Reason:     record.Reason,
			TriagedAt:  at,
		},
		Receipt:  receipt,
		Replayed: replayed,
	}, nil
}

// History returns the durable triage labels of one incident in publication
// order. The last entry is the current status.
func (s *Service) History(ctx context.Context, incidentID string) ([]Entry, error) {
	if s == nil || s.store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if !contracts.ValidIncidentID(incidentID) {
		return nil, ErrInvalidInput
	}
	records, err := s.store.Records(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	for _, record := range records {
		if record.Incident == nil {
			continue
		}
		if err := validateStored(record); err != nil {
			return nil, err
		}
		if record.Incident.IncidentID != incidentID {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, record.Incident.TriagedAt)
		if err != nil {
			return nil, storage.ErrRecovery
		}
		entries = append(entries, Entry{
			IncidentID: record.Incident.IncidentID,
			Status:     record.Incident.Status,
			Reason:     record.Incident.Reason,
			TriagedAt:  at,
		})
	}
	return entries, nil
}

func validateStored(record storage.Record) error {
	if record.Incident == nil || record.Receipt.OperationID != operationID(record.Incident.IncidentID, record.Incident.KeyDigest) {
		return storage.ErrRecovery
	}
	return nil
}

func keyDigest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func operationID(incidentID, keyHash string) string {
	sum := sha256.Sum256([]byte(incidentID + "\x00" + keyHash))
	return "incident-triage/" + hex.EncodeToString(sum[:])
}

func validIdempotencyKey(key string) bool {
	return utf8.ValidString(key) && utf8.RuneCountInString(key) >= minIdempotencyKeyRunes && utf8.RuneCountInString(key) <= maxIdempotencyKeyRunes
}

func decodeBody(ctx context.Context, raw []byte) (string, string, error) {
	if ctx == nil {
		return "", "", ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if len(raw) == 0 || len(raw) > contracts.MaxStoredInputBytes || !utf8.Valid(raw) || !json.Valid(raw) || !contracts.ValidUnicodeEscapes(raw) {
		return "", "", ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", "", ErrInvalidInput
	}
	fields := make(map[string]json.RawMessage, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", "", ErrInvalidInput
		}
		name, ok := token.(string)
		if !ok || (name != "status" && name != "reason") {
			return "", "", ErrInvalidInput
		}
		if _, exists := fields[name]; exists {
			return "", "", ErrInvalidInput
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return "", "", ErrInvalidInput
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return "", "", ErrInvalidInput
	}
	var status, reason string
	if len(fields) != 2 || json.Unmarshal(fields["status"], &status) != nil || json.Unmarshal(fields["reason"], &reason) != nil {
		return "", "", ErrInvalidInput
	}
	if !validText(status, contracts.MaxIncidentStatusRunes) || !validText(reason, contracts.MaxIncidentReasonRunes) {
		return "", "", ErrInvalidInput
	}
	return status, reason, nil
}

func validText(value string, max int) bool {
	count := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && count >= 1 && count <= max
}
