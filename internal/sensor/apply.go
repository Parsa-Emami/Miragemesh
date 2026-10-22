package sensor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// Applier reconciles signed desired state with the durable applied configuration.
// The visible manifest is authoritative; there is no second in-memory commit.
type Applier struct {
	store      *storage.Store
	validator  *config.Service
	now        func() time.Time
	maxSensors int
}

func configOperation(sensorID string, revision int64) string {
	hash := sha256.Sum256([]byte(sensorID))
	return "config/" + hex.EncodeToString(hash[:]) + "/" + strconv.FormatInt(revision, 10)
}

func NewApplier(ctx context.Context, store *storage.Store, verifier config.Verifier) (*Applier, error) {
	if store == nil {
		return nil, config.ErrInvalidInput
	}
	validator, err := config.New(verifier)
	if err != nil {
		return nil, err
	}
	a := &Applier{store: store, validator: validator, now: verifier.Clock, maxSensors: verifier.MaxSensors}
	records, err := store.Records(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = a.project(ctx, records); err != nil {
		return nil, err
	}
	return a, nil
}

// project authenticates history at each original acceptance time. An expired
// last-known configuration retains its revision floor; it is never readmitted.
func (a *Applier) project(ctx context.Context, records []storage.Record) (map[string]storage.Record, error) {
	latest := make(map[string]storage.Record)
	for _, record := range records {
		if record.Config == nil {
			continue
		}
		c := record.Config
		at, err := time.Parse(time.RFC3339Nano, c.AppliedAt)
		if err != nil {
			return nil, storage.ErrRecovery
		}
		doc, err := a.validator.VerifyAt(ctx, c.Payload, c.Signature, at)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil || record.Receipt.OperationID != configOperation(doc.SensorID, doc.Revision) {
			return nil, storage.ErrRecovery
		}
		if previous, ok := latest[doc.SensorID]; ok {
			prior, err := config.Parse(previous.Config.Payload)
			if err != nil || doc.Revision <= prior.Revision {
				return nil, storage.ErrRecovery
			}
		} else if len(latest) >= a.maxSensors {
			return nil, storage.ErrRecovery
		}
		latest[doc.SensorID] = record
	}
	return latest, nil
}

func applied(record storage.Record) config.Applied {
	doc, _ := config.Parse(record.Config.Payload)
	at, _ := time.Parse(time.RFC3339Nano, record.Config.AppliedAt)
	return config.Applied{SensorID: doc.SensorID, Revision: doc.Revision, Payload: append([]byte(nil), record.Config.Payload...), AppliedAt: at}
}

func (a *Applier) Apply(ctx context.Context, payload, signature []byte) (config.Applied, error) {
	if a == nil {
		return config.Applied{}, config.ErrInvalidInput
	}
	// Own the signed bytes before validation and persistence.
	payload = append([]byte(nil), payload...)
	signature = append([]byte(nil), signature...)
	if _, err := a.validator.VerifyAt(ctx, payload, signature, a.now()); err != nil {
		return config.Applied{}, err
	}
	var result config.Applied
	_, err := a.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		latest, err := a.project(ctx, records)
		if err != nil {
			return "", nil, err
		}
		now := a.now().UTC()
		doc, err := a.validator.VerifyAt(ctx, payload, signature, now)
		if err != nil {
			return "", nil, err
		}
		if current, ok := latest[doc.SensorID]; ok {
			prior := applied(current)
			if doc.Revision < prior.Revision {
				return "", nil, config.ErrStale
			}
			if doc.Revision == prior.Revision {
				if !bytes.Equal(payload, current.Config.Payload) {
					return "", nil, config.ErrConflict
				}
				result = prior
				return current.Receipt.OperationID, current.Input, nil
			}
		} else if len(latest) >= a.maxSensors {
			return "", nil, config.ErrQuota
		}
		stored := contracts.AppliedConfig{SchemaVersion: contracts.SchemaVersion, Kind: contracts.ConfigApplied, Payload: payload, Signature: signature, AppliedAt: now.Format(time.RFC3339Nano)}
		raw, err := json.Marshal(stored)
		if err != nil {
			return "", nil, config.ErrInvalidInput
		}
		result = config.Applied{SensorID: doc.SensorID, Revision: doc.Revision, Payload: payload, AppliedAt: now}
		return configOperation(doc.SensorID, doc.Revision), raw, nil
	})
	if err != nil {
		return config.Applied{}, err
	}
	return result, nil
}

// SameStore reports whether this applier reads the given store. Callers that
// combine config and event writes must reject a mismatched pair.
func (a *Applier) SameStore(store *storage.Store) bool {
	return a != nil && a.store == store
}

// ActiveAll rebuilds every observed applied configuration from one durable snapshot.
func (a *Applier) ActiveAll(ctx context.Context) (map[string]config.Applied, error) {
	if a == nil || a.store == nil {
		return nil, config.ErrInvalidInput
	}
	records, err := a.store.Records(ctx)
	if err != nil {
		return nil, err
	}
	latest, err := a.project(ctx, records)
	if err != nil {
		return nil, err
	}
	result := make(map[string]config.Applied, len(latest))
	for sensorID, record := range latest {
		result[sensorID] = applied(record)
	}
	return result, nil
}

// Active rebuilds the observed applied state from the current durable snapshot.
// Storage failures are explicit errors rather than a missing or stale cache hit.
func (a *Applier) Active(ctx context.Context, sensorID string) (config.Applied, bool, error) {
	if !contracts.ValidSensorID(sensorID) {
		return config.Applied{}, false, config.ErrInvalidInput
	}
	all, err := a.ActiveAll(ctx)
	if err != nil {
		return config.Applied{}, false, err
	}
	result, ok := all[sensorID]
	return result, ok, nil
}
