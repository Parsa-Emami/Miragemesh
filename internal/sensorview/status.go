// Package sensorview builds a read-only projection of durable per-sensor state.
package sensorview

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

const (
	SchemaVersion = "1"
	OfflineAfter  = 5 * time.Minute
	configMissing = "missing"
	configExpired = "expired"
	configCurrent = "current"
)

var ErrInvalidInput = errors.New("sensor view: invalid input")

type Sensor struct {
	SensorID          string  `json:"sensor_id"`
	LastEventAt       *string `json:"last_event_at"`
	Offline           bool    `json:"offline"`
	ConfigStatus      string  `json:"config_status"`
	DroppedEventCount uint64  `json:"dropped_event_count"`
}

type Snapshot struct {
	SchemaVersion       string   `json:"schema_version"`
	OfflineAfterSeconds int      `json:"offline_after_seconds"`
	Sensors             []Sensor `json:"sensors"`
}

// BuildSnapshot trusts only committed C05 records and C11's verified applied
// configuration. It never writes to the store.
func BuildSnapshot(ctx context.Context, store *storage.Store, applier *sensor.Applier, now time.Time) (Snapshot, error) {
	if ctx == nil || store == nil || applier == nil || now.IsZero() {
		return Snapshot{}, ErrInvalidInput
	}
	records, err := store.Records(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	ids := make(map[string]struct{})
	latest := make(map[string]contracts.Event)
	losses := make(map[string]uint64)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		if record.Event.SchemaVersion != "" {
			ids[record.Event.SensorID] = struct{}{}
			if previous, ok := latest[record.Event.SensorID]; !ok || record.Event.Sequence > previous.Sequence {
				latest[record.Event.SensorID] = record.Event
			}
		}
		if record.Gap != nil {
			ids[record.Gap.SensorID] = struct{}{}
			if record.Receipt.OperationID != sensor.GapOperationID(record.Gap.SensorID, record.Gap.Sequence) {
				return Snapshot{}, storage.ErrRecovery
			}
			losses[record.Gap.SensorID]++
		}
		if record.Config != nil {
			document, err := config.Parse(record.Config.Payload)
			if err != nil {
				return Snapshot{}, storage.ErrRecovery
			}
			ids[document.SensorID] = struct{}{}
		}
	}
	active, err := applier.ActiveAll(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	out := Snapshot{SchemaVersion: SchemaVersion, OfflineAfterSeconds: int(OfflineAfter / time.Second), Sensors: make([]Sensor, 0, len(ordered))}
	for _, id := range ordered {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		status := Sensor{SensorID: id, Offline: true, ConfigStatus: configMissing}
		if event, ok := latest[id]; ok {
			observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
			if err != nil {
				return Snapshot{}, storage.ErrRecovery
			}
			stamp := event.ObservedAt
			status.LastEventAt = &stamp
			status.Offline = now.Sub(observed) > OfflineAfter
		}
		applied, exists := active[id]
		if exists {
			document, err := config.Parse(applied.Payload)
			if err != nil {
				return Snapshot{}, storage.ErrRecovery
			}
			status.ConfigStatus = configCurrent
			if !now.Before(document.ExpiresAt) {
				status.ConfigStatus = configExpired
			}
		}
		status.DroppedEventCount = losses[id]
		out.Sensors = append(out.Sensors, status)
	}
	return out, nil
}
