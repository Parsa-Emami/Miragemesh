package incidentview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var ErrNotFound = errors.New("incidents: source-backed incident not found")
var ErrViewLimit = errors.New("incidents: replay exceeds local response limit")

const MaxViewBytes = 1048576
const MaxViewEvents = 256

type ReplayEvent struct {
	Source alerts.SourceRef `json:"source"`
	Event  contracts.Event  `json:"event"`
}

type TriageLabel struct {
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	TriagedAt string `json:"triaged_at"`
}

type ReplayIncident struct {
	ID      string        `json:"id"`
	Finding alerts.Alert  `json:"finding"`
	Events  []ReplayEvent `json:"events"`
	History []TriageLabel `json:"history"`
}

type MissingOrdinal struct {
	After  uint64 `json:"after"`
	Before uint64 `json:"before"`
}

type Coverage struct {
	Complete           bool             `json:"complete"`
	Missing            []MissingOrdinal `json:"missing_ordinals"`
	IncompleteSegments int              `json:"incomplete_segments"`
}

type ViewSnapshot struct {
	SchemaVersion     string           `json:"schema_version"`
	Coverage          Coverage         `json:"coverage"`
	UnprojectedEvents int              `json:"unprojected_events"`
	RateLimit         int              `json:"rate_limit"`
	WindowSeconds     int              `json:"window_seconds"`
	Incidents         []ReplayIncident `json:"incidents"`
}

type View struct {
	mu       sync.Mutex
	store    *storage.Store
	segments *events.Writer
	triage   *incidents.Service
	policy   alerts.Policy
}

func NewView(ctx context.Context, store *storage.Store, segments *events.Writer, policy alerts.Policy) (*View, error) {
	if ctx == nil || store == nil || segments == nil {
		return nil, incidents.ErrInvalidInput
	}
	if _, err := alerts.Evaluate(ctx, nil, nil, policy, true); err != nil {
		return nil, err
	}
	triage, err := incidents.New(ctx, store)
	if err != nil {
		return nil, err
	}
	return &View{store: store, segments: segments, triage: triage, policy: policy}, nil
}

func (v *View) Snapshot(ctx context.Context) (ViewSnapshot, error) {
	if v == nil || ctx == nil {
		return ViewSnapshot{}, incidents.ErrInvalidInput
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.snapshot(ctx)
}

func (v *View) snapshot(ctx context.Context) (ViewSnapshot, error) {
	index, err := v.segments.Index()
	if err != nil {
		return ViewSnapshot{}, err
	}
	if index.Records > MaxViewEvents {
		return ViewSnapshot{}, ErrViewLimit
	}
	records, err := v.store.Records(ctx)
	if err != nil {
		return ViewSnapshot{}, err
	}
	result := ViewSnapshot{SchemaVersion: "1", RateLimit: v.policy.RateLimit, WindowSeconds: int(v.policy.Window / time.Second), Incidents: []ReplayIncident{}, Coverage: Coverage{Complete: index.Complete, Missing: []MissingOrdinal{}, IncompleteSegments: len(index.Incomplete)}}
	for _, gap := range index.Missing {
		result.Coverage.Missing = append(result.Coverage.Missing, MissingOrdinal{After: gap.After, Before: gap.Before})
	}
	for _, record := range records {
		if record.Event.SchemaVersion == "" {
			continue
		}
		if entry, exists := index.Lookup(record.Event.SensorID, record.Event.EventID); !exists {
			result.UnprojectedEvents++
			result.Coverage.Complete = false
		} else {
			raw := bytes.TrimSuffix(record.Input, []byte{'\n'})
			sum := sha256.Sum256(raw)
			if entry.Sequence != record.Event.Sequence || entry.Digest != hex.EncodeToString(sum[:]) {
				return ViewSnapshot{}, events.ErrIndexConflict
			}
		}
	}
	sources := make([]alerts.Source, 0, index.Records)
	decoded := make(map[[2]string]contracts.Event)
	for _, entry := range index.Entries() {
		raw, err := v.segments.Read(ctx, entry)
		if err != nil {
			return ViewSnapshot{}, err
		}
		event, failure := contracts.DecodeEvent(ctx, raw)
		if failure != nil {
			return ViewSnapshot{}, events.ErrRecovery
		}
		sources = append(sources, alerts.Source{Raw: raw, Ref: entry})
		decoded[[2]string{event.SensorID, event.EventID}] = event
	}
	outcome, err := alerts.Evaluate(ctx, sources, nil, v.policy, result.Coverage.Complete)
	if err != nil {
		return ViewSnapshot{}, err
	}
	for _, finding := range append(outcome.Rates, outcome.Interactions...) {
		raw, err := json.Marshal(finding)
		if err != nil {
			return ViewSnapshot{}, err
		}
		sum := sha256.Sum256(raw)
		incident := ReplayIncident{ID: "incident-" + hex.EncodeToString(sum[:]), Finding: finding, Events: []ReplayEvent{}, History: []TriageLabel{}}
		for _, ref := range finding.Sources {
			incident.Events = append(incident.Events, ReplayEvent{Source: ref, Event: decoded[[2]string{ref.SensorID, ref.EventID}]})
		}
		history, err := v.triage.History(ctx, incident.ID)
		if err != nil {
			return ViewSnapshot{}, err
		}
		for _, entry := range history {
			incident.History = append(incident.History, TriageLabel{Status: entry.Status, Reason: entry.Reason, TriagedAt: entry.TriagedAt.UTC().Format(time.RFC3339Nano)})
		}
		result.Incidents = append(result.Incidents, incident)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return ViewSnapshot{}, err
	}
	if len(encoded) > MaxViewBytes {
		return ViewSnapshot{}, ErrViewLimit
	}
	return result, nil
}

func (v *View) Triage(ctx context.Context, id, key string, body []byte) (incidents.Result, error) {
	if v == nil || ctx == nil {
		return incidents.Result{}, incidents.ErrInvalidInput
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	snapshot, err := v.snapshot(ctx)
	if err != nil {
		return incidents.Result{}, err
	}
	for _, incident := range snapshot.Incidents {
		if incident.ID == id {
			return v.triage.Triage(ctx, id, key, body)
		}
	}
	return incidents.Result{}, ErrNotFound
}
