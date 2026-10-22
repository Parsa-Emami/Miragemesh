// Package alerts derives explainable, read-only findings from committed event
// references and explicit sensor-health evidence.
package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
)

var (
	ErrInvalidInput   = errors.New("alerts: invalid input")
	ErrInvalidPolicy  = errors.New("alerts: invalid rate policy")
	ErrInvalidSource  = errors.New("alerts: invalid source event")
	ErrSourceConflict = errors.New("alerts: source reference conflict")
)

const (
	ClassInteraction  = "interaction"
	ClassAttackSignal = "attack_signal"
	ClassSensorHealth = "sensor_health"
)

// Policy is supplied by trusted local configuration. No rate threshold is
// selected by the engine.
type Policy struct {
	RateLimit int
	Window    time.Duration
}

// Source binds the exact accepted C04 bytes to their C18 index location.
type Source struct {
	Raw []byte
	Ref events.Entry
}

// SensorHealth contains durable C15 loss evidence, not an inference from
// missing events.
type SensorHealth struct {
	SensorID      string
	DroppedEvents uint64
	GapSequences  []int64
}

type SourceRef struct {
	SensorID string `json:"sensor_id"`
	EventID  string `json:"event_id"`
	Sequence int64  `json:"sequence"`
	Segment  string `json:"segment"`
	Record   int64  `json:"record"`
	Digest   string `json:"digest"`
}

type Alert struct {
	Class         string      `json:"class"`
	SensorID      string      `json:"sensor_id"`
	Explanation   string      `json:"explanation"`
	Count         int         `json:"count,omitempty"`
	WindowSeconds int         `json:"window_seconds,omitempty"`
	ObservedFrom  string      `json:"observed_from,omitempty"`
	ObservedTo    string      `json:"observed_to,omitempty"`
	Sources       []SourceRef `json:"sources,omitempty"`
	GapSequences  []int64     `json:"gap_sequences,omitempty"`
}

type Outcome struct {
	CoverageComplete bool    `json:"coverage_complete"`
	RateLimit        int     `json:"rate_limit"`
	WindowSeconds    int     `json:"window_seconds"`
	Interactions     []Alert `json:"interactions"`
	Rates            []Alert `json:"rates"`
	SensorHealth     []Alert `json:"sensor_health"`
}

type decodedSource struct {
	ref      SourceRef
	observed time.Time
	identity string
}

func Evaluate(ctx context.Context, sources []Source, health []SensorHealth, policy Policy, coverageComplete bool) (Outcome, error) {
	if ctx == nil {
		return Outcome{}, ErrInvalidInput
	}
	if policy.RateLimit <= 0 || policy.Window <= 0 || policy.Window%time.Second != 0 || int64(policy.Window/time.Second) > int64(int(^uint(0)>>1)) {
		return Outcome{}, ErrInvalidPolicy
	}
	outcome := Outcome{
		CoverageComplete: coverageComplete,
		RateLimit:        policy.RateLimit,
		WindowSeconds:    int(policy.Window / time.Second),
		Interactions:     []Alert{},
		Rates:            []Alert{},
		SensorHealth:     []Alert{},
	}
	decoded := make([]decodedSource, 0, len(sources))
	seen := make(map[string]SourceRef, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		event, failure := contracts.DecodeEvent(ctx, source.Raw)
		if failure != nil {
			return Outcome{}, ErrInvalidSource
		}
		sum := sha256.Sum256(source.Raw)
		digest := hex.EncodeToString(sum[:])
		if source.Ref.Digest != digest || source.Ref.Bytes != int64(len(source.Raw)) || source.Ref.Record < 1 || source.Ref.Segment == "" {
			return Outcome{}, ErrSourceConflict
		}
		if event.SensorID != source.Ref.SensorID || event.EventID != source.Ref.EventID || event.Sequence != source.Ref.Sequence {
			return Outcome{}, ErrSourceConflict
		}
		observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
		if err != nil {
			return Outcome{}, ErrInvalidSource
		}
		key := event.SensorID + "\x00" + event.EventID
		ref := SourceRef{
			SensorID: source.Ref.SensorID,
			EventID:  source.Ref.EventID,
			Sequence: source.Ref.Sequence,
			Segment:  source.Ref.Segment,
			Record:   source.Ref.Record,
			Digest:   source.Ref.Digest,
		}
		if previous, exists := seen[key]; exists {
			if previous != ref {
				return Outcome{}, ErrSourceConflict
			}
			continue
		}
		seen[key] = ref
		decoded = append(decoded, decodedSource{ref: ref, observed: observed, identity: key})
	}
	sort.Slice(decoded, func(i, j int) bool {
		if decoded[i].ref.SensorID != decoded[j].ref.SensorID {
			return decoded[i].ref.SensorID < decoded[j].ref.SensorID
		}
		if !decoded[i].observed.Equal(decoded[j].observed) {
			return decoded[i].observed.Before(decoded[j].observed)
		}
		if decoded[i].ref.Sequence != decoded[j].ref.Sequence {
			return decoded[i].ref.Sequence < decoded[j].ref.Sequence
		}
		return decoded[i].ref.EventID < decoded[j].ref.EventID
	})
	bySensor := make(map[string][]decodedSource)
	for _, source := range decoded {
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		bySensor[source.ref.SensorID] = append(bySensor[source.ref.SensorID], source)
		outcome.Interactions = append(outcome.Interactions, Alert{
			Class:       ClassInteraction,
			SensorID:    source.ref.SensorID,
			Explanation: "An HTTP request interaction was observed; this alone does not establish malicious activity.",
			Sources:     []SourceRef{source.ref},
		})
	}
	sensors := make([]string, 0, len(bySensor))
	for sensorID := range bySensor {
		sensors = append(sensors, sensorID)
	}
	sort.Strings(sensors)
	for _, sensorID := range sensors {
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		events := bySensor[sensorID]
		bestStart, bestEnd := 0, 0
		start := 0
		for end := range events {
			for start <= end && events[end].observed.Sub(events[start].observed) > policy.Window {
				start++
			}
			if end-start+1 > bestEnd-bestStart+1 {
				bestStart, bestEnd = start, end
			}
		}
		count := bestEnd - bestStart + 1
		if count < policy.RateLimit {
			continue
		}
		refs := make([]SourceRef, 0, count)
		for _, source := range events[bestStart : bestEnd+1] {
			refs = append(refs, source.ref)
		}
		outcome.Rates = append(outcome.Rates, Alert{
			Class:         ClassAttackSignal,
			SensorID:      sensorID,
			Explanation:   fmt.Sprintf("Observed %d HTTP requests within the configured %d-second rate window; this is an attack signal for review, not proof of an attack.", count, outcome.WindowSeconds),
			Count:         count,
			WindowSeconds: outcome.WindowSeconds,
			ObservedFrom:  events[bestStart].observed.UTC().Format(time.RFC3339Nano),
			ObservedTo:    events[bestEnd].observed.UTC().Format(time.RFC3339Nano),
			Sources:       refs,
		})
	}
	seenHealth := make(map[string]bool, len(health))
	for _, signal := range health {
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		if !contracts.ValidSensorID(signal.SensorID) || signal.DroppedEvents == 0 || signal.DroppedEvents > uint64(int(^uint(0)>>1)) || uint64(len(signal.GapSequences)) != signal.DroppedEvents || seenHealth[signal.SensorID] {
			return Outcome{}, ErrInvalidInput
		}
		seenHealth[signal.SensorID] = true
		sequences := append([]int64(nil), signal.GapSequences...)
		sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
		for i, sequence := range sequences {
			if sequence < 1 || i > 0 && sequence == sequences[i-1] {
				return Outcome{}, ErrInvalidInput
			}
		}
		outcome.SensorHealth = append(outcome.SensorHealth, Alert{
			Class:        ClassSensorHealth,
			SensorID:     signal.SensorID,
			Explanation:  fmt.Sprintf("The durable offline spool records %d dropped event(s); the missing event bytes are not available as source events.", signal.DroppedEvents),
			Count:        int(signal.DroppedEvents),
			GapSequences: sequences,
		})
	}
	sort.Slice(outcome.SensorHealth, func(i, j int) bool { return outcome.SensorHealth[i].SensorID < outcome.SensorHealth[j].SensorID })
	return outcome, nil
}
