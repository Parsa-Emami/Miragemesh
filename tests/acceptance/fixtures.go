// Package acceptance composes the existing engine boundaries into the local
// reference workflow. It adds no product transport: the TLS batch envelope in
// workflow.go is a test harness around the real C09 guard and C16 collector,
// not a published ingest protocol.
package acceptance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var ErrFixture = errors.New("acceptance: missing or malformed fixture")

type BoundsRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type Bounds struct {
	HeartbeatSeconds BoundsRange `json:"heartbeat_seconds"`
	SpoolLimitEvents BoundsRange `json:"spool_limit_events"`
	EventBatchLimit  BoundsRange `json:"event_batch_limit"`
}

func (b Bounds) configBounds() config.Bounds {
	return config.Bounds{
		MinHeartbeatSeconds: b.HeartbeatSeconds.Min, MaxHeartbeatSeconds: b.HeartbeatSeconds.Max,
		MinSpoolLimitEvents: b.SpoolLimitEvents.Min, MaxSpoolLimitEvents: b.SpoolLimitEvents.Max,
		MinEventBatchLimit: b.EventBatchLimit.Min, MaxEventBatchLimit: b.EventBatchLimit.Max,
	}
}

type EventSpec struct {
	EventID       string `json:"event_id"`
	Sequence      int64  `json:"sequence"`
	OffsetSeconds int64  `json:"offset_seconds"`
	Path          string `json:"path"`
}

type BatchSpec struct {
	ID            string `json:"id"`
	EventIndexes  []int  `json:"event_indexes"`
	FirstSequence int64  `json:"first_sequence"`
	LastSequence  int64  `json:"last_sequence"`
}

type ConfigSpec struct {
	Revision            int64 `json:"revision"`
	IssuedOffsetSeconds int64 `json:"issued_offset_seconds"`
	LifetimeSeconds     int64 `json:"lifetime_seconds"`
}

type TriageSpec struct {
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
}

type RetentionSpec struct {
	CutoffOffsetSeconds int64  `json:"cutoff_offset_seconds"`
	Reason              string `json:"reason"`
}

type IncidentSpec struct {
	RateLimit     int `json:"rate_limit"`
	WindowSeconds int `json:"window_seconds"`
}

type RotationSpec struct {
	MaxSensors            int   `json:"max_sensors"`
	MaxLifetimeSeconds    int64 `json:"max_lifetime_seconds"`
	MaxOverlapSeconds     int64 `json:"max_overlap_seconds"`
	MaxRecoveryTTLSeconds int64 `json:"max_recovery_ttl_seconds"`
}

type Positive struct {
	FixtureVersion      int                  `json:"fixture_version"`
	License             string               `json:"license"`
	Provenance          string               `json:"provenance"`
	SensorID            string               `json:"sensor_id"`
	StorageLimits       storage.Limits       `json:"storage_limits"`
	SegmentLimits       events.Limits        `json:"segment_limits"`
	ConfigMaxSensors    int                  `json:"config_max_sensors"`
	Bounds              Bounds               `json:"bounds"`
	Config              ConfigSpec           `json:"config"`
	EnrollmentTTLSecond int64                `json:"enrollment_ttl_seconds"`
	Settings            config.Settings      `json:"settings"`
	Events              []EventSpec          `json:"events"`
	Batches             map[string]BatchSpec `json:"batches"`
	OfflineEventIndexes []int                `json:"offline_event_indexes"`
	OverflowEventIndex  int                  `json:"overflow_event_index"`
	Triage              TriageSpec           `json:"triage"`
	Retention           RetentionSpec        `json:"retention"`
	Incident            IncidentSpec         `json:"incident"`
	Rotation            RotationSpec         `json:"rotation"`
}

type ExpectedLoss struct {
	Count uint64           `json:"count"`
	Gaps  []spool.GapRange `json:"gaps"`
}

type ExpectedSegments struct {
	Count          int      `json:"count"`
	Records        int64    `json:"records"`
	Ordinals       []uint64 `json:"ordinals"`
	SealedOrdinals []uint64 `json:"sealed_ordinals"`
}

type ExpectedRetention struct {
	Eligible         int  `json:"eligible"`
	CoverageComplete bool `json:"coverage_complete"`
}

type ExpectedSensor struct {
	ConfigStatus      string `json:"config_status"`
	DroppedEventCount uint64 `json:"dropped_event_count"`
	Offline           bool   `json:"offline"`
}

type Expected struct {
	FixtureVersion    int               `json:"fixture_version"`
	License           string            `json:"license"`
	Provenance        string            `json:"provenance"`
	Steps             []string          `json:"steps"`
	AcceptedSequences []int64           `json:"accepted_sequences"`
	AcknowledgedSeqs  []int64           `json:"acknowledged_sequences"`
	DroppedSequence   int64             `json:"dropped_sequence"`
	Loss              ExpectedLoss      `json:"loss"`
	Counts            map[string]int    `json:"counts"`
	Segments          ExpectedSegments  `json:"segments"`
	Retention         ExpectedRetention `json:"retention"`
	TriageEntries     int               `json:"triage_entries"`
	IncidentsMin      int               `json:"incidents_min"`
	Sensor            ExpectedSensor    `json:"sensor"`
}

type NegativeCase struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
}

type Negative struct {
	FixtureVersion int            `json:"fixture_version"`
	License        string         `json:"license"`
	Provenance     string         `json:"provenance"`
	SensorID       string         `json:"sensor_id"`
	MalformedEvent string         `json:"malformed_event"`
	Cases          []NegativeCase `json:"cases"`
}

// Fixtures is the complete repository-authored input of one C30 run.
type Fixtures struct {
	Positive Positive
	Expected Expected
	Negative Negative
	dir      string
}

// Load reads and validates the versioned C30 fixtures. Synthetic identity
// material is generated at run time and never comes from these files.
func Load(dir string) (Fixtures, error) {
	var f Fixtures
	f.dir = dir
	for name, target := range map[string]any{"positive": &f.Positive, "negative": &f.Negative, "expected-output": &f.Expected} {
		raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil || json.Unmarshal(raw, target) != nil {
			return Fixtures{}, ErrFixture
		}
	}
	if err := f.validate(); err != nil {
		return Fixtures{}, err
	}
	return f, nil
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrFixture, reason) }

func (f Fixtures) validate() error {
	p, e, n := f.Positive, f.Expected, f.Negative
	if p.FixtureVersion != 1 || e.FixtureVersion != 1 || n.FixtureVersion != 1 ||
		p.License != "Apache-2.0" || e.License != "Apache-2.0" || n.License != "Apache-2.0" ||
		p.Provenance == "" || e.Provenance == "" || n.Provenance == "" ||
		p.SensorID != "sensor-01" || n.SensorID != p.SensorID {
		return invalid("identity metadata")
	}
	if !contracts.ValidSensorID(p.SensorID) || p.StorageLimits.MaxOperations <= 0 || p.StorageLimits.MaxBytes <= 0 ||
		p.StorageLimits.MaxManifestBytes <= 0 || p.ConfigMaxSensors <= 0 || p.EnrollmentTTLSecond <= 0 {
		return invalid("storage or enrollment limits")
	}
	if p.SegmentLimits.MaxSegments <= 0 || p.SegmentLimits.MaxRecordsPerSegment <= 0 ||
		p.SegmentLimits.MaxBytesPerSegment < contracts.MaxInputBytes+1 {
		return invalid("segment limits")
	}
	if p.Settings.HeartbeatSeconds < p.Bounds.HeartbeatSeconds.Min || p.Settings.HeartbeatSeconds > p.Bounds.HeartbeatSeconds.Max ||
		p.Settings.SpoolLimitEvents < p.Bounds.SpoolLimitEvents.Min || p.Settings.SpoolLimitEvents > p.Bounds.SpoolLimitEvents.Max ||
		p.Settings.EventBatchLimit < p.Bounds.EventBatchLimit.Min || p.Settings.EventBatchLimit > p.Bounds.EventBatchLimit.Max ||
		p.Settings.EventBatchLimit > p.Settings.SpoolLimitEvents {
		return invalid("settings bounds")
	}
	if p.Config.Revision != 1 || p.Config.LifetimeSeconds <= 0 ||
		len(p.Triage.IdempotencyKey) < 16 || len(p.Triage.IdempotencyKey) > 128 ||
		p.Triage.Status == "" || p.Triage.Reason == "" ||
		p.Incident.RateLimit <= 0 || p.Incident.WindowSeconds <= 0 ||
		p.Rotation.MaxSensors <= 0 || p.Rotation.MaxLifetimeSeconds <= 0 ||
		p.Rotation.MaxOverlapSeconds <= 0 || p.Rotation.MaxRecoveryTTLSeconds <= 0 ||
		p.Rotation.MaxOverlapSeconds >= p.Rotation.MaxLifetimeSeconds {
		return invalid("config, triage or rotation policy")
	}
	if len(p.Events) != 5 || len(p.Batches) != 4 || len(p.OfflineEventIndexes) != 2 ||
		p.OverflowEventIndex < 0 || p.OverflowEventIndex >= len(p.Events) {
		return invalid("workflow shape")
	}
	for i, event := range p.Events {
		if event.EventID == "" || event.Sequence != int64(i+1) || event.Path == "" {
			return invalid("event identity")
		}
		if i > 0 && event.OffsetSeconds <= p.Events[i-1].OffsetSeconds {
			return invalid("event offsets")
		}
	}
	for _, name := range []string{"first", "reconnect", "duplicate", "resumed"} {
		spec, ok := p.Batches[name]
		if !ok || spec.ID == "" || len(spec.EventIndexes) == 0 || spec.FirstSequence <= 0 || spec.LastSequence < spec.FirstSequence {
			return invalid("batch " + name)
		}
		var low, high int64
		for i, index := range spec.EventIndexes {
			if index < 0 || index >= len(p.Events) || (i > 0 && index <= spec.EventIndexes[i-1]) {
				return invalid("batch index " + name)
			}
			if i == 0 {
				low = p.Events[index].Sequence
			}
			high = p.Events[index].Sequence
		}
		if low != spec.FirstSequence || high != spec.LastSequence {
			return invalid("batch sequences " + name)
		}
	}
	if p.Batches["reconnect"].ID != p.Batches["duplicate"].ID {
		return invalid("duplicate batch identity")
	}
	if len(e.Steps) != 8 || e.DroppedSequence != 4 || e.Loss.Count != 1 || len(e.Loss.Gaps) != 1 ||
		e.Loss.Gaps[0] != (spool.GapRange{From: 4, Through: 4}) ||
		e.Counts["config"] != 1 || e.Counts["event"] != 4 || e.Counts["ack"] != 4 || e.Counts["gap"] != 1 ||
		e.Segments.Count != 2 || e.Segments.Records != 4 || len(e.Segments.Ordinals) != 2 ||
		len(e.Segments.SealedOrdinals) != 1 || e.Segments.SealedOrdinals[0] != 1 ||
		e.Retention.Eligible != 0 || !e.Retention.CoverageComplete ||
		e.TriageEntries != 1 || e.IncidentsMin < 1 ||
		e.Sensor.ConfigStatus != "current" || e.Sensor.DroppedEventCount != 1 || e.Sensor.Offline {
		return invalid("expected outcome")
	}
	wantSteps := []string{"enroll", "apply-config", "event-01", "disconnect", "spool", "reconnect", "triage-retention", "restart-restore"}
	for i, step := range e.Steps {
		if step != wantSteps[i] {
			return invalid("expected steps")
		}
	}
	if len(e.AcceptedSequences) != 4 || len(e.AcknowledgedSeqs) != 4 {
		return invalid("expected sequences")
	}
	for i, sequence := range []int64{1, 2, 3, 5} {
		if e.AcceptedSequences[i] != sequence || e.AcknowledgedSeqs[i] != sequence {
			return invalid("expected sequence values")
		}
	}
	if len(e.Segments.Ordinals) != 2 || e.Segments.Ordinals[0] != 1 || e.Segments.Ordinals[1] != 2 {
		return invalid("expected segment ordinals")
	}
	if len(n.Cases) != 6 || n.MalformedEvent == "" {
		return invalid("negative cases")
	}
	wanted := map[string]string{
		"enrollment-token-replay":      "enrollment.ErrReplay",
		"untrusted-client-certificate": "tls.handshake_rejected",
		"unconfigured-batch-ingest":    "sensor.ErrUnconfigured",
		"malformed-event":              "contracts.INVALID_INPUT",
		"spool-overflow":               "spool.ErrDropped",
		"missing-fixture":              "acceptance.ErrFixture",
	}
	for _, c := range n.Cases {
		if wanted[c.Name] == "" || c.Expected != wanted[c.Name] {
			return invalid("negative case " + c.Name)
		}
	}
	return nil
}

func (f Fixtures) eventBytes(index int, now time.Time) ([]byte, error) {
	if index < 0 || index >= len(f.Positive.Events) {
		return nil, ErrFixture
	}
	spec := f.Positive.Events[index]
	event := contracts.Event{
		SchemaVersion: contracts.SchemaVersion,
		SensorID:      f.Positive.SensorID,
		EventID:       spec.EventID,
		Sequence:      spec.Sequence,
		ObservedAt:    now.Add(time.Duration(spec.OffsetSeconds) * time.Second).Format(time.RFC3339Nano),
		Kind:          "http.request",
		Metadata:      contracts.HTTPMetadata{Path: spec.Path},
	}
	return json.Marshal(event)
}

func (f Fixtures) envelope(name string, now time.Time) (batchEnvelope, error) {
	spec, ok := f.Positive.Batches[name]
	if !ok {
		return batchEnvelope{}, ErrFixture
	}
	envelope := batchEnvelope{BatchID: spec.ID, FirstSequence: spec.FirstSequence, LastSequence: spec.LastSequence}
	for _, index := range spec.EventIndexes {
		raw, err := f.eventBytes(index, now)
		if err != nil {
			return batchEnvelope{}, err
		}
		envelope.Events = append(envelope.Events, string(raw))
	}
	return envelope, nil
}
