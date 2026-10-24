package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c28Bounds struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type c28Settings struct {
	HeartbeatSeconds int `json:"heartbeat_seconds"`
	SpoolLimitEvents int `json:"spool_limit_events"`
	EventBatchLimit  int `json:"event_batch_limit"`
}

type c28Config struct {
	Revision   int64       `json:"revision"`
	IssuedAt   string      `json:"issued_at"`
	ExpiresAt  string      `json:"expires_at"`
	MaxSensors int         `json:"max_sensors"`
	Settings   c28Settings `json:"settings"`
	Bounds     struct {
		HeartbeatSeconds c28Bounds `json:"heartbeat_seconds"`
		SpoolLimitEvents c28Bounds `json:"spool_limit_events"`
		EventBatchLimit  c28Bounds `json:"event_batch_limit"`
	} `json:"bounds"`
}

type c28Target struct {
	Sensors     int `json:"sensors"`
	SteadyPhase struct {
		DurationSeconds int `json:"duration_seconds"`
		EventsPerSecond int `json:"events_per_second"`
		BatchSize       int `json:"batch_size"`
	} `json:"steady_phase"`
	BacklogPhase struct {
		Events    int `json:"events"`
		BatchSize int `json:"batch_size"`
	} `json:"backlog_phase"`
	Config c28Config `json:"config"`
	Event  struct {
		Kind          string `json:"kind"`
		MetadataBytes int    `json:"metadata_bytes"`
		ObservedAt    string `json:"observed_at"`
	} `json:"event"`
	StorageLimits storage.Limits `json:"storage_limits"`
	SegmentLimits struct {
		MaxSegments          int   `json:"max_segments"`
		MaxRecordsPerSegment int64 `json:"max_records_per_segment"`
		MaxBytesPerSegment   int64 `json:"max_bytes_per_segment"`
	} `json:"segment_limits"`
	Alerts struct {
		RateLimit     int `json:"rate_limit"`
		WindowSeconds int `json:"window_seconds"`
	} `json:"alerts"`
	HTTP struct {
		WarmupRequests   int      `json:"warmup_requests"`
		RequestsPerLevel int      `json:"requests_per_level"`
		Levels           []int    `json:"levels"`
		SaturationLevel  int      `json:"saturation_level"`
		SaturationP99MS  int      `json:"saturation_p99_ms"`
		Endpoints        []string `json:"endpoints"`
	} `json:"http"`
	Regression struct {
		EventsPerSensor int `json:"events_per_sensor"`
		BatchSize       int `json:"batch_size"`
	} `json:"regression"`
}

type c28Scenario struct {
	SchemaVersion  int    `json:"schema_version"`
	FixtureVersion int    `json:"fixture_version"`
	Status         string `json:"status"`
	Task           string `json:"task"`
	Title          string `json:"title"`
	Profile        string `json:"profile"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	HardwareTarget struct {
		VCPU        int `json:"vcpu"`
		MemoryMiB   int `json:"memory_mib"`
		FreeDiskMiB int `json:"free_disk_mib"`
	} `json:"hardware_target"`
	PublishedCapacity struct {
		Sensors         int `json:"sensors"`
		EventsPerSecond int `json:"events_per_second"`
	} `json:"published_capacity"`
	Target    c28Target `json:"target"`
	OverLimit struct {
		RateProbe struct {
			EventsPerSecond int `json:"events_per_second"`
			DurationSeconds int `json:"duration_seconds"`
			BatchSize       int `json:"batch_size"`
		} `json:"rate_probe"`
		BatchProbe struct {
			BatchSize         int    `json:"batch_size"`
			AppliedBatchLimit int    `json:"applied_batch_limit"`
			ExpectedError     string `json:"expected_error"`
		} `json:"batch_probe"`
		StorageProbe struct {
			Sensors       int            `json:"sensors"`
			Events        int            `json:"events"`
			BatchSize     int            `json:"batch_size"`
			StorageLimits storage.Limits `json:"storage_limits"`
			ExpectedError string         `json:"expected_error"`
		} `json:"storage_probe"`
		HTTPSaturation struct {
			Concurrency int `json:"concurrency"`
			Requests    int `json:"requests"`
		} `json:"http_saturation"`
	} `json:"over_limit"`
	Cancellation struct {
		BatchSize         int  `json:"batch_size"`
		CancelAfterChecks int  `json:"cancel_after_checks"`
		Retry             bool `json:"retry"`
	} `json:"cancellation"`
	Restart struct {
		Checks []string `json:"checks"`
	} `json:"restart"`
	Fixtures      []string `json:"fixtures"`
	NegativeCases []string `json:"negative_cases"`
}

type c28Positive struct {
	FixtureVersion int      `json:"fixture_version"`
	License        string   `json:"license"`
	Provenance     string   `json:"provenance"`
	Sensors        []string `json:"sensors"`
	Samples        []string `json:"samples"`
	Batch          struct {
		BatchID       string   `json:"batch_id"`
		SensorID      string   `json:"sensor_id"`
		FirstSequence int64    `json:"first_sequence"`
		LastSequence  int64    `json:"last_sequence"`
		Events        []string `json:"events"`
	} `json:"batch"`
	ConfigPayload string         `json:"config_payload"`
	StorageLimits storage.Limits `json:"storage_limits"`
	Expected      struct {
		SamplesAccepted int `json:"samples_accepted"`
		BatchAccepted   int `json:"batch_accepted"`
	} `json:"expected"`
}

type c28Generate struct {
	SensorID      string `json:"sensor_id"`
	FirstSequence int64  `json:"first_sequence"`
	Count         int    `json:"count"`
	PathBytes     int    `json:"path_bytes"`
}

type c28BatchEnvelope struct {
	BatchID       string `json:"batch_id"`
	SensorID      string `json:"sensor_id"`
	FirstSequence int64  `json:"first_sequence"`
	LastSequence  int64  `json:"last_sequence"`
}

type c28NegativeCase struct {
	Name            string           `json:"name"`
	Kind            string           `json:"kind"`
	ExpectedIs      string           `json:"expected_is"`
	Seed            []string         `json:"seed"`
	Input           string           `json:"input"`
	Batch           c28BatchEnvelope `json:"batch"`
	Events          []string         `json:"events"`
	Generate        *c28Generate     `json:"generate"`
	StorageLimits   *storage.Limits  `json:"storage_limits"`
	RequestedEvents int              `json:"requested_events"`
}

type c28Negative struct {
	FixtureVersion int               `json:"fixture_version"`
	License        string            `json:"license"`
	Provenance     string            `json:"provenance"`
	SensorCount    int               `json:"sensor_count"`
	Cases          []c28NegativeCase `json:"cases"`
}

type c28Expected struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Regression     struct {
		Sensors         int   `json:"sensors"`
		EventsPerSensor int   `json:"events_per_sensor"`
		BatchSize       int   `json:"batch_size"`
		Batches         int   `json:"batches"`
		Events          int   `json:"events"`
		Acks            int   `json:"acks"`
		AppliedRevision int64 `json:"applied_revision"`
	} `json:"regression"`
	Target struct {
		Sensors                      int   `json:"sensors"`
		SteadyEvents                 int   `json:"steady_events"`
		BacklogEvents                int   `json:"backlog_events"`
		TotalEvents                  int   `json:"total_events"`
		TotalAcks                    int   `json:"total_acks"`
		Configs                      int   `json:"configs"`
		IngestCalls                  int   `json:"ingest_calls"`
		PerSensorSequences           int   `json:"per_sensor_sequences"`
		AppliedRevision              int64 `json:"applied_revision"`
		Segments                     int   `json:"segments"`
		IndexRecordsFirstProjection  int   `json:"index_records_first_projection"`
		IndexRecordsAfterRestart     int   `json:"index_records_after_restart"`
		IndexSensorsAfterRestart     int   `json:"index_sensors_after_restart"`
		SkippedNonEvents             int   `json:"skipped_non_events"`
		Appended                     int   `json:"appended"`
		AlreadyProjectedAfterRestart int   `json:"already_projected_after_restart"`
		AppendedAfterRestart         int   `json:"appended_after_restart"`
	} `json:"target"`
	OverLimit struct {
		RateProbe struct {
			EventsPerSecond int `json:"events_per_second"`
			DurationSeconds int `json:"duration_seconds"`
			PlannedEvents   int `json:"planned_events"`
			CompletedMax    int `json:"completed_max"`
		} `json:"rate_probe"`
		BatchProbe struct {
			BatchSize int    `json:"batch_size"`
			Error     string `json:"error"`
		} `json:"batch_probe"`
		StorageProbe struct {
			RequestedEvents int    `json:"requested_events"`
			BatchSize       int    `json:"batch_size"`
			AcceptedBetween []int  `json:"accepted_between"`
			Error           string `json:"error"`
		} `json:"storage_probe"`
	} `json:"over_limit"`
	Cancellation struct {
		BatchSize       int    `json:"batch_size"`
		Error           string `json:"error"`
		AcksBeforeRetry int    `json:"acks_before_retry"`
		RetryEvents     int    `json:"retry_events"`
		RetryAcks       int    `json:"retry_acks"`
	} `json:"cancellation"`
	Negatives struct {
		Count int `json:"count"`
	} `json:"negatives"`
}

type c28Latency struct {
	Count  int     `json:"count"`
	MinMS  float64 `json:"min_ms"`
	MeanMS float64 `json:"mean_ms"`
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	P99MS  float64 `json:"p99_ms"`
	MaxMS  float64 `json:"max_ms"`
}

type c28Phase struct {
	PlannedEvents   int        `json:"planned_events"`
	CompletedEvents int        `json:"completed_events"`
	Batches         int        `json:"batches"`
	ElapsedMS       float64    `json:"elapsed_ms"`
	EventsPerSecond float64    `json:"events_per_second"`
	Latency         c28Latency `json:"latency"`
}

type c28TypeError struct {
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Matched  bool   `json:"matched"`
}

type c28StorageProbe struct {
	Requested int    `json:"requested"`
	Accepted  int    `json:"accepted"`
	Acks      int    `json:"acks"`
	Error     string `json:"error"`
	Matched   bool   `json:"matched"`
}

type c28RateProbe struct {
	PlannedEvents   int        `json:"planned_events"`
	CompletedEvents int        `json:"completed_events"`
	ElapsedMS       float64    `json:"elapsed_ms"`
	EventsPerSecond float64    `json:"events_per_second"`
	Latency         c28Latency `json:"latency"`
}

type c28Cancellation struct {
	Error             string `json:"error"`
	Matched           bool   `json:"matched"`
	EventsBeforeRetry int    `json:"events_before_retry"`
	AcksBeforeRetry   int    `json:"acks_before_retry"`
	RetryEvents       int    `json:"retry_events"`
	RetryAcks         int    `json:"retry_acks"`
}

type c28Restart struct {
	Events          int    `json:"events"`
	Acks            int    `json:"acks"`
	AppliedRevision int64  `json:"applied_revision"`
	ManifestSHA256  string `json:"manifest_sha256"`
}

type c28NegativeResult struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Matched  bool   `json:"matched"`
	Wrote    bool   `json:"wrote"`
}

type c28Regression struct {
	Events        int  `json:"events"`
	Acks          int  `json:"acks"`
	ReplayMatched bool `json:"replay_matched"`
}

type c28Measurement struct {
	Phase           string              `json:"phase"`
	Task            string              `json:"task"`
	Scenario        string              `json:"scenario"`
	Sensors         int                 `json:"sensors"`
	Events          int                 `json:"events"`
	Acks            int                 `json:"acks"`
	Configs         int                 `json:"configs"`
	IngestCalls     int                 `json:"ingest_calls"`
	Steady          c28Phase            `json:"steady"`
	Backlog         c28Phase            `json:"backlog"`
	AppliedRevision int64               `json:"applied_revision"`
	ManifestSHA256  string              `json:"manifest_sha256"`
	BatchProbe      *c28TypeError       `json:"batch_probe,omitempty"`
	RateProbe       *c28RateProbe       `json:"rate_probe,omitempty"`
	StorageProbe    *c28StorageProbe    `json:"storage_probe,omitempty"`
	Cancellation    *c28Cancellation    `json:"cancellation,omitempty"`
	Restart         *c28Restart         `json:"restart,omitempty"`
	Negatives       []c28NegativeResult `json:"negatives,omitempty"`
	Regression      *c28Regression      `json:"regression,omitempty"`
}

func c28Read(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing C28 fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("malformed C28 fixture %s: %v", path, err)
	}
}

func c28Validate(scenario c28Scenario, positive c28Positive, negative c28Negative, expected c28Expected) error {
	if scenario.SchemaVersion != 1 || scenario.FixtureVersion != 1 || scenario.Task != "C28" || scenario.Status != "defined" || scenario.Profile == "" {
		return errors.New("unsupported C28 scenario metadata")
	}
	if scenario.License != "Apache-2.0" || scenario.Provenance == "" || scenario.Title == "" {
		return errors.New("C28 scenario requires license, provenance and title")
	}
	if scenario.HardwareTarget.VCPU <= 0 || scenario.HardwareTarget.MemoryMiB <= 0 || scenario.HardwareTarget.FreeDiskMiB <= 0 {
		return errors.New("C28 hardware target must be positive")
	}
	if scenario.PublishedCapacity.Sensors <= 0 || scenario.PublishedCapacity.EventsPerSecond <= 0 {
		return errors.New("C28 published capacity must be positive")
	}
	target := scenario.Target
	if target.Sensors <= 0 || target.Sensors != scenario.PublishedCapacity.Sensors || target.Sensors != len(positive.Sensors) {
		return errors.New("C28 target sensors must match the published cap and positive fixture")
	}
	if target.SteadyPhase.DurationSeconds <= 0 || target.SteadyPhase.EventsPerSecond <= 0 || target.SteadyPhase.BatchSize != 1 {
		return errors.New("C28 steady phase requires a positive duration/rate and batch size 1")
	}
	if target.SteadyPhase.EventsPerSecond != scenario.PublishedCapacity.EventsPerSecond {
		return errors.New("C28 steady rate must exercise the published events_per_second")
	}
	if target.BacklogPhase.Events <= 0 || target.BacklogPhase.BatchSize <= 0 || target.BacklogPhase.Events%target.Sensors != 0 {
		return errors.New("C28 backlog must be positive and divisible by the sensor count")
	}
	perSensor := target.BacklogPhase.Events / target.Sensors
	if (perSensor+target.BacklogPhase.BatchSize-1)/target.BacklogPhase.BatchSize <= 0 {
		return errors.New("C28 backlog requires at least one batch per sensor")
	}
	if target.Config.Settings.EventBatchLimit <= 0 || target.BacklogPhase.BatchSize > target.Config.Settings.EventBatchLimit {
		return errors.New("C28 backlog batch must fit the signed batch limit")
	}
	if target.StorageLimits.MaxOperations <= 0 || target.StorageLimits.MaxBytes <= 0 || target.StorageLimits.MaxManifestBytes <= 0 {
		return errors.New("C28 target storage limits must be positive")
	}
	if target.SegmentLimits.MaxSegments <= 0 || target.SegmentLimits.MaxRecordsPerSegment <= 0 || target.SegmentLimits.MaxBytesPerSegment <= contracts.MaxInputBytes {
		return errors.New("C28 segment limits must be positive and above the event input bound")
	}
	if target.Alerts.RateLimit <= 0 || target.Alerts.WindowSeconds <= 0 {
		return errors.New("C28 projection requires an explicit alert policy")
	}
	if len(target.HTTP.Endpoints) == 0 || len(target.HTTP.Levels) == 0 || target.HTTP.RequestsPerLevel <= 0 || target.HTTP.SaturationLevel <= 0 || target.HTTP.SaturationP99MS <= 0 {
		return errors.New("C28 HTTP measurement policy is incomplete")
	}
	for _, endpoint := range target.HTTP.Endpoints {
		if !strings.HasPrefix(endpoint, "/") || strings.Contains(endpoint, "..") {
			return fmt.Errorf("C28 endpoint is not a local path: %q", endpoint)
		}
	}
	steady := target.SteadyPhase.DurationSeconds * target.SteadyPhase.EventsPerSecond
	if scenario.OverLimit.RateProbe.EventsPerSecond <= 0 || scenario.OverLimit.RateProbe.DurationSeconds <= 0 || scenario.OverLimit.RateProbe.BatchSize != 1 {
		return errors.New("C28 rate probe is incomplete")
	}
	if scenario.OverLimit.RateProbe.EventsPerSecond <= scenario.PublishedCapacity.EventsPerSecond {
		return errors.New("C28 rate probe must exceed the published rate")
	}
	if scenario.OverLimit.BatchProbe.BatchSize <= target.Config.Settings.EventBatchLimit {
		return errors.New("C28 batch probe must exceed the signed batch limit")
	}
	if scenario.OverLimit.StorageProbe.Events <= 0 || scenario.OverLimit.StorageProbe.BatchSize <= 0 || scenario.OverLimit.StorageProbe.Sensors <= 0 {
		return errors.New("C28 storage probe is incomplete")
	}
	if scenario.OverLimit.StorageProbe.StorageLimits.MaxBytes <= 0 || scenario.OverLimit.StorageProbe.StorageLimits.MaxOperations <= 0 {
		return errors.New("C28 storage probe requires explicit quotas")
	}
	if scenario.Cancellation.BatchSize <= 0 || scenario.Cancellation.CancelAfterChecks <= 0 || !scenario.Cancellation.Retry {
		return errors.New("C28 cancellation policy is incomplete")
	}
	if len(scenario.Restart.Checks) == 0 {
		return errors.New("C28 restart checks are required")
	}
	if len(scenario.Fixtures) != 3 {
		return errors.New("C28 scenario must reference the three fixture files")
	}
	if positive.FixtureVersion != 1 || negative.FixtureVersion != 1 || expected.FixtureVersion != 1 {
		return errors.New("C28 fixture version must be 1")
	}
	if positive.License != "Apache-2.0" || negative.License != "Apache-2.0" || expected.License != "Apache-2.0" ||
		positive.Provenance == "" || negative.Provenance == "" || expected.Provenance == "" {
		return errors.New("C28 fixtures require license and provenance")
	}
	if len(positive.Samples) != positive.Expected.SamplesAccepted || len(positive.Samples) == 0 {
		return errors.New("C28 positive sample count is inconsistent")
	}
	if len(positive.Batch.Events) != positive.Expected.BatchAccepted || positive.Batch.LastSequence-positive.Batch.FirstSequence+1 != int64(len(positive.Batch.Events)) {
		return errors.New("C28 positive batch is inconsistent")
	}
	if _, failure := config.Parse([]byte(positive.ConfigPayload)); failure != nil {
		return fmt.Errorf("C28 positive config payload is invalid: %w", failure)
	}
	if len(negative.Cases) != expected.Negatives.Count || negative.SensorCount <= 0 || negative.SensorCount > len(positive.Sensors) {
		return errors.New("C28 negative fixture count is inconsistent")
	}
	seen := map[string]bool{}
	for _, testCase := range negative.Cases {
		if testCase.Name == "" || seen[testCase.Name] {
			return fmt.Errorf("C28 negative case name is missing or duplicated: %q", testCase.Name)
		}
		seen[testCase.Name] = true
		if _, ok := c28ExpectedError(testCase.ExpectedIs); !ok {
			return fmt.Errorf("C28 negative case %s has unknown expected error %q", testCase.Name, testCase.ExpectedIs)
		}
		switch testCase.Kind {
		case "event":
			if testCase.Input == "" && testCase.Generate == nil {
				return fmt.Errorf("C28 negative case %s requires input or generate", testCase.Name)
			}
		case "batch":
			if testCase.Batch.BatchID == "" || testCase.Batch.SensorID == "" || testCase.Batch.FirstSequence < 1 || testCase.Batch.LastSequence < testCase.Batch.FirstSequence {
				return fmt.Errorf("C28 negative batch case %s has an invalid envelope", testCase.Name)
			}
			if len(testCase.Events) == 0 && testCase.Generate == nil {
				return fmt.Errorf("C28 negative batch case %s requires events or generate", testCase.Name)
			}
		case "storage_quota":
			if testCase.StorageLimits == nil || testCase.RequestedEvents <= 0 {
				return fmt.Errorf("C28 storage quota case %s requires limits and a count", testCase.Name)
			}
		default:
			return fmt.Errorf("C28 negative case %s has unknown kind %q", testCase.Name, testCase.Kind)
		}
	}
	if expected.Regression.Events != target.Sensors*target.Regression.EventsPerSensor ||
		expected.Regression.Sensors != target.Sensors || expected.Regression.BatchSize != target.Regression.BatchSize {
		return errors.New("C28 regression expectation is inconsistent")
	}
	if expected.Target.Sensors != target.Sensors || expected.Target.SteadyEvents != steady ||
		expected.Target.BacklogEvents != target.BacklogPhase.Events ||
		expected.Target.TotalEvents != steady+target.BacklogPhase.Events ||
		expected.Target.TotalAcks != expected.Target.TotalEvents ||
		expected.Target.PerSensorSequences != expected.Target.TotalEvents/target.Sensors ||
		expected.Target.Configs != target.Sensors {
		return errors.New("C28 target expectation is inconsistent with the scenario")
	}
	if expected.OverLimit.RateProbe.EventsPerSecond != scenario.OverLimit.RateProbe.EventsPerSecond ||
		expected.OverLimit.RateProbe.DurationSeconds != scenario.OverLimit.RateProbe.DurationSeconds ||
		expected.OverLimit.RateProbe.PlannedEvents != scenario.OverLimit.RateProbe.EventsPerSecond*scenario.OverLimit.RateProbe.DurationSeconds ||
		expected.OverLimit.RateProbe.CompletedMax >= expected.OverLimit.RateProbe.PlannedEvents {
		return errors.New("C28 rate probe expectation is inconsistent with the scenario")
	}
	if expected.OverLimit.BatchProbe.BatchSize != scenario.OverLimit.BatchProbe.BatchSize ||
		expected.OverLimit.StorageProbe.RequestedEvents != scenario.OverLimit.StorageProbe.Events ||
		expected.OverLimit.StorageProbe.BatchSize != scenario.OverLimit.StorageProbe.BatchSize {
		return errors.New("C28 over-limit expectation is inconsistent with the scenario")
	}
	if expected.Cancellation.BatchSize != scenario.Cancellation.BatchSize || expected.Cancellation.RetryEvents != scenario.Cancellation.BatchSize {
		return errors.New("C28 cancellation expectation is inconsistent with the scenario")
	}
	return nil
}

func c28Load(t *testing.T) (c28Scenario, c28Positive, c28Negative, c28Expected) {
	t.Helper()
	var scenario c28Scenario
	var positive c28Positive
	var negative c28Negative
	var expected c28Expected
	c28Read(t, "scenarios/target-workload.json", &scenario)
	c28Read(t, "fixtures/miragemesh/C28/positive.json", &positive)
	c28Read(t, "fixtures/miragemesh/C28/negative.json", &negative)
	c28Read(t, "fixtures/miragemesh/C28/expected-output.json", &expected)
	if err := c28Validate(scenario, positive, negative, expected); err != nil {
		t.Fatalf("invalid C28 workload: %v", err)
	}
	for _, reference := range scenario.Fixtures {
		if !strings.HasPrefix(reference, "tests/fixtures/miragemesh/C28/") {
			t.Fatalf("C28 fixture path is outside its directory: %s", reference)
		}
		if _, err := os.Stat(strings.TrimPrefix(reference, "tests/")); err != nil {
			t.Fatalf("C28 fixture is missing: %s", reference)
		}
	}
	for _, sample := range positive.Samples {
		if _, failure := contracts.DecodeEvent(context.Background(), []byte(sample)); failure != nil {
			t.Fatalf("C28 positive sample is invalid: %v", failure)
		}
	}
	for _, sample := range positive.Batch.Events {
		if _, failure := contracts.DecodeEvent(context.Background(), []byte(sample)); failure != nil {
			t.Fatalf("C28 positive batch event is invalid: %v", failure)
		}
	}
	return scenario, positive, negative, expected
}

func c28ExpectedError(token string) (error, bool) {
	switch token {
	case "invalid_event":
		return sensor.ErrInvalidEvent, true
	case "out_of_order":
		return sensor.ErrOutOfOrder, true
	case "unconfigured":
		return sensor.ErrUnconfigured, true
	case "conflict":
		return storage.ErrConflict, true
	case "invalid_batch":
		return collector.ErrInvalidBatch, true
	case "batch_too_large":
		return collector.ErrBatchTooLarge, true
	case "sensor_mismatch":
		return collector.ErrSensorMismatch, true
	case "quota":
		return storage.ErrQuota, true
	}
	return nil, false
}

func c28Verifier(scenario c28Scenario, public ed25519.PublicKey) (config.Verifier, error) {
	issued, err := time.Parse(time.RFC3339, scenario.Target.Config.IssuedAt)
	if err != nil {
		return config.Verifier{}, err
	}
	expires, err := time.Parse(time.RFC3339, scenario.Target.Config.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return config.Verifier{}, errors.New("invalid C28 config validity window")
	}
	return config.Verifier{
		PublicKey:  public,
		Clock:      func() time.Time { return issued.Add(time.Minute) },
		MaxSensors: scenario.Target.Config.MaxSensors,
		Bounds: config.Bounds{
			MinHeartbeatSeconds: scenario.Target.Config.Bounds.HeartbeatSeconds.Min,
			MaxHeartbeatSeconds: scenario.Target.Config.Bounds.HeartbeatSeconds.Max,
			MinSpoolLimitEvents: scenario.Target.Config.Bounds.SpoolLimitEvents.Min,
			MaxSpoolLimitEvents: scenario.Target.Config.Bounds.SpoolLimitEvents.Max,
			MinEventBatchLimit:  scenario.Target.Config.Bounds.EventBatchLimit.Min,
			MaxEventBatchLimit:  scenario.Target.Config.Bounds.EventBatchLimit.Max,
		},
	}, nil
}

func c28Open(t *testing.T, scenario c28Scenario, dir string, limits storage.Limits, trusted ed25519.PublicKey) (*storage.Store, *sensor.Applier, ed25519.PrivateKey) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(dir, "state"), limits)
	if err != nil {
		t.Fatalf("open C28 store: %v", err)
	}
	public := trusted
	var private ed25519.PrivateKey
	if len(public) == 0 {
		generatedPublic, generatedPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate C28 key: %v", err)
		}
		public, private = generatedPublic, generatedPrivate
	}
	verifier, err := c28Verifier(scenario, public)
	if err != nil {
		t.Fatalf("build C28 verifier: %v", err)
	}
	applier, err := sensor.NewApplier(context.Background(), store, verifier)
	if err != nil {
		t.Fatalf("build C28 applier: %v", err)
	}
	return store, applier, private
}

func c28Payload(sensorID string, scenario c28Scenario) []byte {
	config := scenario.Target.Config
	raw, _ := json.Marshal(struct {
		SchemaVersion string      `json:"schema_version"`
		SensorID      string      `json:"sensor_id"`
		Revision      int64       `json:"revision"`
		IssuedAt      string      `json:"issued_at"`
		ExpiresAt     string      `json:"expires_at"`
		Settings      c28Settings `json:"settings"`
	}{"1", sensorID, config.Revision, config.IssuedAt, config.ExpiresAt, config.Settings})
	return raw
}

func c28ApplyAll(t *testing.T, scenario c28Scenario, applier *sensor.Applier, key ed25519.PrivateKey, sensors []string) {
	t.Helper()
	for _, sensorID := range sensors {
		payload := c28Payload(sensorID, scenario)
		if _, err := applier.Apply(context.Background(), payload, ed25519.Sign(key, payload)); err != nil {
			t.Fatalf("apply C28 config for %s: %v", sensorID, err)
		}
	}
}

func c28Event(sensorID string, sequence int64, scenario c28Scenario, pathBytes int) []byte {
	if pathBytes < 16 {
		pathBytes = 16
	}
	event := contracts.Event{
		SchemaVersion: "1",
		SensorID:      sensorID,
		EventID:       fmt.Sprintf("event-%s-%06d", sensorID, sequence),
		Sequence:      sequence,
		ObservedAt:    scenario.Target.Event.ObservedAt,
		Kind:          scenario.Target.Event.Kind,
		Metadata:      contracts.HTTPMetadata{Path: "/synthetic/" + sensorID + "/" + strings.Repeat("p", pathBytes)},
	}
	raw, _ := json.Marshal(event)
	return raw
}

func c28GenerateEvents(scenario c28Scenario, spec c28Generate) [][]byte {
	pathBytes := spec.PathBytes
	if pathBytes == 0 {
		pathBytes = scenario.Target.Event.MetadataBytes
	}
	events := make([][]byte, spec.Count)
	for index := range events {
		events[index] = c28Event(spec.SensorID, spec.FirstSequence+int64(index), scenario, pathBytes)
	}
	return events
}

func c28Counts(t *testing.T, store *storage.Store) (int, int, int) {
	t.Helper()
	records, err := store.Records(context.Background())
	if err != nil {
		t.Fatalf("read C28 records: %v", err)
	}
	events, acks, configs := 0, 0, 0
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			events++
		}
		if record.Ack != nil {
			acks++
		}
		if record.Config != nil {
			configs++
		}
	}
	return events, acks, configs
}

func c28ManifestSHA(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "state", "manifest.json"))
	if err != nil {
		t.Fatalf("read C28 manifest: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func c28LatencyOf(durations []time.Duration) c28Latency {
	if len(durations) == 0 {
		return c28Latency{}
	}
	values := make([]float64, len(durations))
	total := float64(0)
	for index, duration := range durations {
		values[index] = float64(duration) / float64(time.Millisecond)
		total += values[index]
	}
	sort.Float64s(values)
	percentile := func(fraction float64) float64 {
		position := int(float64(len(values))*fraction+0.999999) - 1
		if position < 0 {
			position = 0
		}
		if position >= len(values) {
			position = len(values) - 1
		}
		return values[position]
	}
	return c28Latency{Count: len(values), MinMS: values[0], MeanMS: total / float64(len(values)), P50MS: percentile(0.50), P95MS: percentile(0.95), P99MS: percentile(0.99), MaxMS: values[len(values)-1]}
}

func c28RunTarget(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) c28Measurement {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	store, applier, key := c28Open(t, scenario, dir, scenario.Target.StorageLimits, nil)
	defer store.Close()
	c28ApplyAll(t, scenario, applier, key, positive.Sensors)
	if err := os.WriteFile(filepath.Join(dir, "public.key"), key.Public().(ed25519.PublicKey), 0600); err != nil {
		t.Fatalf("write C28 public key: %v", err)
	}
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatalf("build C28 collector: %v", err)
	}
	next := make(map[string]int64, len(positive.Sensors))
	for _, sensorID := range positive.Sensors {
		next[sensorID] = 1
	}
	planned := scenario.Target.SteadyPhase.DurationSeconds * scenario.Target.SteadyPhase.EventsPerSecond
	rate := scenario.Target.SteadyPhase.EventsPerSecond
	start := time.Now()
	deadline := start.Add(time.Duration(scenario.Target.SteadyPhase.DurationSeconds) * time.Second)
	steadyDurations := make([]time.Duration, 0, planned)
	steadyCompleted := 0
	for index := 0; index < planned; index++ {
		due := start.Add(time.Duration(index) * time.Second / time.Duration(rate))
		if now := time.Now(); now.Before(due) {
			time.Sleep(due.Sub(now))
		}
		if time.Now().After(deadline) {
			break
		}
		sensorID := positive.Sensors[index%len(positive.Sensors)]
		input := c28Event(sensorID, next[sensorID], scenario, scenario.Target.Event.MetadataBytes)
		began := time.Now()
		_, err := ingestor.Ingest(context.Background(), sensorID, collector.Batch{
			ID: fmt.Sprintf("c28-steady-%06d", index), FirstSequence: next[sensorID], LastSequence: next[sensorID], Events: [][]byte{input},
		})
		if err != nil {
			t.Fatalf("steady C28 ingest at %d: %v", index, err)
		}
		steadyDurations = append(steadyDurations, time.Since(began))
		next[sensorID]++
		steadyCompleted++
	}
	steadyElapsed := time.Since(start)
	steady := c28Phase{PlannedEvents: planned, CompletedEvents: steadyCompleted, Batches: steadyCompleted, ElapsedMS: float64(steadyElapsed) / float64(time.Millisecond), Latency: c28LatencyOf(steadyDurations)}
	if steadyElapsed > 0 {
		steady.EventsPerSecond = float64(steadyCompleted) / steadyElapsed.Seconds()
	}
	backlogStart := time.Now()
	backlogDurations := make([]time.Duration, 0, 16)
	backlogBatches := 0
	base := scenario.Target.BacklogPhase.Events / len(positive.Sensors)
	extra := scenario.Target.BacklogPhase.Events % len(positive.Sensors)
	for index, sensorID := range positive.Sensors {
		remaining := base
		if index < extra {
			remaining++
		}
		for remaining > 0 {
			count := scenario.Target.BacklogPhase.BatchSize
			if count > remaining {
				count = remaining
			}
			first := next[sensorID]
			events := make([][]byte, count)
			for offset := range events {
				events[offset] = c28Event(sensorID, first+int64(offset), scenario, scenario.Target.Event.MetadataBytes)
			}
			began := time.Now()
			if _, err := ingestor.Ingest(context.Background(), sensorID, collector.Batch{
				ID: fmt.Sprintf("c28-backlog-%s-%06d", sensorID, first), FirstSequence: first, LastSequence: first + int64(count) - 1, Events: events,
			}); err != nil {
				t.Fatalf("backlog C28 ingest for %s at %d: %v", sensorID, first, err)
			}
			backlogDurations = append(backlogDurations, time.Since(began))
			next[sensorID] += int64(count)
			remaining -= count
			backlogBatches++
		}
	}
	backlogElapsed := time.Since(backlogStart)
	backlog := c28Phase{PlannedEvents: scenario.Target.BacklogPhase.Events, CompletedEvents: scenario.Target.BacklogPhase.Events, Batches: backlogBatches, ElapsedMS: float64(backlogElapsed) / float64(time.Millisecond), Latency: c28LatencyOf(backlogDurations)}
	if backlogElapsed > 0 {
		backlog.EventsPerSecond = float64(scenario.Target.BacklogPhase.Events) / backlogElapsed.Seconds()
	}
	events, acks, configs := c28Counts(t, store)
	active, exists, err := applier.Active(context.Background(), positive.Sensors[0])
	if err != nil || !exists {
		t.Fatalf("active C28 config after target: exists=%v err=%v", exists, err)
	}
	result := c28Measurement{
		Phase: "target", Task: "C28", Scenario: "tests/scenarios/target-workload.json",
		Sensors: len(positive.Sensors), Events: events, Acks: acks, Configs: configs,
		IngestCalls: steadyCompleted + backlogBatches, Steady: steady, Backlog: backlog,
		AppliedRevision: active.Revision, ManifestSHA256: c28ManifestSHA(t, dir),
	}
	before := events
	probeFirst := next[positive.Sensors[0]]
	probeEvents := make([][]byte, scenario.OverLimit.BatchProbe.BatchSize)
	for offset := range probeEvents {
		probeEvents[offset] = c28Event(positive.Sensors[0], probeFirst+int64(offset), scenario, scenario.Target.Event.MetadataBytes)
	}
	_, probeErr := ingestor.Ingest(context.Background(), positive.Sensors[0], collector.Batch{
		ID: "c28-batch-over-limit", FirstSequence: probeFirst, LastSequence: probeFirst + int64(len(probeEvents)) - 1, Events: probeEvents,
	})
	if !errors.Is(probeErr, collector.ErrBatchTooLarge) {
		t.Fatalf("C28 batch probe error = %v, want ErrBatchTooLarge", probeErr)
	}
	after, _, _ := c28Counts(t, store)
	if after != before {
		t.Fatalf("C28 batch probe wrote %d records", after-before)
	}
	result.BatchProbe = &c28TypeError{Expected: scenario.OverLimit.BatchProbe.ExpectedError, Observed: probeErr.Error(), Matched: true}
	result.Negatives = []c28NegativeResult{{Name: "batch_over_limit", Expected: scenario.OverLimit.BatchProbe.ExpectedError, Observed: probeErr.Error(), Matched: true, Wrote: after != before}}
	return result
}

type c28CancelAfter struct {
	context.Context
	remaining atomic.Int64
}

func (c *c28CancelAfter) Err() error {
	if c.remaining.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

func c28RunCancellation(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) *c28Cancellation {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	store, applier, key := c28Open(t, scenario, dir, scenario.Target.StorageLimits, nil)
	defer store.Close()
	c28ApplyAll(t, scenario, applier, key, positive.Sensors[:1])
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	sensorID := positive.Sensors[0]
	events := c28GenerateEvents(scenario, c28Generate{SensorID: sensorID, FirstSequence: 1, Count: scenario.Cancellation.BatchSize})
	batch := collector.Batch{ID: "c28-cancel", FirstSequence: 1, LastSequence: int64(len(events)), Events: events}
	cancelContext := &c28CancelAfter{Context: context.Background()}
	cancelContext.remaining.Store(int64(scenario.Cancellation.CancelAfterChecks))
	_, cancelErr := ingestor.Ingest(cancelContext, sensorID, batch)
	if !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("C28 cancellation error = %v, want context.Canceled", cancelErr)
	}
	eventsBefore, acksBefore, _ := c28Counts(t, store)
	if acksBefore != 0 {
		t.Fatalf("C28 cancellation acknowledged %d events before retry", acksBefore)
	}
	if _, err := ingestor.Ingest(context.Background(), sensorID, batch); err != nil {
		t.Fatalf("C28 cancellation retry: %v", err)
	}
	eventsAfter, acksAfter, _ := c28Counts(t, store)
	return &c28Cancellation{
		Error: cancelErr.Error(), Matched: true, EventsBeforeRetry: eventsBefore, AcksBeforeRetry: acksBefore,
		RetryEvents: eventsAfter, RetryAcks: acksAfter,
	}
}

func c28RunStorageProbe(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) *c28StorageProbe {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	limits := scenario.OverLimit.StorageProbe.StorageLimits
	store, applier, key := c28Open(t, scenario, dir, limits, nil)
	defer store.Close()
	c28ApplyAll(t, scenario, applier, key, positive.Sensors[:scenario.OverLimit.StorageProbe.Sensors])
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	sensorID := positive.Sensors[0]
	sent := 0
	var observed error
	for sent < scenario.OverLimit.StorageProbe.Events {
		count := scenario.OverLimit.StorageProbe.BatchSize
		if count > scenario.OverLimit.StorageProbe.Events-sent {
			count = scenario.OverLimit.StorageProbe.Events - sent
		}
		first := int64(sent + 1)
		events := c28GenerateEvents(scenario, c28Generate{SensorID: sensorID, FirstSequence: first, Count: count})
		_, err := ingestor.Ingest(context.Background(), sensorID, collector.Batch{ID: fmt.Sprintf("c28-quota-%04d", sent), FirstSequence: first, LastSequence: first + int64(count) - 1, Events: events})
		if err != nil {
			observed = err
			break
		}
		sent += count
	}
	if !errors.Is(observed, storage.ErrQuota) {
		t.Fatalf("C28 storage probe error = %v, want storage quota", observed)
	}
	events, acks, _ := c28Counts(t, store)
	if events == 0 || events >= scenario.OverLimit.StorageProbe.Events || acks > events {
		t.Fatalf("C28 storage probe accepted=%d acks=%d", events, acks)
	}
	return &c28StorageProbe{Requested: scenario.OverLimit.StorageProbe.Events, Accepted: events, Acks: acks, Error: observed.Error(), Matched: true}
}

func c28RunRestart(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) c28Measurement {
	t.Helper()
	rawPublic, err := os.ReadFile(filepath.Join(dir, "public.key"))
	if err != nil || len(rawPublic) != ed25519.PublicKeySize {
		t.Fatalf("read C28 public key: %v", err)
	}
	store, applier, _ := c28Open(t, scenario, dir, scenario.Target.StorageLimits, ed25519.PublicKey(rawPublic))
	defer store.Close()
	events, acks, configs := c28Counts(t, store)
	active, exists, err := applier.Active(context.Background(), positive.Sensors[0])
	if err != nil || !exists {
		t.Fatalf("C28 restart active config: exists=%v err=%v", exists, err)
	}
	return c28Measurement{
		Phase: "restart", Task: "C28", Scenario: "tests/scenarios/target-workload.json",
		Sensors: len(positive.Sensors), Events: events, Acks: acks, Configs: configs,
		AppliedRevision: active.Revision,
		Restart:         &c28Restart{Events: events, Acks: acks, AppliedRevision: active.Revision, ManifestSHA256: c28ManifestSHA(t, dir)},
	}
}

func c28RunRateProbe(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) *c28RateProbe {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	store, applier, key := c28Open(t, scenario, dir, scenario.Target.StorageLimits, nil)
	defer store.Close()
	c28ApplyAll(t, scenario, applier, key, positive.Sensors)
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	probe := scenario.OverLimit.RateProbe
	planned := probe.EventsPerSecond * probe.DurationSeconds
	next := make(map[string]int64, len(positive.Sensors))
	for _, sensorID := range positive.Sensors {
		next[sensorID] = 1
	}
	start := time.Now()
	deadline := start.Add(time.Duration(probe.DurationSeconds) * time.Second)
	durations := make([]time.Duration, 0, planned)
	completed := 0
	for index := 0; index < planned; index++ {
		due := start.Add(time.Duration(index) * time.Second / time.Duration(probe.EventsPerSecond))
		if now := time.Now(); now.Before(due) {
			time.Sleep(due.Sub(now))
		}
		if time.Now().After(deadline) {
			break
		}
		sensorID := positive.Sensors[index%len(positive.Sensors)]
		input := c28Event(sensorID, next[sensorID], scenario, scenario.Target.Event.MetadataBytes)
		began := time.Now()
		if _, err := ingestor.Ingest(context.Background(), sensorID, collector.Batch{
			ID: fmt.Sprintf("c28-rate-%06d", index), FirstSequence: next[sensorID], LastSequence: next[sensorID], Events: [][]byte{input},
		}); err != nil {
			t.Fatalf("C28 rate probe ingest at %d: %v", index, err)
		}
		durations = append(durations, time.Since(began))
		next[sensorID]++
		completed++
	}
	elapsed := time.Since(start)
	result := &c28RateProbe{PlannedEvents: planned, CompletedEvents: completed, ElapsedMS: float64(elapsed) / float64(time.Millisecond), Latency: c28LatencyOf(durations)}
	if elapsed > 0 {
		result.EventsPerSecond = float64(completed) / elapsed.Seconds()
	}
	return result
}

func c28RunOverLimit(t *testing.T, scenario c28Scenario, positive c28Positive, dir string) c28Measurement {
	t.Helper()
	rateProbe := c28RunRateProbe(t, scenario, positive, filepath.Join(dir, "rate"))
	cancellation := c28RunCancellation(t, scenario, positive, filepath.Join(dir, "cancel"))
	storageProbe := c28RunStorageProbe(t, scenario, positive, filepath.Join(dir, "quota"))
	return c28Measurement{
		Phase: "over-limit", Task: "C28", Scenario: "tests/scenarios/target-workload.json",
		RateProbe: rateProbe, Cancellation: cancellation, StorageProbe: storageProbe,
		Negatives: []c28NegativeResult{
			{Name: "rate_probe_saturated", Expected: fmt.Sprintf("fewer than %d events", rateProbe.PlannedEvents), Observed: fmt.Sprintf("%d events in %.0f ms", rateProbe.CompletedEvents, rateProbe.ElapsedMS), Matched: rateProbe.CompletedEvents < rateProbe.PlannedEvents},
			{Name: "cancellation", Expected: context.Canceled.Error(), Observed: cancellation.Error, Matched: cancellation.Matched},
			{Name: "storage_quota", Expected: scenario.OverLimit.StorageProbe.ExpectedError, Observed: storageProbe.Error, Matched: storageProbe.Matched},
		},
	}
}

func c28RunNegative(t *testing.T, scenario c28Scenario, positive c28Positive, testCase c28NegativeCase) c28NegativeResult {
	t.Helper()
	want, ok := c28ExpectedError(testCase.ExpectedIs)
	if !ok {
		t.Fatalf("unknown C28 expected error %q", testCase.ExpectedIs)
	}
	dir := t.TempDir()
	limits := scenario.Target.StorageLimits
	sensorCount := len(positive.Sensors)
	if testCase.Kind == "storage_quota" {
		limits = *testCase.StorageLimits
		sensorCount = 1
	}
	store, applier, key := c28Open(t, scenario, dir, limits, nil)
	defer store.Close()
	c28ApplyAll(t, scenario, applier, key, positive.Sensors[:sensorCount])
	for _, seed := range testCase.Seed {
		if _, err := sensor.Accept(context.Background(), store, []byte(seed)); err != nil {
			t.Fatalf("C28 negative case %s seed: %v", testCase.Name, err)
		}
	}
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	if testCase.Kind == "storage_quota" {
		sent := 0
		var observed error
		for sent < testCase.RequestedEvents {
			first := int64(sent + 1)
			events := c28GenerateEvents(scenario, c28Generate{SensorID: positive.Sensors[0], FirstSequence: first, Count: testCase.RequestedEvents - sent})
			_, err := ingestor.Ingest(context.Background(), positive.Sensors[0], collector.Batch{ID: fmt.Sprintf("c28-negative-quota-%d", sent), FirstSequence: first, LastSequence: first + int64(len(events)) - 1, Events: events})
			if err != nil {
				observed = err
				break
			}
			sent += len(events)
		}
		before, _, _ := c28Counts(t, store)
		matched := errors.Is(observed, want) && before > 0 && before < testCase.RequestedEvents
		if !matched {
			t.Fatalf("C28 negative case %s: error=%v accepted=%d", testCase.Name, observed, before)
		}
		return c28NegativeResult{Name: testCase.Name, Expected: testCase.ExpectedIs, Observed: observed.Error(), Matched: true, Wrote: true}
	}
	var batch collector.Batch
	switch testCase.Kind {
	case "event":
		input := []byte(testCase.Input)
		if testCase.Generate != nil {
			input = c28GenerateEvents(scenario, *testCase.Generate)[0]
		}
		first := int64(1)
		if event, failure := contracts.DecodeEvent(context.Background(), input); failure == nil && event.Sequence >= 1 {
			first = event.Sequence
		}
		batch = collector.Batch{ID: "c28-negative-" + testCase.Name, FirstSequence: first, LastSequence: first, Events: [][]byte{input}}
	case "batch":
		events := make([][]byte, 0, len(testCase.Events))
		for _, raw := range testCase.Events {
			events = append(events, []byte(raw))
		}
		if testCase.Generate != nil {
			events = c28GenerateEvents(scenario, *testCase.Generate)
		}
		batch = collector.Batch{ID: testCase.Batch.BatchID, FirstSequence: testCase.Batch.FirstSequence, LastSequence: testCase.Batch.LastSequence, Events: events}
	default:
		t.Fatalf("unknown C28 negative kind %q", testCase.Kind)
	}
	before, _, _ := c28Counts(t, store)
	sensorID := testCase.Batch.SensorID
	if testCase.Kind == "event" {
		sensorID = firstSensorFor(positive, testCase)
	}
	_, err = ingestor.Ingest(context.Background(), sensorID, batch)
	if !errors.Is(err, want) {
		t.Fatalf("C28 negative case %s error = %v, want %v", testCase.Name, err, want)
	}
	after, _, _ := c28Counts(t, store)
	if after != before {
		t.Fatalf("C28 negative case %s wrote %d records", testCase.Name, after-before)
	}
	return c28NegativeResult{Name: testCase.Name, Expected: testCase.ExpectedIs, Observed: err.Error(), Matched: true, Wrote: false}
}

func firstSensorFor(positive c28Positive, testCase c28NegativeCase) string {
	if testCase.Generate != nil && testCase.Generate.SensorID != "" {
		return testCase.Generate.SensorID
	}
	if testCase.Input != "" {
		var event struct {
			SensorID string `json:"sensor_id"`
		}
		if json.Unmarshal([]byte(testCase.Input), &event) == nil && event.SensorID != "" {
			return event.SensorID
		}
	}
	return positive.Sensors[0]
}

func c28RunRegression(t *testing.T, scenario c28Scenario, positive c28Positive) *c28Regression {
	t.Helper()
	dir := t.TempDir()
	store, applier, key := c28Open(t, scenario, dir, scenario.Target.StorageLimits, nil)
	c28ApplyAll(t, scenario, applier, key, positive.Sensors)
	ingestor, err := collector.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	batches := 0
	for _, sensorID := range positive.Sensors {
		count := scenario.Target.Regression.EventsPerSensor
		events := make([][]byte, count)
		for index := range events {
			events[index] = c28Event(sensorID, int64(index+1), scenario, scenario.Target.Event.MetadataBytes)
		}
		if _, err := ingestor.Ingest(context.Background(), sensorID, collector.Batch{
			ID: fmt.Sprintf("c28-regression-%s", sensorID), FirstSequence: 1, LastSequence: int64(count), Events: events,
		}); err != nil {
			t.Fatalf("C28 regression ingest %s: %v", sensorID, err)
		}
		batches++
	}
	events, acks, _ := c28Counts(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, reopenedApplier, _ := c28Open(t, scenario, dir, scenario.Target.StorageLimits, key.Public().(ed25519.PublicKey))
	defer reopened.Close()
	eventsAfter, acksAfter, _ := c28Counts(t, reopened)
	if events != eventsAfter || acks != acksAfter {
		t.Fatalf("C28 regression restart events=%d/%d acks=%d/%d", events, eventsAfter, acks, acksAfter)
	}
	replay, exists, err := reopenedApplier.Active(context.Background(), positive.Sensors[0])
	if err != nil || !exists || replay.Revision != scenario.Target.Config.Revision {
		t.Fatalf("C28 regression active revision %+v exists=%v err=%v", replay.Revision, exists, err)
	}
	last := c28Event(positive.Sensors[len(positive.Sensors)-1], int64(scenario.Target.Regression.EventsPerSensor), scenario, scenario.Target.Event.MetadataBytes)
	replayReceipt, err := sensor.Accept(context.Background(), reopened, last)
	if err != nil {
		t.Fatalf("C28 regression replay: %v", err)
	}
	again, err := sensor.Accept(context.Background(), reopened, last)
	if err != nil || again != replayReceipt {
		t.Fatalf("C28 regression exact replay changed receipt: %v", err)
	}
	if events != scenario.Target.Regression.EventsPerSensor*len(positive.Sensors) || acks != events || batches != len(positive.Sensors) {
		t.Fatalf("C28 regression counts events=%d acks=%d batches=%d", events, acks, batches)
	}
	return &c28Regression{Events: events, Acks: acks, ReplayMatched: true}
}

func TestC28WorkloadFixturesAndLimits(t *testing.T) {
	scenario, positive, negative, expected := c28Load(t)
	regression := c28RunRegression(t, scenario, positive)
	if regression.Events != expected.Regression.Events || regression.Acks != expected.Regression.Acks || !regression.ReplayMatched {
		t.Fatalf("C28 regression expectation mismatch: %+v", regression)
	}
	cancelDir := filepath.Join(t.TempDir(), "cancel")
	cancellation := c28RunCancellation(t, scenario, positive, cancelDir)
	if cancellation.AcksBeforeRetry != expected.Cancellation.AcksBeforeRetry || cancellation.RetryEvents != expected.Cancellation.RetryEvents || cancellation.RetryAcks != expected.Cancellation.RetryAcks {
		t.Fatalf("C28 cancellation expectation mismatch: %+v", cancellation)
	}
	quotaDir := filepath.Join(t.TempDir(), "quota")
	quota := c28RunStorageProbe(t, scenario, positive, quotaDir)
	if quota.Accepted < expected.OverLimit.StorageProbe.AcceptedBetween[0] || quota.Accepted > expected.OverLimit.StorageProbe.AcceptedBetween[1] {
		t.Fatalf("C28 storage probe expectation mismatch: %+v", quota)
	}
	results := make([]c28NegativeResult, 0, len(negative.Cases))
	for _, testCase := range negative.Cases {
		results = append(results, c28RunNegative(t, scenario, positive, testCase))
	}
	if len(results) != expected.Negatives.Count {
		t.Fatalf("C28 negative case count = %d, want %d", len(results), expected.Negatives.Count)
	}
	for _, result := range results {
		if !result.Matched || (result.Wrote && result.Name != "storage_quota") {
			t.Fatalf("C28 negative case failed: %+v", result)
		}
	}
}

func TestC28RejectsMalformedWorkloads(t *testing.T) {
	scenario, positive, negative, expected := c28Load(t)
	mutations := []func(*c28Scenario, *c28Positive, *c28Negative, *c28Expected){
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) { s.SchemaVersion = 2 },
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) { s.License = "" },
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) { s.Target.Sensors = 0 },
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) {
			s.Target.SteadyPhase.EventsPerSecond = 0
		},
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) {
			s.Target.BacklogPhase.Events = 501
		},
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) {
			s.Target.SegmentLimits.MaxRecordsPerSegment = 0
		},
		func(s *c28Scenario, _ *c28Positive, _ *c28Negative, _ *c28Expected) { s.Target.HTTP.Endpoints = nil },
		func(_ *c28Scenario, p *c28Positive, _ *c28Negative, _ *c28Expected) { p.Samples = p.Samples[:1] },
		func(_ *c28Scenario, _ *c28Positive, n *c28Negative, _ *c28Expected) {
			n.Cases[1].ExpectedIs = "unknown"
		},
		func(_ *c28Scenario, _ *c28Positive, n *c28Negative, _ *c28Expected) {
			n.Cases[2].Name = n.Cases[1].Name
		},
		func(_ *c28Scenario, _ *c28Positive, _ *c28Negative, e *c28Expected) { e.Target.TotalEvents = 999 },
		func(_ *c28Scenario, _ *c28Positive, _ *c28Negative, e *c28Expected) { e.Negatives.Count = 1 },
	}
	for index, mutate := range mutations {
		mutatedScenario := scenario
		mutatedPositive := positive
		mutatedNegative := negative
		mutatedNegative.Cases = append([]c28NegativeCase(nil), negative.Cases...)
		mutatedExpected := expected
		mutate(&mutatedScenario, &mutatedPositive, &mutatedNegative, &mutatedExpected)
		if err := c28Validate(mutatedScenario, mutatedPositive, mutatedNegative, mutatedExpected); err == nil {
			t.Fatalf("C28 mutation %d was accepted", index)
		}
	}
}

func TestC28TargetWorkloadMeasurement(t *testing.T) {
	if os.Getenv("C28_MEASURE") != "1" {
		t.Skip("measurement is driven by scripts/benchmark-local.mjs")
	}
	scenario, positive, _, _ := c28Load(t)
	phase := os.Getenv("C28_PHASE")
	directory := os.Getenv("C28_WORKLOAD_DIR")
	output := os.Getenv("C28_RESULT")
	if directory == "" || output == "" {
		t.Fatal("C28 measurement requires C28_WORKLOAD_DIR and C28_RESULT")
	}
	var result c28Measurement
	switch phase {
	case "target":
		result = c28RunTarget(t, scenario, positive, directory)
	case "restart":
		result = c28RunRestart(t, scenario, positive, directory)
	case "over-limit":
		result = c28RunOverLimit(t, scenario, positive, directory)
	default:
		t.Fatalf("unknown C28 measurement phase %q", phase)
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestC28HarnessStaysOnLoopback(t *testing.T) {
	raw, err := os.ReadFile("../scripts/benchmark-local.mjs")
	if err != nil {
		t.Fatalf("missing C28 benchmark harness: %v", err)
	}
	pattern := regexp.MustCompile(`https?://[^\s"'` + "`" + `)]+`)
	hostPattern := regexp.MustCompile(`^https?://(\[[^\]]+\]|[^/:\s]+)`)
	for _, match := range pattern.FindAllString(string(raw), -1) {
		host := hostPattern.FindStringSubmatch(match)
		if len(host) != 2 || (host[1] != "127.0.0.1" && host[1] != "[::1]" && host[1] != "localhost") {
			t.Fatalf("C28 harness references a non-loopback URL: %s", match)
		}
	}
	self, err := os.ReadFile("performance_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"net/" + "http", "net." + "Dial", "http." + "Get(", "http." + "Post("} {
		if strings.Contains(string(self), forbidden) {
			t.Fatalf("C28 measurement must not open network clients: %s", forbidden)
		}
	}
}
