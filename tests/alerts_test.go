package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
)

type c19Positive struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Policy         struct {
		RateLimit     int `json:"rate_limit"`
		WindowSeconds int `json:"window_seconds"`
	} `json:"policy"`
	Events []struct {
		Segment string `json:"segment"`
		Record  int64  `json:"record"`
		Raw     string `json:"raw"`
	} `json:"events"`
	Health []struct {
		SensorID  string  `json:"sensor_id"`
		Dropped   uint64  `json:"dropped_event_count"`
		Sequences []int64 `json:"gap_sequences"`
	} `json:"health"`
}

type c19Expected struct {
	FixtureVersion          int      `json:"fixture_version"`
	License                 string   `json:"license"`
	Provenance              string   `json:"provenance"`
	InteractionEventIDs     []string `json:"interaction_event_ids"`
	RateAlertSensorID       string   `json:"rate_alert_sensor_id"`
	RateAlertEventIDs       []string `json:"rate_alert_event_ids"`
	HealthAlertSensorID     string   `json:"health_alert_sensor_id"`
	HealthAlertGapSequences []int64  `json:"health_alert_gap_sequences"`
	CoverageComplete        bool     `json:"coverage_complete"`
}

func c19Fixture(t *testing.T) (c19Positive, c19Expected) {
	t.Helper()
	var positive c19Positive
	var expected c19Expected
	for path, target := range map[string]any{
		"positive.json":        &positive,
		"expected-output.json": &expected,
	} {
		raw, err := os.ReadFile(filepath.Join("fixtures", "miragemesh", "C19", path))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || positive.Provenance == "" || expected.Provenance == "" {
		t.Fatal("invalid C19 fixture metadata")
	}
	return positive, expected
}

func c19Inputs(fixture c19Positive) ([]alerts.Source, []alerts.SensorHealth) {
	sources := make([]alerts.Source, len(fixture.Events))
	for i, item := range fixture.Events {
		raw := []byte(item.Raw)
		digest := sha256.Sum256(raw)
		eventID := "event-01"
		sensorID := "sensor-01"
		var fields struct {
			SensorID string `json:"sensor_id"`
			EventID  string `json:"event_id"`
			Sequence int64  `json:"sequence"`
		}
		_ = json.Unmarshal(raw, &fields)
		eventID, sensorID = fields.EventID, fields.SensorID
		sources[i] = alerts.Source{Raw: raw, Ref: events.Entry{
			SensorID: sensorID,
			EventID:  eventID,
			Sequence: fields.Sequence,
			Segment:  item.Segment,
			Record:   item.Record,
			Digest:   hex.EncodeToString(digest[:]),
			Bytes:    int64(len(raw)),
		}}
	}
	health := make([]alerts.SensorHealth, len(fixture.Health))
	for i, item := range fixture.Health {
		health[i] = alerts.SensorHealth{SensorID: item.SensorID, DroppedEvents: item.Dropped, GapSequences: item.Sequences}
	}
	return sources, health
}

func TestAlertsReferenceInteractionsAndSeparateRateFromSensorHealth(t *testing.T) {
	fixture, expected := c19Fixture(t)
	sources, health := c19Inputs(fixture)
	outcome, err := alerts.Evaluate(context.Background(), sources, health, alerts.Policy{
		RateLimit: fixture.Policy.RateLimit, Window: time.Duration(fixture.Policy.WindowSeconds) * time.Second,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.CoverageComplete || outcome.RateLimit != fixture.Policy.RateLimit || outcome.WindowSeconds != fixture.Policy.WindowSeconds {
		t.Fatalf("policy or coverage = %+v", outcome)
	}
	if len(outcome.Interactions) != len(expected.InteractionEventIDs) {
		t.Fatalf("interaction count = %d", len(outcome.Interactions))
	}
	for i, want := range expected.InteractionEventIDs {
		if got := outcome.Interactions[i].Sources[0].EventID; got != want || outcome.Interactions[i].Class != alerts.ClassInteraction {
			t.Fatalf("interaction %d = %+v, want event %q", i, outcome.Interactions[i], want)
		}
	}
	if len(outcome.Rates) != 1 || outcome.Rates[0].SensorID != expected.RateAlertSensorID || outcome.Rates[0].Class != alerts.ClassAttackSignal {
		t.Fatalf("rate alerts = %+v", outcome.Rates)
	}
	var rateIDs []string
	for _, source := range outcome.Rates[0].Sources {
		rateIDs = append(rateIDs, source.EventID)
	}
	if !reflect.DeepEqual(rateIDs, expected.RateAlertEventIDs) {
		t.Fatalf("rate references = %v, want %v", rateIDs, expected.RateAlertEventIDs)
	}
	if len(outcome.SensorHealth) != 1 || outcome.SensorHealth[0].SensorID != expected.HealthAlertSensorID || outcome.SensorHealth[0].Class != alerts.ClassSensorHealth || !reflect.DeepEqual(outcome.SensorHealth[0].GapSequences, expected.HealthAlertGapSequences) {
		t.Fatalf("sensor health = %+v", outcome.SensorHealth)
	}
}

func TestAlertsRejectMissingPolicyMalformedSourceAndTamperedReference(t *testing.T) {
	fixture, _ := c19Fixture(t)
	sources, health := c19Inputs(fixture)
	if _, err := alerts.Evaluate(context.Background(), sources, health, alerts.Policy{}, true); !errors.Is(err, alerts.ErrInvalidPolicy) {
		t.Fatalf("missing policy error = %v", err)
	}
	malformed := append([]alerts.Source(nil), sources...)
	malformed[0].Raw = []byte("{not-json")
	if _, err := alerts.Evaluate(context.Background(), malformed, health, alerts.Policy{RateLimit: 3, Window: 5 * time.Second}, true); !errors.Is(err, alerts.ErrInvalidSource) {
		t.Fatalf("malformed source error = %v", err)
	}
	tampered := append([]alerts.Source(nil), sources...)
	tampered[0].Ref.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := alerts.Evaluate(context.Background(), tampered, health, alerts.Policy{RateLimit: 3, Window: 5 * time.Second}, true); !errors.Is(err, alerts.ErrSourceConflict) {
		t.Fatalf("tampered source error = %v", err)
	}
}

func TestAlertsNegativeFixtureCases(t *testing.T) {
	fixture, _ := c19Fixture(t)
	var negative struct {
		FixtureVersion int    `json:"fixture_version"`
		License        string `json:"license"`
		Provenance     string `json:"provenance"`
		Cases          []struct {
			Name          string `json:"name"`
			RateLimit     int    `json:"rate_limit"`
			WindowSeconds int    `json:"window_seconds"`
			Raw           string `json:"raw"`
			EventID       string `json:"event_id"`
			Digest        string `json:"reference_digest"`
			ExpectedError string `json:"expected_error"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile(filepath.Join("fixtures", "miragemesh", "C19", "negative.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &negative); err != nil {
		t.Fatal(err)
	}
	if negative.FixtureVersion != 1 || negative.License != "Apache-2.0" || negative.Provenance == "" || len(negative.Cases) != 4 {
		t.Fatalf("invalid negative fixture metadata: %+v", negative)
	}
	for _, item := range negative.Cases {
		t.Run(item.Name, func(t *testing.T) {
			sources, health := c19Inputs(fixture)
			policy := alerts.Policy{RateLimit: item.RateLimit, Window: time.Duration(item.WindowSeconds) * time.Second}
			switch item.Name {
			case "malformed-event":
				sources[0].Raw = []byte(item.Raw)
			case "tampered-reference":
				sources[0].Ref.Digest = item.Digest
			case "zero-rate-limit", "zero-window":
			default:
				t.Fatalf("unknown negative case %q", item.Name)
			}
			_, err := alerts.Evaluate(context.Background(), sources, health, policy, true)
			want := map[string]error{
				"invalid_policy":  alerts.ErrInvalidPolicy,
				"invalid_source":  alerts.ErrInvalidSource,
				"source_conflict": alerts.ErrSourceConflict,
			}[item.ExpectedError]
			if want == nil || !errors.Is(err, want) {
				t.Fatalf("error = %v, want %s", err, item.ExpectedError)
			}
		})
	}
}

func TestAlertsRetainIncompleteCoverageAndHonorCancellation(t *testing.T) {
	fixture, _ := c19Fixture(t)
	sources, health := c19Inputs(fixture)
	coverage, err := alerts.Evaluate(context.Background(), sources, health, alerts.Policy{RateLimit: 9, Window: 5 * time.Second}, false)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.CoverageComplete {
		t.Fatal("incomplete source coverage was reported complete")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := alerts.Evaluate(ctx, sources, health, alerts.Policy{RateLimit: 3, Window: 5 * time.Second}, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evaluation error = %v", err)
	}
}
