package tests

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func sensorEvents(t *testing.T) ([][]byte, storage.Limits, []int64) {
	t.Helper()
	var fixture struct {
		FixtureVersion int            `json:"fixture_version"`
		License        string         `json:"license"`
		Provenance     string         `json:"provenance"`
		Limits         storage.Limits `json:"limits"`
		Events         []string       `json:"events"`
	}
	data, err := os.ReadFile("fixtures/miragemesh/C07/positive.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil || fixture.FixtureVersion != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" {
		t.Fatalf("invalid positive fixture: %v", err)
	}
	events := make([][]byte, len(fixture.Events))
	for i, event := range fixture.Events {
		events[i] = []byte(event)
	}
	var expected struct {
		FixtureVersion    int     `json:"fixture_version"`
		License           string  `json:"license"`
		Provenance        string  `json:"provenance"`
		AcceptedSequences []int64 `json:"accepted_sequences"`
	}
	data, err = os.ReadFile("fixtures/miragemesh/C07/expected-output.json")
	if err != nil || json.Unmarshal(data, &expected) != nil || expected.FixtureVersion != 1 || expected.License != "Apache-2.0" || expected.Provenance == "" {
		t.Fatalf("invalid expected-output fixture: %v", err)
	}
	return events, fixture.Limits, expected.AcceptedSequences
}

func TestSensorSequenceReplayAndRestart(t *testing.T) {
	events, limits, expectedSequences := sensorEvents(t)
	if len(events) != len(expectedSequences)+1 || len(expectedSequences) != 3 {
		t.Fatalf("positive fixture events=%d expected sequences=%v", len(events), expectedSequences)
	}
	path := storePath(t)
	store := openStore(t, path, limits)
	var first storage.Receipt
	var second storage.Receipt
	for i, sequence := range expectedSequences[:2] {
		receipt, err := sensor.Accept(context.Background(), store, events[i])
		if err != nil {
			t.Fatalf("accept sequence %d: %v", sequence, err)
		}
		if i == 0 {
			first = receipt
		} else {
			second = receipt
			if second.Generation != first.Generation+1 {
				t.Fatalf("second receipt %+v after %+v", second, first)
			}
		}
	}
	replay, err := sensor.Accept(context.Background(), store, events[0])
	if err != nil || replay != first {
		t.Fatalf("replay %+v, want %+v: %v", replay, first, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, path, limits)
	replay, err = sensor.Accept(context.Background(), store, events[1])
	if err != nil || replay != second {
		t.Fatalf("post-restart replay %+v, want %+v: %v", replay, second, err)
	}
	third, err := sensor.Accept(context.Background(), store, events[2])
	if err != nil || third.Generation != second.Generation+1 {
		t.Fatalf("post-restart next sequence %+v after %+v: %v", third, second, err)
	}
	independent, err := sensor.Accept(context.Background(), store, events[3])
	if err != nil || independent.Generation != third.Generation+1 {
		t.Fatalf("independent sensor receipt %+v after %+v: %v", independent, third, err)
	}
	if _, err = sensor.Accept(context.Background(), store, []byte(`{"schema_version":"1","sensor_id":"sensor-01","event_id":"event-05","sequence":5,"observed_at":"2026-01-01T00:00:04Z","kind":"http.request","metadata":{"path":"/later"}}`)); !errors.Is(err, sensor.ErrOutOfOrder) {
		t.Fatalf("sequence gap error = %v", err)
	}
}

func TestSensorRejectsInvalidAndConflictingEvents(t *testing.T) {
	events, limits, _ := sensorEvents(t)
	store := openStore(t, storePath(t), limits)
	var invalid struct {
		FixtureVersion int    `json:"fixture_version"`
		License        string `json:"license"`
		Provenance     string `json:"provenance"`
		Cases          []struct {
			Name  string `json:"name"`
			After string `json:"after"`
			Input string `json:"input"`
			Error string `json:"error"`
		} `json:"cases"`
	}
	data, err := os.ReadFile("fixtures/miragemesh/C07/invalid.json")
	if err != nil || json.Unmarshal(data, &invalid) != nil || invalid.FixtureVersion != 1 || invalid.License != "Apache-2.0" || invalid.Provenance == "" {
		t.Fatalf("invalid negative fixture: %v", err)
	}
	for _, test := range invalid.Cases {
		if test.After != "" {
			if _, err := sensor.Accept(context.Background(), store, []byte(test.After)); err != nil {
				t.Fatalf("%s setup: %v", test.Name, err)
			}
		}
		want := sensor.ErrInvalidEvent
		if test.Error == sensor.ErrOutOfOrder.Error() {
			want = sensor.ErrOutOfOrder
		} else if test.Error == storage.ErrConflict.Error() {
			want = storage.ErrConflict
		} else if test.Error != sensor.ErrInvalidEvent.Error() {
			t.Fatalf("unknown expected error %q for %s", test.Error, test.Name)
		}
		if _, err := sensor.Accept(context.Background(), store, []byte(test.Input)); !errors.Is(err, want) {
			t.Errorf("%s error = %v, want %v", test.Name, err, want)
		}
	}
	first, err := sensor.Accept(context.Background(), store, events[0])
	if err != nil {
		t.Fatal(err)
	}
	conflict := []byte(`{"schema_version":"1","sensor_id":"sensor-01","event_id":"different-event","sequence":1,"observed_at":"2026-01-01T00:00:00Z","kind":"http.request","metadata":{"path":"/health"}}`)
	if _, err = sensor.Accept(context.Background(), store, conflict); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("same sequence conflict error = %v (first receipt %+v)", err, first)
	}
	second, err := sensor.Accept(context.Background(), store, events[1])
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatalf("valid next sequence after rejected events %+v after %+v: %v", second, first, err)
	}
}
