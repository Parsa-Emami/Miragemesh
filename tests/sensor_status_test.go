package tests

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/sensorview"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func TestSensorSnapshotReflectsDurableEventsConfigAndSpoolLoss(t *testing.T) {
	var fixture struct {
		FixtureVersion int            `json:"fixture_version"`
		License        string         `json:"license"`
		Provenance     string         `json:"provenance"`
		Limits         storage.Limits `json:"limits"`
		SnapshotAt     time.Time      `json:"snapshot_at"`
		Events         []string       `json:"events"`
	}
	readFixture := func(name string, target any) {
		t.Helper()
		raw, err := os.ReadFile("fixtures/miragemesh/C21/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("malformed C21 %s fixture: %v", name, err)
		}
	}
	readFixture("positive", &fixture)
	if fixture.FixtureVersion != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" || len(fixture.Events) != 5 || fixture.Limits.MaxOperations == 0 {
		t.Fatal("invalid C21 positive fixture")
	}
	rawExpected, err := os.ReadFile("fixtures/miragemesh/C21/expected-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var expectedEnvelope struct {
		FixtureVersion int    `json:"fixture_version"`
		License        string `json:"license"`
		Provenance     string `json:"provenance"`
	}
	if err = json.Unmarshal(rawExpected, &expectedEnvelope); err != nil || expectedEnvelope.FixtureVersion != 1 || expectedEnvelope.License != "Apache-2.0" || expectedEnvelope.Provenance == "" {
		t.Fatal("invalid C21 expected fixture", err)
	}
	want := sensorview.Snapshot{}
	if err = json.Unmarshal(rawExpected, &want); err != nil {
		t.Fatal(err)
	}

	c10, _, _ := c10Files(t)
	public, private := c10Key(t)
	verifier := c10Verifier(t, c10, public, c10.Bounds)
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	defer store.Close()
	applier := c11Applier(t, store, verifier)
	apply := func(sensorID, expiresAt string, spoolLimit int) {
		t.Helper()
		payload := strings.ReplaceAll(c10.Payloads["initial"], `"sensor-01"`, `"`+sensorID+`"`)
		payload = strings.Replace(payload, `"2026-11-21T00:00:00Z"`, `"`+expiresAt+`"`, 1)
		payload = strings.Replace(payload, `"spool_limit_events":4096`, `"spool_limit_events":`+strconv.Itoa(spoolLimit), 1)
		if spoolLimit == 1 {
			payload = strings.Replace(payload, `"event_batch_limit":64`, `"event_batch_limit":1`, 1)
		}
		if _, err := applier.Apply(context.Background(), []byte(payload), ed25519.Sign(private, []byte(payload))); err != nil {
			t.Fatalf("apply %s config: %v", sensorID, err)
		}
	}
	apply("sensor-01", "2026-10-21T00:01:00Z", 1)
	apply("sensor-02", "2026-12-21T00:00:00Z", 4096)
	queue, err := spool.New(store, applier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = queue.Enqueue(context.Background(), []byte(fixture.Events[0])); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.Enqueue(context.Background(), []byte(fixture.Events[1])); err == nil {
		t.Fatal("full spool did not record the expected dropped event")
	}
	if _, err = sensor.Accept(context.Background(), store, []byte(fixture.Events[2])); err != nil {
		t.Fatal(err)
	}
	if _, err = sensor.Accept(context.Background(), store, []byte(fixture.Events[3])); err != nil {
		t.Fatal(err)
	}
	if _, err = sensor.Accept(context.Background(), store, []byte(fixture.Events[4])); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sensorview.BuildSnapshot(context.Background(), store, applier, fixture.SnapshotAt)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	after, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("read-only snapshot changed the durable manifest", err)
	}
	records, err := store.Records(context.Background())
	if err != nil || len(records) == 0 {
		t.Fatal("read C05 records", err)
	}
	if err = os.WriteFile(filepath.Join(path, "object-"+records[0].Receipt.InputDigest+".json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = sensorview.BuildSnapshot(context.Background(), store, applier, fixture.SnapshotAt); !errors.Is(err, storage.ErrRecovery) {
		t.Fatalf("corrupt authoritative state was not rejected: %v", err)
	}
}
