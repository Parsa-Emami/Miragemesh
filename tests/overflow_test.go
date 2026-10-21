package tests

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c15Positive struct {
	FixtureVersion int      `json:"fixture_version"`
	License        string   `json:"license"`
	Provenance     string   `json:"provenance"`
	SensorID       string   `json:"sensor_id"`
	Limit          int      `json:"configured_event_limit"`
	Events         []string `json:"events"`
}

type c15Expected struct {
	FixtureVersion int              `json:"fixture_version"`
	License        string           `json:"license"`
	Provenance     string           `json:"provenance"`
	Accepted       []int64          `json:"accepted_sequences_before_overflow"`
	Dropped        int64            `json:"dropped_sequence"`
	LossCount      uint64           `json:"loss_count_after_exact_retry_and_next_full_event"`
	Gaps           []spool.GapRange `json:"gap_ranges"`
	Resume         int64            `json:"sequence_after_gap"`
	QuotaLossCount uint64           `json:"quota_failure_persisted_loss_count"`
}

type c15Invalid struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Cases          []struct {
		Name          string `json:"name"`
		Input         string `json:"input"`
		EventID       string `json:"event_id"`
		ExpectedError string `json:"expected_error"`
	} `json:"cases"`
}

func c15Files(t *testing.T) (c15Positive, c15Expected) {
	t.Helper()
	var positive c15Positive
	var expected c15Expected
	for path, target := range map[string]any{"positive.json": &positive, "expected-output.json": &expected} {
		raw, err := os.ReadFile("fixtures/miragemesh/C15/" + path)
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("invalid C15 fixture %s: %v", path, err)
		}
	}
	if positive.FixtureVersion != 1 || positive.License != "Apache-2.0" || positive.Provenance == "" || positive.SensorID != "sensor-01" || positive.Limit != 2 || len(positive.Events) != 5 {
		t.Fatal("invalid C15 positive fixture metadata")
	}
	if expected.FixtureVersion != 1 || expected.License != "Apache-2.0" || expected.Provenance == "" || len(expected.Accepted) != 2 || expected.Dropped != 3 || expected.LossCount != 2 || len(expected.Gaps) != 1 || expected.Gaps[0] != (spool.GapRange{From: 3, Through: 4}) || expected.Resume != 5 {
		t.Fatal("invalid C15 expected-output fixture")
	}
	return positive, expected
}

func c15InvalidCases(t *testing.T) c15Invalid {
	t.Helper()
	var invalid c15Invalid
	raw, err := os.ReadFile("fixtures/miragemesh/C15/invalid.json")
	if err != nil || json.Unmarshal(raw, &invalid) != nil || invalid.FixtureVersion != 1 || invalid.License != "Apache-2.0" || invalid.Provenance == "" || len(invalid.Cases) != 3 {
		t.Fatalf("invalid C15 negative fixture: %v", err)
	}
	if invalid.Cases[0].ExpectedError != sensor.ErrInvalidEvent.Error() || invalid.Cases[1].ExpectedError != storage.ErrConflict.Error() || invalid.Cases[2].ExpectedError != storage.ErrQuota.Error() || invalid.Cases[0].Input != "{}" || invalid.Cases[1].EventID == "" {
		t.Fatal("C15 negative fixture verdicts do not match typed outcomes")
	}
	return invalid
}

func TestSpoolOverflowPersistsDroppedEventAndResumesAfterGap(t *testing.T) {
	f := c14Files(t)
	positive, expected := c15Files(t)
	public, key := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	for _, input := range positive.Events[:2] {
		if _, err := q.Enqueue(context.Background(), []byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := q.Enqueue(context.Background(), []byte(positive.Events[expected.Dropped-1]))
	var dropped *spool.DroppedError
	if !errors.As(err, &dropped) || !errors.Is(err, spool.ErrDropped) || dropped.SensorID != positive.SensorID || dropped.EventID != "event-03" || dropped.Sequence != expected.Dropped {
		t.Fatalf("full spool typed outcome: %+v %v", dropped, err)
	}
	invalid := c15InvalidCases(t)
	conflict := strings.Replace(positive.Events[expected.Dropped-1], "event-03", invalid.Cases[1].EventID, 1)
	if _, err := q.Enqueue(context.Background(), []byte(conflict)); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("same dropped sequence with different input: %v", err)
	}
	_, err = q.Enqueue(context.Background(), []byte(positive.Events[expected.Dropped-1]))
	dropped = nil
	if !errors.As(err, &dropped) || !errors.Is(err, spool.ErrDropped) || dropped.Sequence != expected.Dropped {
		t.Fatalf("dropped replay: %+v %v", dropped, err)
	}
	if _, err := q.Enqueue(context.Background(), []byte(positive.Events[3])); !errors.Is(err, spool.ErrDropped) {
		t.Fatalf("next full event: %v", err)
	}
	loss, err := q.Losses(context.Background(), "sensor-01")
	if err != nil || loss.Count != expected.LossCount || len(loss.Gaps) != 1 || loss.Gaps[0] != expected.Gaps[0] {
		t.Fatalf("loss projection: %+v %v", loss, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	a = c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	q = c14Spool(t, s, a)
	loss, err = q.Losses(context.Background(), "sensor-01")
	if err != nil || loss.Count != expected.LossCount || len(loss.Gaps) != 1 || loss.Gaps[0] != expected.Gaps[0] {
		t.Fatalf("recovered loss: %+v %v", loss, err)
	}
	if _, err := q.Enqueue(context.Background(), []byte(positive.Events[expected.Dropped-1])); !errors.Is(err, spool.ErrDropped) {
		t.Fatalf("recovered dropped retry: %v", err)
	}
	c11Apply(t, a, key, f.Payloads["raise"])
	if _, err := q.Enqueue(context.Background(), []byte(positive.Events[expected.Resume-1])); err != nil {
		t.Fatalf("event after gap: %v", err)
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := len(records); got != 7 { // config, two events, two gaps, raised config, next event
		t.Fatalf("record count=%d", got)
	}
	for _, record := range records {
		if record.Gap != nil && strings.Contains(string(record.Input), `"metadata"`) {
			t.Fatal("gap marker retained omitted event payload")
		}
	}
}

func TestSpoolOverflowIsBoundedByStorageQuota(t *testing.T) {
	f := c14Files(t)
	positive, expected := c15Files(t)
	public, key := c10Key(t)
	limits := f.StorageLimits
	limits.MaxOperations = 3
	path := storePath(t)
	s := openStore(t, path, limits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	for _, input := range positive.Events[:2] {
		if _, err := q.Enqueue(context.Background(), []byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	before := c14Manifest(t, path)
	if _, err := q.Enqueue(context.Background(), []byte(positive.Events[expected.Dropped-1])); !errors.Is(err, storage.ErrQuota) {
		t.Fatalf("storage quota must fail explicitly: %v", err)
	}
	if after := c14Manifest(t, path); string(before) != string(after) {
		t.Fatal("quota failure partially published a gap")
	}
	loss, err := q.Losses(context.Background(), "sensor-01")
	if err != nil || loss.Count != expected.QuotaLossCount {
		t.Fatalf("quota failure claimed a persisted loss: %+v %v", loss, err)
	}
}

func TestSpoolOverflowRejectsInvalidEventsWithoutCountingLoss(t *testing.T) {
	f := c14Files(t)
	positive, _ := c15Files(t)
	invalid := c15InvalidCases(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	for _, input := range positive.Events[:2] {
		if _, err := q.Enqueue(context.Background(), []byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.Enqueue(context.Background(), []byte(invalid.Cases[0].Input)); !errors.Is(err, sensor.ErrInvalidEvent) {
		t.Fatalf("invalid full-queue event: %v", err)
	}
	loss, err := q.Losses(context.Background(), "sensor-01")
	if err != nil || loss.Count != 0 {
		t.Fatalf("invalid input counted as loss: %+v %v", loss, err)
	}
}

func TestSpoolOverflowRejectsNilQueueAndCancellation(t *testing.T) {
	var queue *spool.Store
	if _, err := queue.Losses(context.Background(), "sensor-01"); !errors.Is(err, spool.ErrInvalidInput) {
		t.Fatalf("nil queue: %v", err)
	}
	f := c14Files(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	queue = c14Spool(t, s, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queue.Losses(ctx, "sensor-01"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Losses(context.Background(), "sensor-01"); !errors.Is(err, storage.ErrClosed) {
		t.Fatalf("closed store query: %v", err)
	}
}
