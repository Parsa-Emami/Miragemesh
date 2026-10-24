package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// C26 composes the existing offline spool, collector acknowledgement and
// durable restart boundaries into one scenario. It adds no new runtime
// behavior: every step goes through the same code the product uses, and the
// crash/egress proofs of C13, C14 and C16 remain their own required anchors in
// the same engine suite.
type c26Batch struct {
	BatchID       string `json:"batch_id"`
	FirstSequence int64  `json:"first_sequence"`
	LastSequence  int64  `json:"last_sequence"`
	EventIndexes  []int  `json:"event_indexes"`
}

type c26Fixture struct {
	c10Positive
	StorageLimits       storage.Limits      `json:"storage_limits"`
	Events              []string            `json:"events"`
	OfflineEventIndexes []int               `json:"offline_event_indexes"`
	DroppedIndex        int                 `json:"dropped_index"`
	Batches             map[string]c26Batch `json:"batches"`
}

type c26Loss struct {
	Count uint64           `json:"count"`
	Gaps  []spool.GapRange `json:"gaps"`
}

type c26Expected struct {
	FixtureVersion           int     `json:"fixture_version"`
	License                  string  `json:"license"`
	Provenance               string  `json:"provenance"`
	AcceptedOfflineSequences []int64 `json:"accepted_offline_sequences"`
	DroppedSequence          int64   `json:"dropped_sequence"`
	Loss                     c26Loss `json:"loss"`
	AcknowledgedSequences    []int64 `json:"acknowledged_sequences"`
	RestartRevision          int64   `json:"restart_revision"`
	FinalCounts              struct {
		Config int `json:"config"`
		Event  int `json:"event"`
		Ack    int `json:"ack"`
		Gap    int `json:"gap"`
	} `json:"final_counts"`
}

type c26InvalidCase struct {
	Name          string   `json:"name"`
	SensorID      string   `json:"sensor_id"`
	BatchID       string   `json:"batch_id"`
	FirstSequence int64    `json:"first_sequence"`
	LastSequence  int64    `json:"last_sequence"`
	EventIndexes  []int    `json:"event_indexes"`
	RawEvents     []string `json:"raw_events"`
	ExpectedIs    string   `json:"expected_is"`
}

type c26Invalid struct {
	FixtureVersion int              `json:"fixture_version"`
	License        string           `json:"license"`
	Provenance     string           `json:"provenance"`
	SensorID       string           `json:"sensor_id"`
	Cases          []c26InvalidCase `json:"cases"`
}

func c26Files(t *testing.T) (c26Fixture, c26Expected, c26Invalid) {
	t.Helper()
	var positive c26Fixture
	var expected c26Expected
	var invalid c26Invalid
	for name, target := range map[string]any{"positive": &positive, "expected-output": &expected, "invalid": &invalid} {
		raw, err := os.ReadFile("fixtures/miragemesh/C26/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C26 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || invalid.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || invalid.License != "Apache-2.0" ||
		positive.Provenance == "" || expected.Provenance == "" || invalid.Provenance == "" ||
		positive.BoundsProvenance == "" ||
		len(positive.Events) != 6 || len(positive.OfflineEventIndexes) != 4 ||
		positive.DroppedIndex != positive.OfflineEventIndexes[3] ||
		len(positive.Batches) != 4 || len(expected.AcknowledgedSequences) != 5 ||
		expected.Loss.Count != 1 || len(expected.Loss.Gaps) != 1 ||
		expected.FinalCounts.Config != 1 || expected.FinalCounts.Event != 5 ||
		expected.FinalCounts.Ack != 5 || expected.FinalCounts.Gap != 1 ||
		invalid.SensorID != positive.SensorID || len(invalid.Cases) != 7 {
		t.Fatal("invalid C26 fixture metadata")
	}
	for _, name := range []string{"first", "duplicate", "third", "resumed"} {
		shape, ok := positive.Batches[name]
		if !ok {
			t.Fatalf("missing C26 batch %q", name)
		}
		for _, index := range shape.EventIndexes {
			if index < 0 || index >= len(positive.Events) {
				t.Fatalf("batch %q references event index %d", name, index)
			}
		}
	}
	if positive.Batches["first"].BatchID != positive.Batches["duplicate"].BatchID {
		t.Fatal("the duplicate C26 batch must reuse the first batch identity")
	}
	for _, testCase := range invalid.Cases {
		if c26Sentinel(t, testCase.ExpectedIs) == nil {
			t.Fatalf("unsupported C26 expected error %q", testCase.ExpectedIs)
		}
	}
	return positive, expected, invalid
}

func c26Sentinel(t *testing.T, name string) error {
	t.Helper()
	switch name {
	case "sensor.ErrUnconfigured":
		return sensor.ErrUnconfigured
	case "collector.ErrInvalidBatch":
		return collector.ErrInvalidBatch
	case "collector.ErrBatchTooLarge":
		return collector.ErrBatchTooLarge
	case "collector.ErrSensorMismatch":
		return collector.ErrSensorMismatch
	case "storage.ErrConflict":
		return storage.ErrConflict
	default:
		return nil
	}
}

func (f c26Fixture) batch(t *testing.T, name string) collector.Batch {
	t.Helper()
	shape, ok := f.Batches[name]
	if !ok {
		t.Fatalf("missing C26 batch %q", name)
	}
	batch := collector.Batch{ID: shape.BatchID, FirstSequence: shape.FirstSequence, LastSequence: shape.LastSequence}
	for _, index := range shape.EventIndexes {
		batch.Events = append(batch.Events, []byte(f.Events[index]))
	}
	return batch
}

func c26InvalidBatch(t *testing.T, f c26Fixture, testCase c26InvalidCase) collector.Batch {
	t.Helper()
	batch := collector.Batch{ID: testCase.BatchID, FirstSequence: testCase.FirstSequence, LastSequence: testCase.LastSequence}
	if len(testCase.RawEvents) != 0 {
		for _, raw := range testCase.RawEvents {
			batch.Events = append(batch.Events, []byte(raw))
		}
		return batch
	}
	for _, index := range testCase.EventIndexes {
		if index < 0 || index >= len(f.Events) {
			t.Fatalf("C26 case %q references event index %d", testCase.Name, index)
		}
		batch.Events = append(batch.Events, []byte(f.Events[index]))
	}
	return batch
}

// c26Sequences returns the discrete event and acknowledgement sequences in
// durable record order. Gap markers are separate loss history and never events.
func c26Sequences(t *testing.T, s *storage.Store) (events, acks []int64) {
	t.Helper()
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			events = append(events, record.Event.Sequence)
		}
		if record.Ack != nil {
			acks = append(acks, record.Ack.Sequence)
		}
	}
	return events, acks
}

func c26EqualSequences(t *testing.T, what string, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s sequences %v, want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s sequences %v, want %v", what, got, want)
		}
	}
}

func TestResilienceOfflineSpoolDuplicateBatchesAndRestart(t *testing.T) {
	f, expected, _ := c26Files(t)
	public, key := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)

	// Offline: the signed bound retains the first three events and drops the
	// fourth with an explicit durable gap. An exact retry is the same drop.
	var accepted []int64
	for _, index := range f.OfflineEventIndexes[:len(f.OfflineEventIndexes)-1] {
		if _, err := q.Enqueue(context.Background(), []byte(f.Events[index])); err != nil {
			t.Fatalf("offline enqueue %d: %v", index, err)
		}
		accepted = append(accepted, int64(index+1))
	}
	c26EqualSequences(t, "offline", accepted, expected.AcceptedOfflineSequences)
	before := c14Manifest(t, path)
	_, err := q.Enqueue(context.Background(), []byte(f.Events[f.DroppedIndex]))
	var dropped *spool.DroppedError
	if !errors.As(err, &dropped) || !errors.Is(err, spool.ErrDropped) ||
		dropped.SensorID != f.SensorID || dropped.Sequence != expected.DroppedSequence {
		t.Fatalf("bounded spool outcome: %+v %v", dropped, err)
	}
	afterDrop := c14Manifest(t, path)
	if bytes.Equal(before, afterDrop) {
		t.Fatal("a dropped event must record its gap durably")
	}
	_, err = q.Enqueue(context.Background(), []byte(f.Events[f.DroppedIndex]))
	dropped = nil
	if !errors.As(err, &dropped) || !errors.Is(err, spool.ErrDropped) || dropped.Sequence != expected.DroppedSequence {
		t.Fatalf("dropped retry: %+v %v", dropped, err)
	}
	if after := c14Manifest(t, path); !bytes.Equal(afterDrop, after) {
		t.Fatal("an exact retry published a second gap")
	}
	loss, err := q.Losses(context.Background(), f.SensorID)
	if err != nil {
		t.Fatal(err)
	}
	if loss.Count != expected.Loss.Count || len(loss.Gaps) != len(expected.Loss.Gaps) ||
		loss.Gaps[0] != expected.Loss.Gaps[0] {
		t.Fatalf("offline loss summary: %+v", loss)
	}

	// Reconnect: a lost acknowledgement is replayed with the identical batch.
	ing := c16Ingestor(t, s, a)
	first, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || first.FirstSequence != 1 || first.LastSequence != 2 {
		t.Fatalf("first delivery: %+v", first)
	}
	events, acks := c26Sequences(t, s)
	if len(events) != 3 || len(acks) != 2 {
		t.Fatalf("first delivery counts: events=%v acks=%v", events, acks)
	}
	duplicate, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "duplicate"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range first.Events {
		if duplicate.Events[i] != first.Events[i] {
			t.Fatalf("duplicate delivery changed receipt %d: %+v != %+v", i, duplicate.Events[i], first.Events[i])
		}
	}
	events, acks = c26Sequences(t, s)
	if len(events) != 3 || len(acks) != 2 {
		t.Fatalf("duplicate delivery not idempotent: events=%v acks=%v", events, acks)
	}

	// Restart: the applied revision, receipts and loss accounting are durable.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	a = c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	active, exists, err := a.Active(context.Background(), f.SensorID)
	if err != nil || !exists || active.Revision != expected.RestartRevision ||
		!bytes.Equal(active.Payload, []byte(f.Payloads["initial"])) {
		t.Fatalf("applied state after restart: %+v %v exists=%v", active, err, exists)
	}
	q = c14Spool(t, s, a)
	ing = c16Ingestor(t, s, a)
	loss, err = q.Losses(context.Background(), f.SensorID)
	if err != nil || loss.Count != expected.Loss.Count || loss.Gaps[0] != expected.Loss.Gaps[0] {
		t.Fatalf("loss summary after restart: %+v %v", loss, err)
	}
	replayed, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "duplicate"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range first.Events {
		if replayed.Events[i] != first.Events[i] {
			t.Fatalf("restart replay changed receipt %d: %+v != %+v", i, replayed.Events[i], first.Events[i])
		}
	}

	// Delivery continues across the explicit gap, and acknowledged events no
	// longer consume the signed spool capacity.
	if _, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "third")); err != nil {
		t.Fatalf("third delivery: %v", err)
	}
	for _, index := range f.Batches["resumed"].EventIndexes {
		if _, err := q.Enqueue(context.Background(), []byte(f.Events[index])); err != nil {
			t.Fatalf("resumed enqueue %d: %v", index, err)
		}
	}
	resumed, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "resumed"))
	if err != nil {
		t.Fatalf("resumed delivery: %v", err)
	}
	if resumed.FirstSequence != 5 || resumed.LastSequence != 6 {
		t.Fatalf("resumed delivery: %+v", resumed)
	}

	events, acks = c26Sequences(t, s)
	c26EqualSequences(t, "event", events, expected.AcknowledgedSequences)
	c26EqualSequences(t, "acknowledgement", acks, expected.AcknowledgedSequences)
	counts := c16Counts(t, s)
	if counts.config != expected.FinalCounts.Config || counts.event != expected.FinalCounts.Event ||
		counts.ack != expected.FinalCounts.Ack || counts.gap != expected.FinalCounts.Gap || counts.enrollment != 0 {
		t.Fatalf("final durable counts: %+v", counts)
	}
	loss, err = q.Losses(context.Background(), f.SensorID)
	if err != nil || loss.Count != expected.Loss.Count || len(loss.Gaps) != 1 || loss.Gaps[0] != expected.Loss.Gaps[0] {
		t.Fatalf("final loss summary: %+v %v", loss, err)
	}
}

func TestResilienceRejectsUnconfiguredAndMalformedBatches(t *testing.T) {
	f, _, invalid := c26Files(t)
	public, key := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	ing := c16Ingestor(t, s, a)
	before := c14Manifest(t, path)

	// A sensor without applied signed settings cannot deliver anything.
	unconfigured := invalid.Cases[0]
	if unconfigured.Name != "unconfigured" {
		t.Fatalf("unexpected first C26 negative case %q", unconfigured.Name)
	}
	if _, err := ing.Ingest(context.Background(), unconfigured.SensorID, c26InvalidBatch(t, f, unconfigured)); !errors.Is(err, sensor.ErrUnconfigured) {
		t.Fatalf("unconfigured delivery: %v", err)
	}
	if after := c14Manifest(t, path); !bytes.Equal(before, after) {
		t.Fatal("an unconfigured delivery changed the store")
	}

	c11Apply(t, a, key, f.Payloads["initial"])
	// Establish sequence 1 so the conflicting replay is a genuine identity conflict.
	if _, err := ing.Ingest(context.Background(), f.SensorID, collector.Batch{
		ID: "batch-resilience-precondition", FirstSequence: 1, LastSequence: 1,
		Events: [][]byte{[]byte(f.Events[0])},
	}); err != nil {
		t.Fatal(err)
	}
	before = c14Manifest(t, path)
	baseline := c16Counts(t, s)
	for _, testCase := range invalid.Cases[1:] {
		batch := c26InvalidBatch(t, f, testCase)
		if _, err := ing.Ingest(context.Background(), testCase.SensorID, batch); !errors.Is(err, c26Sentinel(t, testCase.ExpectedIs)) {
			t.Fatalf("C26 case %q: %v", testCase.Name, err)
		}
		if after := c14Manifest(t, path); !bytes.Equal(before, after) {
			t.Fatalf("C26 case %q changed the store", testCase.Name)
		}
		if after := c16Counts(t, s); after != baseline {
			t.Fatalf("C26 case %q changed durable counts: %+v != %+v", testCase.Name, after, baseline)
		}
	}
}

// The composed offline and delivery path must have no network capability at
// all. The real rootless-container egress proof remains
// TestDecoyIsolationDeniesInternetAndPrivateSubnets; this anchor covers the
// packages this scenario actually calls.
func TestResilienceDeliveryPathHasNoEgress(t *testing.T) {
	directories := []string{"../internal/spool", "../internal/collector", "../internal/sensor"}
	for _, directory := range directories {
		files, err := filepath.Glob(filepath.Join(directory, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s sources: %v", directory, err)
		}
		for _, file := range files {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range parsed.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if importPath == "net" || strings.HasPrefix(importPath, "net/") ||
					importPath == "os/exec" || importPath == "syscall" ||
					importPath == "plugin" || importPath == "C" {
					t.Fatalf("%s imports %q; the offline delivery path must not be able to egress", file, importPath)
				}
			}
		}
	}
}
