package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var c18StorageLimits = storage.Limits{
	MaxOperations:    16,
	MaxBytes:         1 << 20,
	MaxManifestBytes: 1 << 16,
}

type c18FixtureEntry struct {
	SensorID string `json:"sensor_id"`
	EventID  string `json:"event_id"`
	Sequence int64  `json:"sequence"`
	Segment  string `json:"segment"`
	Record   int64  `json:"record"`
	Digest   string `json:"digest"`
	Bytes    int64  `json:"bytes"`
}

type c18FixtureGap struct {
	After  uint64 `json:"after"`
	Before uint64 `json:"before"`
}

type c18FixtureIdentity struct {
	SensorID string `json:"sensor_id"`
	EventID  string `json:"event_id"`
}

type c18Positive struct {
	FixtureVersion   int           `json:"fixture_version"`
	License          string        `json:"license"`
	Provenance       string        `json:"provenance"`
	BoundsProvenance string        `json:"bounds_provenance"`
	Limits           events.Limits `json:"limits"`
	Events           []string      `json:"events"`
}

type c18Expected struct {
	FixtureVersion   int    `json:"fixture_version"`
	License          string `json:"license"`
	Provenance       string `json:"provenance"`
	BoundsProvenance string `json:"bounds_provenance"`
	FullIndex        struct {
		Records      int64             `json:"records"`
		Sensors      int               `json:"sensors"`
		SegmentIDs   []string          `json:"segment_ids"`
		FirstOrdinal uint64            `json:"first_ordinal"`
		LastOrdinal  uint64            `json:"last_ordinal"`
		Complete     bool              `json:"complete"`
		Duplicates   int64             `json:"duplicates"`
		Entries      []c18FixtureEntry `json:"entries"`
	} `json:"full_index"`
	AfterSegmentLoss struct {
		RemovedSegment string               `json:"removed_segment"`
		Records        int64                `json:"records"`
		Sensors        int                  `json:"sensors"`
		SegmentIDs     []string             `json:"segment_ids"`
		FirstOrdinal   uint64               `json:"first_ordinal"`
		LastOrdinal    uint64               `json:"last_ordinal"`
		Missing        []c18FixtureGap      `json:"missing"`
		Complete       bool                 `json:"complete"`
		Absent         []c18FixtureIdentity `json:"absent"`
		Projection     struct {
			Appended         int `json:"appended"`
			AlreadyProjected int `json:"already_projected"`
			Skipped          int `json:"skipped"`
		} `json:"projection"`
	} `json:"after_segment_loss"`
	IncompleteTail struct {
		Records           int64  `json:"records"`
		Complete          bool   `json:"complete"`
		IncompleteSegment string `json:"incomplete_segment"`
		AbsentSensorID    string `json:"absent_sensor_id"`
		AbsentEventID     string `json:"absent_event_id"`
	} `json:"incomplete_tail"`
}

type c18NegativeCase struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
}

type c18Negative struct {
	FixtureVersion int               `json:"fixture_version"`
	License        string            `json:"license"`
	Provenance     string            `json:"provenance"`
	Cases          []c18NegativeCase `json:"cases"`
}

func c18Files(t *testing.T) (c18Positive, c18Expected, c18Negative) {
	t.Helper()
	var positive c18Positive
	var expected c18Expected
	var negative c18Negative
	for name, target := range map[string]any{
		"positive":        &positive,
		"expected-output": &expected,
		"negative":        &negative,
	} {
		raw, err := os.ReadFile("fixtures/miragemesh/C18/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C18 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || negative.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || negative.License != "Apache-2.0" ||
		positive.Provenance == "" || expected.Provenance == "" || negative.Provenance == "" ||
		positive.BoundsProvenance == "" || expected.BoundsProvenance == "" ||
		len(positive.Events) != 5 || positive.Limits.MaxSegments <= 0 || positive.Limits.MaxRecordsPerSegment != 2 ||
		len(expected.FullIndex.Entries) != 5 || len(expected.AfterSegmentLoss.Absent) != 2 ||
		len(expected.AfterSegmentLoss.Missing) != 1 || len(negative.Cases) != 6 {
		t.Fatal("invalid C18 fixture metadata")
	}
	known := map[string]bool{
		"modified_invalid_byte": true, "modified_valid_event": true, "conflicting_identity": true,
		"exact_duplicate": true, "missing_segment": true, "incomplete_tail": true,
	}
	for _, testCase := range negative.Cases {
		if !known[testCase.Name] || testCase.Expect == "" {
			t.Fatalf("unknown C18 negative case %q", testCase.Name)
		}
		delete(known, testCase.Name)
	}
	if len(known) != 0 {
		t.Fatalf("C18 negative fixture omits %v", known)
	}
	return positive, expected, negative
}

func c18StoreRecords(t *testing.T, directory string, rawEvents []string) []storage.Record {
	t.Helper()
	store, err := storage.Open(directory, c18StorageLimits)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for index, raw := range rawEvents {
		if _, err := store.Commit(ctx, fmt.Sprintf("event-%02d", index+1), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return records
}

func c18CheckEntry(t *testing.T, got events.Entry, want c18FixtureEntry) {
	t.Helper()
	if got.SensorID != want.SensorID || got.EventID != want.EventID || got.Sequence != want.Sequence ||
		got.Segment != want.Segment || got.Record != want.Record || got.Digest != want.Digest || got.Bytes != want.Bytes {
		t.Fatalf("entry = %+v, want %+v", got, want)
	}
}

func c18CheckIndex(t *testing.T, w *events.Writer, want c18Expected) {
	t.Helper()
	index, err := w.Index()
	if err != nil {
		t.Fatal(err)
	}
	full := want.FullIndex
	if index.Records != full.Records || index.Sensors != full.Sensors || index.FirstOrdinal != full.FirstOrdinal ||
		index.LastOrdinal != full.LastOrdinal || index.Complete != full.Complete || index.Duplicates != full.Duplicates ||
		strings.Join(index.SegmentIDs, ",") != strings.Join(full.SegmentIDs, ",") || len(index.Missing) != 0 || len(index.Incomplete) != 0 {
		t.Fatalf("index = %+v, want %+v", index, full)
	}
	entries := index.Entries()
	if len(entries) != len(full.Entries) {
		t.Fatalf("index entries = %d, want %d", len(entries), len(full.Entries))
	}
	for position, entry := range entries {
		c18CheckEntry(t, entry, full.Entries[position])
	}
	for _, want := range full.Entries {
		entry, ok := index.Lookup(want.SensorID, want.EventID)
		if !ok {
			t.Fatalf("missing index entry %s/%s", want.SensorID, want.EventID)
		}
		c18CheckEntry(t, entry, want)
	}
}

func TestIndexRebuildsFromCommittedSegments(t *testing.T) {
	positive, expected, _ := c18Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.Limits)
	c17AppendAll(t, w, positive.Events)
	c18CheckIndex(t, w, expected)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := c17Open(t, directory, positive.Limits)
	c18CheckIndex(t, reopened, expected)
}

func TestIndexLossRebuildDoesNotClaimMissingEvents(t *testing.T) {
	positive, expected, _ := c18Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.Limits)
	c17AppendAll(t, w, positive.Events)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Removing one sealed segment simulates retention or loss of indexed
	// evidence. The remaining ordinals still identify the gap.
	if err := os.Remove(filepath.Join(directory, expected.AfterSegmentLoss.RemovedSegment+".sealed.jsonl")); err != nil {
		t.Fatal(err)
	}

	reopened := c17Open(t, directory, positive.Limits)
	index, err := reopened.Index()
	if err != nil {
		t.Fatal(err)
	}
	loss := expected.AfterSegmentLoss
	if index.Records != loss.Records || index.Sensors != loss.Sensors || index.Complete ||
		index.FirstOrdinal != loss.FirstOrdinal || index.LastOrdinal != loss.LastOrdinal ||
		len(index.Missing) != 1 || index.Missing[0].After != loss.Missing[0].After || index.Missing[0].Before != loss.Missing[0].Before ||
		len(index.Incomplete) != 0 {
		t.Fatalf("rebuilt index after loss = %+v, want %+v", index, loss)
	}
	for _, absent := range loss.Absent {
		if _, ok := index.Lookup(absent.SensorID, absent.EventID); ok {
			t.Fatalf("index claims missing event %s/%s as ingested", absent.SensorID, absent.EventID)
		}
		for _, entry := range index.Entries() {
			if entry.SensorID == absent.SensorID && entry.EventID == absent.EventID {
				t.Fatalf("entries claim missing event %s/%s", absent.SensorID, absent.EventID)
			}
		}
	}

	records := c18StoreRecords(t, filepath.Join(t.TempDir(), "storage"), positive.Events)
	projection, err := reopened.AppendRecords(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Appended != loss.Projection.Appended || projection.AlreadyProjected != loss.Projection.AlreadyProjected ||
		projection.Skipped != loss.Projection.Skipped {
		t.Fatalf("projection after loss = %+v, want %+v", projection, loss.Projection)
	}
	if !projection.IndexKnown || projection.Rebuilt.Complete || len(projection.Rebuilt.Missing) != 1 ||
		projection.Rebuilt.Missing[0].After != loss.Missing[0].After || projection.Rebuilt.Missing[0].Before != loss.Missing[0].Before {
		t.Fatalf("projection index snapshot = %+v", projection.Rebuilt)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-projection actually recovers the two absent events from C05. The
	// ordinal gap remains explicit and no event is counted twice.
	final := c17Open(t, directory, positive.Limits)
	index, err = final.Index()
	if err != nil {
		t.Fatal(err)
	}
	if index.Records != 5 || index.Duplicates != 0 || index.Complete || len(index.Missing) != 1 {
		t.Fatalf("index after recovery = %+v", index)
	}
	for _, absent := range loss.Absent {
		entry, ok := index.Lookup(absent.SensorID, absent.EventID)
		if !ok || entry.Segment == loss.RemovedSegment {
			t.Fatalf("recovered event %s/%s = %+v ok=%v", absent.SensorID, absent.EventID, entry, ok)
		}
	}
}

func TestIndexRejectsModifiedSegmentByte(t *testing.T) {
	positive, expected, _ := c18Files(t)
	limits := positive.Limits
	limits.MaxRecordsPerSegment = 1

	t.Run("modified_invalid_byte", func(t *testing.T) {
		directory := c17Dir(t)
		w := c17Open(t, directory, limits)
		c17AppendAll(t, w, positive.Events)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "segment-00000000000000000002.sealed.jsonl")
		raw := mustRead(t, path)
		if len(raw) < 1 {
			t.Fatal("empty sealed segment")
		}
		raw[0] = '[' // one modified byte makes the record invalid
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if writer, err := events.Open(directory, limits); !errors.Is(err, events.ErrRecovery) {
			if writer != nil {
				_ = writer.Close()
			}
			t.Fatalf("open error = %v, want recovery", err)
		}
	})

	t.Run("modified_valid_event", func(t *testing.T) {
		directory := c17Dir(t)
		w := c17Open(t, directory, limits)
		c17AppendAll(t, w, positive.Events)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "segment-00000000000000000002.sealed.jsonl")
		raw := mustRead(t, path)
		modified := bytes.Replace(raw, []byte(`"sequence":2`), []byte(`"sequence":6`), 1)
		if bytes.Equal(raw, modified) {
			t.Fatal("modified event was not found")
		}
		if err := os.WriteFile(path, modified, 0600); err != nil {
			t.Fatal(err)
		}
		writer, err := events.Open(directory, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Close() }()
		index, err := writer.Index()
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := index.Lookup("sensor-01", "event-02")
		if !ok || entry.Sequence != 6 || entry.Digest == expected.FullIndex.Entries[1].Digest {
			t.Fatalf("modified entry = %+v ok=%v", entry, ok)
		}
		records := c18StoreRecords(t, filepath.Join(t.TempDir(), "storage"), positive.Events)
		before := c17FileSnapshot(t, directory)
		projection, err := writer.AppendRecords(context.Background(), records)
		if !errors.Is(err, events.ErrIndexConflict) {
			t.Fatalf("projection error = %v, want conflict", err)
		}
		if projection.Appended != 0 || projection.AlreadyProjected != 1 {
			t.Fatalf("conflicting projection = %+v", projection)
		}
		if after := c17FileSnapshot(t, directory); after != before {
			t.Fatal("conflicting projection changed segment bytes")
		}
	})
}

func TestIndexProjectionDeduplicatesAcrossRestart(t *testing.T) {
	positive, _, _ := c18Files(t)
	directory := c17Dir(t)
	storageDirectory := filepath.Join(t.TempDir(), "storage")
	records := c18StoreRecords(t, storageDirectory, positive.Events[:3])

	w := c17Open(t, directory, positive.Limits)
	first, err := w.AppendRecords(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if first.Appended != 3 || first.AlreadyProjected != 0 || first.Skipped != 0 {
		t.Fatalf("first projection = %+v", first)
	}
	before := c17FileSnapshot(t, directory)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := c17Open(t, directory, positive.Limits)
	second, err := reopened.AppendRecords(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if second.Appended != 0 || second.AlreadyProjected != 3 || second.Skipped != 0 || !second.IndexKnown ||
		second.Rebuilt.Records != 3 || second.Rebuilt.Duplicates != 0 || !second.Rebuilt.Complete {
		t.Fatalf("deduplicated projection = %+v", second)
	}
	if after := c17FileSnapshot(t, directory); after != before {
		t.Fatal("repeated projection changed segment bytes")
	}
}

func TestIndexExcludesIncompleteTail(t *testing.T) {
	positive, expected, _ := c18Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.Limits)
	c17AppendAll(t, w, positive.Events[:3])
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	active := c17ActivePath(t, directory)
	raw := mustRead(t, active)
	if len(raw) < 2 {
		t.Fatal("active segment is too small")
	}
	cut := len(raw) / 2
	tail := append([]byte(nil), raw[:cut]...)
	if err := os.Truncate(active, int64(cut)); err != nil {
		t.Fatal(err)
	}

	reopened := c17Open(t, directory, positive.Limits)
	index, err := reopened.Index()
	if err != nil {
		t.Fatal(err)
	}
	incomplete := expected.IncompleteTail
	if index.Records != incomplete.Records || index.Complete || len(index.Incomplete) != 1 ||
		index.Incomplete[0].ID != incomplete.IncompleteSegment || index.Incomplete[0].Incomplete == nil ||
		index.Incomplete[0].Incomplete.Bytes != int64(len(tail)) || index.Incomplete[0].Incomplete.Digest != c17Digest(tail) {
		t.Fatalf("index with incomplete tail = %+v", index)
	}
	if _, ok := index.Lookup(incomplete.AbsentSensorID, incomplete.AbsentEventID); ok {
		t.Fatal("incomplete tail was indexed as an event")
	}
	if entries := index.Entries(); len(entries) != 2 {
		t.Fatalf("indexed records = %d, want 2", len(entries))
	}
}

func TestIndexConflictsAreTypedAndFailClosed(t *testing.T) {
	positive, _, _ := c18Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.Limits)
	c17AppendAll(t, w, positive.Events[:1])
	before := c17FileSnapshot(t, directory)

	conflicting := `{"schema_version":"1","sensor_id":"sensor-01","event_id":"event-01","sequence":2,"observed_at":"2026-01-01T00:00:09Z","kind":"http.request","metadata":{"path":"/other"}}`
	if _, err := w.Append(context.Background(), []byte(conflicting)); !errors.Is(err, events.ErrIndexConflict) {
		t.Fatalf("conflicting append error = %v, want conflict", err)
	}
	if after := c17FileSnapshot(t, directory); after != before {
		t.Fatal("conflicting append changed segment bytes")
	}

	if _, err := w.Append(context.Background(), []byte(positive.Events[0])); err != nil {
		t.Fatalf("exact duplicate append: %v", err)
	}
	index, err := w.Index()
	if err != nil {
		t.Fatal(err)
	}
	if index.Records != 1 || index.Duplicates != 1 {
		t.Fatalf("duplicate index = %+v", index)
	}

	rebuilt := c17Dir(t)
	if err := os.Mkdir(rebuilt, 0700); err != nil {
		t.Fatal(err)
	}
	payload := positive.Events[0] + "\n" + conflicting + "\n"
	if err := os.WriteFile(filepath.Join(rebuilt, "segment-00000000000000000001.sealed.jsonl"), []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	if writer, err := events.Open(rebuilt, positive.Limits); !errors.Is(err, events.ErrIndexConflict) {
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatalf("open conflict error = %v, want conflict", err)
	}
}

func TestIndexHasNoNetworkImports(t *testing.T) {
	source, err := os.ReadFile("../internal/events/index.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "index.go", source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"errors": true}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" {
			t.Fatalf("index.go imports forbidden package %s", path)
		}
		if !allowed[path] {
			t.Fatalf("index.go imports unexpected package %s", path)
		}
	}
}
