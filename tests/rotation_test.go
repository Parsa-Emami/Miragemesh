package tests

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	c24fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

type c17SegmentExpect struct {
	ID      string `json:"id"`
	Records int64  `json:"records"`
	Sealed  bool   `json:"sealed"`
}

type c17RotationExpect struct {
	Segments      []c17SegmentExpect `json:"segments"`
	ResumeSegment string             `json:"resume_segment"`
}

type c17Positive struct {
	FixtureVersion   int           `json:"fixture_version"`
	License          string        `json:"license"`
	Provenance       string        `json:"provenance"`
	BoundsProvenance string        `json:"bounds_provenance"`
	Events           []string      `json:"events"`
	RecordLimits     events.Limits `json:"record_limits"`
	ByteLimits       events.Limits `json:"byte_limits"`
	IncompleteLimits events.Limits `json:"incomplete_limits"`
	ByteEvents       []string      `json:"byte_events"`
}

type c17Expected struct {
	FixtureVersion   int               `json:"fixture_version"`
	License          string            `json:"license"`
	Provenance       string            `json:"provenance"`
	BoundsProvenance string            `json:"bounds_provenance"`
	RecordRotation   c17RotationExpect `json:"record_rotation"`
	ByteRotation     c17RotationExpect `json:"byte_rotation"`
	IncompleteTail   struct {
		ValidRecordsBeforeTail int64  `json:"valid_records_before_tail"`
		IncompleteSegment      string `json:"incomplete_segment"`
		ResumeSegment          string `json:"resume_segment"`
		TailNotAnEvent         bool   `json:"tail_not_an_event"`
	} `json:"incomplete_tail"`
	Restart struct {
		SealedSegmentsUnchanged bool   `json:"sealed_segments_unchanged"`
		ResumeAfterRestart      string `json:"resume_after_restart"`
	} `json:"restart"`
	RetentionGap struct {
		RemovedSegment           string   `json:"removed_segment"`
		RemainingSegments        []string `json:"remaining_segments"`
		GapIsNotEventSequenceGap bool     `json:"gap_is_not_event_sequence_gap"`
	} `json:"retention_gap"`
}

type c17InvalidCase struct {
	Name  string `json:"name"`
	Raw   string `json:"raw"`
	Error string `json:"error"`
}

type c17InvalidLimits struct {
	Name                 string `json:"name"`
	MaxSegments          int    `json:"max_segments"`
	MaxRecordsPerSegment int64  `json:"max_records_per_segment"`
	MaxBytesPerSegment   int64  `json:"max_bytes_per_segment"`
	Error                string `json:"error"`
}

type c17Invalid struct {
	FixtureVersion int                `json:"fixture_version"`
	License        string             `json:"license"`
	Provenance     string             `json:"provenance"`
	Cases          []c17InvalidCase   `json:"cases"`
	Limits         []c17InvalidLimits `json:"limits"`
	UnsafeState    []string           `json:"unsafe_state"`
}

type c17CrashPhase struct {
	Name              string `json:"name"`
	ValidRecords      int64  `json:"valid_records"`
	Incomplete        bool   `json:"incomplete"`
	IncompleteSegment string `json:"incomplete_segment"`
	ResumeSegment     string `json:"resume_segment"`
}

type c17Crash struct {
	FixtureVersion int             `json:"fixture_version"`
	License        string          `json:"license"`
	Provenance     string          `json:"provenance"`
	Phases         []c17CrashPhase `json:"phases"`
}

func c17Files(t *testing.T) (c17Positive, c17Expected, c17Invalid, c17Crash) {
	t.Helper()
	var positive c17Positive
	var expected c17Expected
	var invalid c17Invalid
	var crash c17Crash
	for name, target := range map[string]any{
		"positive":        &positive,
		"expected-output": &expected,
		"invalid":         &invalid,
		"crash":           &crash,
	} {
		raw, err := os.ReadFile("fixtures/miragemesh/C17/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C17 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || invalid.FixtureVersion != 1 || crash.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || invalid.License != "Apache-2.0" || crash.License != "Apache-2.0" ||
		positive.Provenance == "" || expected.Provenance == "" || invalid.Provenance == "" || crash.Provenance == "" ||
		positive.BoundsProvenance == "" || expected.BoundsProvenance == "" ||
		len(positive.Events) != 5 || len(positive.ByteEvents) != 5 ||
		positive.RecordLimits.MaxSegments <= 0 || positive.ByteLimits.MaxSegments <= 0 || positive.IncompleteLimits.MaxSegments <= 0 ||
		len(invalid.Cases) == 0 || len(invalid.Limits) == 0 || len(invalid.UnsafeState) == 0 ||
		len(crash.Phases) == 0 {
		t.Fatal("invalid C17 fixture metadata")
	}
	return positive, expected, invalid, crash
}

func c17Dir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "segments")
}

func c17Open(t *testing.T, directory string, limits events.Limits) *events.Writer {
	t.Helper()
	w, err := events.Open(directory, limits)
	if err != nil {
		t.Fatalf("open segments: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func c17AppendAll(t *testing.T, w *events.Writer, raws []string) {
	t.Helper()
	for i, raw := range raws {
		if _, err := w.Append(context.Background(), []byte(raw)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func c17Segments(t *testing.T, w *events.Writer) []events.Segment {
	t.Helper()
	segments, err := w.Segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	return segments
}

func c17CheckSegments(t *testing.T, got []events.Segment, want []c17SegmentExpect) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("segment count = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Records != want[i].Records || got[i].Sealed != want[i].Sealed {
			t.Fatalf("segment %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func c17RecordPayloads(t *testing.T, directory string) [][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "segment-") {
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, ".incomplete.jsonl") {
			if index := bytes.LastIndexByte(raw, '\n'); index >= 0 {
				raw = raw[:index+1]
			} else {
				raw = nil
			}
		}
		if len(raw) == 0 {
			continue
		}
		if raw[len(raw)-1] != '\n' {
			t.Fatalf("%s has a non-terminated complete record", name)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")) {
			payloads = append(payloads, append([]byte(nil), line...))
		}
	}
	return payloads
}

func c17ActivePath(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "segment-") && strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".sealed.jsonl") && !strings.HasSuffix(name, ".incomplete.jsonl") {
			if found != "" {
				t.Fatalf("multiple active segments: %s and %s", found, name)
			}
			found = filepath.Join(directory, name)
		}
	}
	if found == "" {
		t.Fatal("missing active segment")
	}
	return found
}

func c17SealedPaths(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sealed.jsonl") {
			found = append(found, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(found)
	return found
}

func c17Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestSegmentRotationAcrossRecordAndByteBounds(t *testing.T) {
	positive, expected, _, _ := c17Files(t)
	for _, scenario := range []struct {
		name   string
		limits events.Limits
		events []string
		want   c17RotationExpect
	}{
		{name: "record", limits: positive.RecordLimits, events: positive.Events, want: expected.RecordRotation},
		{name: "byte", limits: positive.ByteLimits, events: positive.ByteEvents, want: expected.ByteRotation},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := c17Dir(t)
			w := c17Open(t, directory, scenario.limits)
			c17AppendAll(t, w, scenario.events)
			c17CheckSegments(t, c17Segments(t, w), scenario.want.Segments)
			if got := c17Segments(t, w)[len(scenario.want.Segments)-1].ID; got != scenario.want.ResumeSegment {
				t.Fatalf("resume segment = %s, want %s", got, scenario.want.ResumeSegment)
			}
			payloads := c17RecordPayloads(t, directory)
			if len(payloads) != len(scenario.events) {
				t.Fatalf("record count = %d, want %d", len(payloads), len(scenario.events))
			}
			for i, event := range scenario.events {
				if !bytes.Equal(payloads[i], []byte(event)) {
					t.Fatalf("record %d bytes changed", i)
				}
			}
		})
	}
}

func TestSegmentRecordsSurviveRestartAndRemainImmutable(t *testing.T) {
	positive, expected, _, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	c17AppendAll(t, w, positive.Events)
	firstSealed := c17SealedPaths(t, directory)
	if len(firstSealed) != 1 {
		t.Fatalf("sealed segments = %d, want 1", len(firstSealed))
	}
	firstHash := c17Digest(mustRead(t, firstSealed[0]))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w = c17Open(t, directory, positive.RecordLimits)
	if got := c17Digest(mustRead(t, firstSealed[0])); got != firstHash {
		t.Fatalf("sealed segment hash changed: %s != %s", got, firstHash)
	}
	extra := []string{
		`{"schema_version":"1","sensor_id":"sensor-02","event_id":"event-03","sequence":3,"observed_at":"2026-01-01T00:00:02Z","kind":"http.request","metadata":{"path":"/next"}}`,
		`{"schema_version":"1","sensor_id":"sensor-02","event_id":"event-04","sequence":4,"observed_at":"2026-01-01T00:00:03Z","kind":"http.request","metadata":{"path":"/admin"}}`,
	}
	c17AppendAll(t, w, extra)
	if got := c17Segments(t, w); len(got) != 3 || got[0].ID != expected.RecordRotation.Segments[0].ID || got[1].ID != expected.RecordRotation.Segments[1].ID {
		t.Fatalf("unexpected segments after restart append: %+v", got)
	}
	if got := c17Digest(mustRead(t, firstSealed[0])); got != firstHash {
		t.Fatalf("sealed segment hash changed after append: %s != %s", got, firstHash)
	}
}

func TestSegmentRotationAllowsRetentionOrdinalGaps(t *testing.T) {
	positive, expected, _, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	c17AppendAll(t, w, positive.Events)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sealed := c17SealedPaths(t, directory)
	if len(sealed) != 1 {
		t.Fatalf("sealed segments = %d, want 1", len(sealed))
	}
	if err := os.Remove(sealed[0]); err != nil {
		t.Fatal(err)
	}
	w = c17Open(t, directory, positive.RecordLimits)
	extra := []string{
		`{"schema_version":"1","sensor_id":"sensor-02","event_id":"event-03","sequence":3,"observed_at":"2026-01-01T00:00:02Z","kind":"http.request","metadata":{"path":"/next"}}`,
		`{"schema_version":"1","sensor_id":"sensor-02","event_id":"event-04","sequence":4,"observed_at":"2026-01-01T00:00:03Z","kind":"http.request","metadata":{"path":"/admin"}}`,
	}
	c17AppendAll(t, w, extra)
	segments := c17Segments(t, w)
	if len(segments) != 2 || segments[0].ID != expected.RetentionGap.RemainingSegments[0] || segments[1].ID != expected.RetentionGap.RemainingSegments[1] {
		t.Fatalf("retention gap segments = %+v, want %v", segments, expected.RetentionGap.RemainingSegments)
	}
	if !expected.RetentionGap.GapIsNotEventSequenceGap {
		t.Fatal("fixture conflates segment ordinal gap with event sequence gap")
	}
}

func TestSegmentRotationMarksIncompleteFinalRecordAfterRestart(t *testing.T) {
	positive, expected, _, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.IncompleteLimits)
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

	w = c17Open(t, directory, positive.IncompleteLimits)
	segments := c17Segments(t, w)
	if len(segments) != 2 {
		t.Fatalf("segments after incomplete recovery = %d, want 2", len(segments))
	}
	if segments[1].ID != expected.IncompleteTail.IncompleteSegment || segments[1].Incomplete == nil {
		t.Fatalf("incomplete segment = %+v", segments[1])
	}
	if segments[1].Records != 0 || segments[1].Incomplete.Offset != 0 || segments[1].Incomplete.Bytes != int64(len(tail)) || segments[1].Incomplete.Digest != c17Digest(tail) {
		t.Fatalf("incomplete metadata = %+v", segments[1])
	}
	if got := c17RecordPayloads(t, directory); len(got) != 2 {
		t.Fatalf("valid records after incomplete recovery = %d, want 2", len(got))
	}
	c17AppendAll(t, w, positive.Events[3:4])
	segments = c17Segments(t, w)
	if len(segments) != 3 || segments[2].ID != expected.IncompleteTail.ResumeSegment {
		t.Fatalf("segments after resume = %+v", segments)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w = c17Open(t, directory, positive.IncompleteLimits)
	segments = c17Segments(t, w)
	if len(segments) != 3 || segments[1].Incomplete == nil || segments[1].Incomplete.Digest != c17Digest(tail) {
		t.Fatalf("incomplete marker did not survive restart: %+v", segments)
	}
	payloads := c17RecordPayloads(t, directory)
	if len(payloads) != 3 || !bytes.Equal(payloads[0], []byte(positive.Events[0])) || !bytes.Equal(payloads[1], []byte(positive.Events[1])) || !bytes.Equal(payloads[2], []byte(positive.Events[3])) {
		t.Fatalf("payloads after restart = %d", len(payloads))
	}
}

func TestSegmentAppendRejectsInvalidEventsBeforeWrite(t *testing.T) {
	positive, _, invalid, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	for _, testCase := range invalid.Cases {
		before := c17FileSnapshot(t, directory)
		_, err := w.Append(context.Background(), []byte(testCase.Raw))
		want := c17Error(t, testCase.Error)
		if !errors.Is(err, want) {
			t.Fatalf("%s: error = %v, want %v", testCase.Name, err, want)
		}
		after := c17FileSnapshot(t, directory)
		if before != after {
			t.Fatalf("%s changed segment bytes after rejection", testCase.Name)
		}
	}
}

func TestSegmentRotationRejectsInvalidLimitsAndClosedWriter(t *testing.T) {
	positive, _, invalid, _ := c17Files(t)
	for _, testCase := range invalid.Limits {
		_, err := events.Open(c17Dir(t), events.Limits{
			MaxSegments:          testCase.MaxSegments,
			MaxRecordsPerSegment: testCase.MaxRecordsPerSegment,
			MaxBytesPerSegment:   testCase.MaxBytesPerSegment,
		})
		if !errors.Is(err, c17Error(t, testCase.Error)) {
			t.Fatalf("%s: error = %v", testCase.Name, err)
		}
	}
	var nilWriter *events.Writer
	if _, err := nilWriter.Append(context.Background(), []byte(positive.Events[0])); !errors.Is(err, events.ErrInvalidInput) {
		t.Fatalf("nil append error = %v", err)
	}
	if _, err := nilWriter.Segments(); !errors.Is(err, events.ErrInvalidInput) {
		t.Fatalf("nil segments error = %v", err)
	}
	if err := nilWriter.Close(); !errors.Is(err, events.ErrInvalidInput) {
		t.Fatalf("nil close error = %v", err)
	}
	if _, err := events.Open("", positive.RecordLimits); !errors.Is(err, events.ErrInvalidInput) {
		t.Fatalf("empty directory error = %v", err)
	}
	if _, err := events.Open(filepath.Join(t.TempDir(), "missing", "segments"), positive.RecordLimits); !errors.Is(err, events.ErrRecovery) {
		t.Fatalf("missing parent error = %v", err)
	}

	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	if _, err := events.Open(directory, positive.RecordLimits); !errors.Is(err, events.ErrLocked) {
		t.Fatalf("second writer error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), []byte(positive.Events[0])); !errors.Is(err, events.ErrClosed) {
		t.Fatalf("closed append error = %v", err)
	}
	if _, err := w.Segments(); !errors.Is(err, events.ErrClosed) {
		t.Fatalf("closed segments error = %v", err)
	}
	if _, err := w.AppendRecords(context.Background(), nil); !errors.Is(err, events.ErrClosed) {
		t.Fatalf("closed projection error = %v", err)
	}
	if _, err := w.AppendRecords(nil, nil); !errors.Is(err, events.ErrInvalidInput) {
		t.Fatalf("nil context projection error = %v", err)
	}

	w = c17Open(t, directory, positive.RecordLimits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Append(ctx, []byte(positive.Events[0])); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled append error = %v", err)
	}
	if got := c17Segments(t, w); len(got) != 0 {
		t.Fatalf("canceled append created segments: %+v", got)
	}
	if _, err := w.Append(context.Background(), []byte(positive.Events[0])); err != nil {
		t.Fatalf("append after cancellation: %v", err)
	}
}

func TestSegmentAppendAcceptsMaxFrameAndRejectsOversize(t *testing.T) {
	positive, _, _, _ := c17Files(t)
	directory := c17Dir(t)
	limits := events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 2, MaxBytesPerSegment: contracts.MaxInputBytes + 1}
	w := c17Open(t, directory, limits)
	makeEvent := func(fill int) []byte {
		return []byte(fmt.Sprintf(`{"schema_version":"1","sensor_id":"sensor-01","event_id":"event-max","sequence":1,"observed_at":"2026-01-01T00:00:00Z","kind":"http.request","metadata":{"path":"%s"}}`, strings.Repeat("p", fill)))
	}
	fixed := len(makeEvent(0))
	maximum := makeEvent(contracts.MaxInputBytes - fixed)
	if len(maximum) != contracts.MaxInputBytes {
		t.Fatalf("maximum event length = %d, want %d", len(maximum), contracts.MaxInputBytes)
	}
	if _, err := w.Append(context.Background(), maximum); err != nil {
		t.Fatalf("append maximum frame: %v", err)
	}
	segments := c17Segments(t, w)
	if len(segments) != 1 || segments[0].Records != 1 || segments[0].Bytes != contracts.MaxInputBytes+1 {
		t.Fatalf("maximum frame segment = %+v", segments)
	}
	c17AppendAll(t, w, positive.Events[:1])
	segments = c17Segments(t, w)
	if len(segments) != 2 || !segments[0].Sealed || segments[1].Records != 1 {
		t.Fatalf("byte rotation after maximum frame = %+v", segments)
	}
	before := c17FileSnapshot(t, directory)
	oversized := makeEvent(contracts.MaxInputBytes - fixed + 1)
	if _, err := w.Append(context.Background(), oversized); !errors.Is(err, events.ErrInvalidEvent) {
		t.Fatalf("oversized event error = %v", err)
	}
	if after := c17FileSnapshot(t, directory); after != before {
		t.Fatal("oversized event changed segment bytes")
	}
}

func TestSegmentProjectionRejectsAmbiguousRecords(t *testing.T) {
	positive, _, _, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	for _, records := range [][]storage.Record{
		{{}},
		{{Event: contracts.Event{SchemaVersion: "1"}, Gap: &contracts.SpoolGapRecord{}}},
	} {
		before := c17FileSnapshot(t, directory)
		projection, err := w.AppendRecords(context.Background(), records)
		if !errors.Is(err, events.ErrRecovery) {
			t.Fatalf("projection = %+v error = %v, want recovery", projection, err)
		}
		if after := c17FileSnapshot(t, directory); after != before {
			t.Fatal("ambiguous record changed segment bytes")
		}
	}
}

func TestSegmentProjectionSkipsEnrollmentRecord(t *testing.T) {
	positive, _, _, _ := c17Files(t)
	directory := c17Dir(t)
	w := c17Open(t, directory, positive.RecordLimits)
	before := c17FileSnapshot(t, directory)
	projection, err := w.AppendRecords(context.Background(), []storage.Record{{Enrollment: &contracts.EnrollmentRecord{}}})
	if err != nil || projection.Appended != 0 || projection.Skipped != 1 {
		t.Fatalf("projection = %+v error = %v", projection, err)
	}
	if after := c17FileSnapshot(t, directory); after != before {
		t.Fatal("skipped enrollment record changed segment bytes")
	}
}

func TestSegmentCrashFixtureDeclaresBoundaries(t *testing.T) {
	_, _, _, crash := c17Files(t)
	want := []string{"before_seal_rename", "after_seal_rename", "after_next_create", "torn_first_record", "before_incomplete_rename"}
	if len(crash.Phases) != len(want) {
		t.Fatalf("crash phases = %d, want %d", len(crash.Phases), len(want))
	}
	for i, phase := range crash.Phases {
		if phase.Name != want[i] || phase.ValidRecords != 2 || phase.ResumeSegment == "" || (phase.Incomplete && phase.IncompleteSegment == "") {
			t.Fatalf("crash phase %d = %+v, want %s", i, phase, want[i])
		}
	}
}

func TestSegmentRotationRejectsCorruptAndUnsafeState(t *testing.T) {
	positive, _, invalid, _ := c17Files(t)
	baseLimits := positive.RecordLimits
	one := func(t *testing.T) string {
		t.Helper()
		directory := c17Dir(t)
		w := c17Open(t, directory, baseLimits)
		c17AppendAll(t, w, positive.Events[:1])
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	tests := map[string]func(t *testing.T) (string, events.Limits){
		"unknown_file": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"zero_ordinal": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			zero := filepath.Join(directory, "segment-00000000000000000000.jsonl")
			if err := os.Rename(active, zero); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"symlink_segment": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			target := filepath.Join(t.TempDir(), "target.jsonl")
			if err := os.WriteFile(target, []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(active); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, active); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"hardlink_segment": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			raw := mustRead(t, active)
			if err := os.Remove(active); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target.jsonl")
			if err := os.WriteFile(target, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, active); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"public_segment_mode": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			if err := os.Chmod(c17ActivePath(t, directory), 0644); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"sealed_tail": func(t *testing.T) (string, events.Limits) {
			directory := c17Dir(t)
			limits := baseLimits
			limits.MaxRecordsPerSegment = 1
			w := c17Open(t, directory, limits)
			c17AppendAll(t, w, positive.Events[:2])
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			sealed := c17SealedPaths(t, directory)
			if len(sealed) != 1 {
				t.Fatalf("sealed segments = %d", len(sealed))
			}
			f, err := os.OpenFile(sealed[0], os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write([]byte("{")); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			return directory, limits
		},
		"incomplete_without_tail": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			incomplete := strings.TrimSuffix(active, ".jsonl") + ".incomplete.jsonl"
			if err := os.Rename(active, incomplete); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"duplicate_ordinal": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			sealed := strings.TrimSuffix(active, ".jsonl") + ".sealed.jsonl"
			raw := mustRead(t, active)
			if err := os.WriteFile(sealed, raw, 0600); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"two_active_segments": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			active := c17ActivePath(t, directory)
			second := filepath.Join(directory, "segment-00000000000000000002.jsonl")
			raw := mustRead(t, active)
			if err := os.WriteFile(second, raw, 0600); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"oversized_segment": func(t *testing.T) (string, events.Limits) {
			directory := one(t)
			f, err := os.OpenFile(c17ActivePath(t, directory), os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write(bytes.Repeat([]byte(" "), int(baseLimits.MaxBytesPerSegment)+1)); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			return directory, baseLimits
		},
		"too_many_records": func(t *testing.T) (string, events.Limits) {
			directory := c17Dir(t)
			limits := baseLimits
			limits.MaxRecordsPerSegment = 2
			w := c17Open(t, directory, limits)
			c17AppendAll(t, w, positive.Events[:2])
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			limits.MaxRecordsPerSegment = 1
			return directory, limits
		},
		"too_many_segments": func(t *testing.T) (string, events.Limits) {
			directory := c17Dir(t)
			limits := baseLimits
			limits.MaxRecordsPerSegment = 1
			limits.MaxSegments = 3
			w := c17Open(t, directory, limits)
			c17AppendAll(t, w, positive.Events[:3])
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			limits.MaxSegments = 2
			return directory, limits
		},
		"symlinked_directory": func(t *testing.T) (string, events.Limits) {
			target := filepath.Join(t.TempDir(), "real")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link, baseLimits
		},
		"symlinked_parent": func(t *testing.T) (string, events.Limits) {
			target := filepath.Join(t.TempDir(), "real")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "segments"), baseLimits
		},
	}
	if len(tests) != len(invalid.UnsafeState) {
		t.Fatalf("unsafe-state coverage = %d, fixture = %d", len(tests), len(invalid.UnsafeState))
	}
	for _, name := range invalid.UnsafeState {
		test, ok := tests[name]
		if !ok {
			t.Fatalf("missing unsafe-state case %s", name)
		}
		t.Run(name, func(t *testing.T) {
			directory, limits := test(t)
			w, err := events.Open(directory, limits)
			if w != nil {
				_ = w.Close()
			}
			if !errors.Is(err, events.ErrRecovery) {
				t.Fatalf("error = %v, want recovery", err)
			}
		})
	}
}

func TestSegmentProjectionSkipsNonEventRecords(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	verifier := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	store := openStore(t, storePath(t), f.StorageLimits)
	applier := c11Applier(t, store, verifier)
	c11Apply(t, applier, key, f.Payloads["initial"])
	queue := c14Spool(t, store, applier)
	for i := 0; i < 2; i++ {
		if _, err := queue.Enqueue(context.Background(), []byte(f.Events[i])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := queue.Enqueue(context.Background(), []byte(f.Events[2])); !errors.Is(err, spool.ErrDropped) {
		t.Fatalf("expected explicit gap, got %v", err)
	}
	ingestor := c16Ingestor(t, store, applier)
	if _, err := ingestor.Ingest(context.Background(), f.SensorID, f.batch(t, "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(context.Background(), []byte(f.Events[3])); err != nil {
		t.Fatal(err)
	}
	incident := contracts.IncidentTriageRecord{
		SchemaVersion: contracts.SchemaVersion,
		Kind:          contracts.IncidentTriage,
		IncidentID:    "incident-01",
		Status:        "investigating",
		Reason:        "synthetic triage label",
		KeyDigest:     strings.Repeat("a", 64),
		TriagedAt:     "2026-01-01T00:00:00Z",
	}
	incidentRaw, err := json.Marshal(incident)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), "incident-triage/test", incidentRaw); err != nil {
		t.Fatal(err)
	}
	records, err := store.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory := c17Dir(t)
	w := c17Open(t, directory, events.Limits{MaxSegments: 8, MaxRecordsPerSegment: 100, MaxBytesPerSegment: 8193})
	projection, err := w.AppendRecords(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Appended != 3 || projection.Skipped != 5 {
		t.Fatalf("projection = %+v, want appended 3 skipped 5", projection)
	}
	payloads := c17RecordPayloads(t, directory)
	want := [][]byte{
		bytes.TrimSuffix([]byte(f.Events[0]), []byte("\n")),
		bytes.TrimSuffix([]byte(f.Events[1]), []byte("\n")),
		bytes.TrimSuffix([]byte(f.Events[3]), []byte("\n")),
	}
	if len(payloads) != len(want) {
		t.Fatalf("payloads = %d, want %d", len(payloads), len(want))
	}
	for i := range want {
		if !bytes.Equal(payloads[i], want[i]) {
			t.Fatalf("payload %d = %s, want %s", i, payloads[i], want[i])
		}
	}
	for _, payload := range payloads {
		if bytes.Contains(payload, []byte("spool.gap")) || bytes.Contains(payload, []byte("spool.ack")) || bytes.Contains(payload, []byte("config.applied")) || bytes.Contains(payload, []byte("incident.triage")) {
			t.Fatalf("non-event record was segmented: %s", payload)
		}
	}
}

func TestSegmentProjectionFailureDoesNotRewriteC16Acknowledgement(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	verifier := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	store := openStore(t, storePath(t), f.StorageLimits)
	applier := c11Applier(t, store, verifier)
	c11Apply(t, applier, key, f.Payloads["initial"])
	ingestor := c16Ingestor(t, store, applier)
	first, err := ingestor.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory := c17Dir(t)
	w := c17Open(t, directory, events.Limits{MaxSegments: 1, MaxRecordsPerSegment: 1, MaxBytesPerSegment: 8193})
	projection, err := w.AppendRecords(context.Background(), before)
	if !errors.Is(err, events.ErrQuota) || projection.Appended != 1 {
		t.Fatalf("projection = %+v error = %v, want one append then quota", projection, err)
	}
	after, err := store.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("segment failure changed C16 record count: %d -> %d", len(before), len(after))
	}
	second, err := ingestor.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != len(first.Events) {
		t.Fatalf("C16 retry changed acknowledgements: %+v != %+v", second, first)
	}
	for i := range first.Events {
		if second.Events[i].AckReceipt != first.Events[i].AckReceipt || second.Events[i].EventReceipt != first.Events[i].EventReceipt {
			t.Fatalf("C16 retry rewrote acknowledgement %d", i)
		}
	}
}

func TestSegmentRotationHasNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("../internal/events/*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no internal/events source files")
	}
	allowed := map[string]bool{
		"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true,
		"errors": true, "fmt": true, "io": true, "math": true, "os": true,
		"path/filepath": true, "sort": true, "strconv": true, "strings": true,
		"sync": true, "syscall": true, "time": true, "unicode/utf8": true,
		"github.com/Parsa-Emami/Miragemesh/internal/contracts": true,
		"github.com/Parsa-Emami/Miragemesh/internal/storage":   true,
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" {
				t.Fatalf("%s imports forbidden package %s", name, path)
			}
			if !allowed[path] {
				t.Fatalf("%s imports unexpected package %s", name, path)
			}
		}
	}
}

func c17Error(t *testing.T, text string) error {
	t.Helper()
	switch text {
	case "invalid input":
		return events.ErrInvalidInput
	case "invalid event":
		return events.ErrInvalidEvent
	case "recovery required":
		return events.ErrRecovery
	case "quota exceeded":
		return events.ErrQuota
	default:
		t.Fatalf("unknown C17 fixture error %q", text)
		return nil
	}
}

func c17FileSnapshot(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var result string
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		result += fmt.Sprintf("%s:%d:%s;", entry.Name(), info.Size(), c17Digest(mustRead(t, filepath.Join(directory, entry.Name()))))
	}
	return result
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type c24Inputs struct {
	FixtureVersion  int             `json:"fixture_version"`
	License         string          `json:"license"`
	Provenance      string          `json:"provenance"`
	Now             string          `json:"now"`
	SensorID        string          `json:"sensor_id"`
	LifetimeSeconds int64           `json:"lifetime_seconds"`
	OverlapSeconds  int64           `json:"overlap_seconds"`
	SourceEvent     json.RawMessage `json:"source_event"`
}

func c24Input(t *testing.T) c24Inputs {
	t.Helper()
	var f c24Inputs
	for _, name := range []string{"positive", "negative", "expected-output"} {
		raw, err := os.ReadFile("fixtures/miragemesh/C24/" + name + ".json")
		var meta c24Inputs
		if err != nil || json.Unmarshal(raw, &meta) != nil || meta.FixtureVersion != 1 || meta.License != "Apache-2.0" || meta.Provenance == "" {
			t.Fatal("missing or malformed C24 fixture", name, err)
		}
		if name == "positive" {
			f = meta
			if f.SensorID == "" || f.LifetimeSeconds != 86400 || f.OverlapSeconds != 3600 || len(f.SourceEvent) == 0 {
				t.Fatal("invalid positive C24 inputs")
			}
		}
		if name == "negative" {
			var negative struct {
				Cases, CrashPhases, Faults []string
				Crash                      []string `json:"crash_phases"`
			}
			if json.Unmarshal(raw, &negative) != nil || len(negative.Cases) != 12 || len(negative.Crash) != 5 || len(negative.Faults) != 9 {
				t.Fatal("invalid C24 negative fixture")
			}
		}
		if name == "expected-output" {
			var expected struct {
				Until     string `json:"overlap_until"`
				Initial   uint64 `json:"initial_revision"`
				Rotated   uint64 `json:"rotated_revision"`
				Recovered uint64 `json:"recovered_revision"`
			}
			if json.Unmarshal(raw, &expected) != nil || expected.Until != "2026-01-01T01:00:00Z" || expected.Initial != 1 || expected.Rotated != 2 || expected.Recovered != 3 {
				t.Fatal("invalid C24 expected outcomes")
			}
		}
	}
	return f
}

func c24Signer(t *testing.T, key string) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		t.Fatal("missing temporary signer")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(crypto.Signer)
}

func c24Rotator(t *testing.T, store *storage.Store, m c24fixture.Material, clock func() time.Time) *pki.Rotator {
	t.Helper()
	r, err := pki.NewRotator(context.Background(), store, pki.RotationOptions{IssuerCertificatePEM: m.Authority, MaxSensors: 16, MaxLifetime: 24 * time.Hour, MaxOverlap: time.Hour, MaxRecoveryTTL: 15 * time.Minute, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func c24Guard(t *testing.T, m c24fixture.Material, r *pki.Rotator, clock func() time.Time) *pki.Guard {
	t.Helper()
	block, _ := pem.Decode([]byte(m.Initial))
	sum := sha256.Sum256(block.Bytes)
	g, err := pki.New(pki.Options{Anchors: []string{m.Authority}, ServerCertificatePEM: m.Server, ServerKeyPEM: m.ServerKey, RevocationListPEM: m.CRL, Scopes: map[string][]string{hex.EncodeToString(sum[:]): {"sensor-24"}}, MaxAnchors: 1, MaxScopes: 16, MaxScopesPerIdentity: 1, Clock: clock, Rotation: r})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func c24Handshake(t *testing.T, m c24fixture.Material, g *pki.Guard, cert, key string, clock func() time.Time) (tls.ConnectionState, error) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(m.Authority))
	type result struct {
		state tls.ConnectionState
		err   error
	}
	finished := make(chan result, 1)
	go func() {
		defer server.Close()
		conn := tls.Server(server, g.TLSConfig())
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err := g.Authenticate(conn)
		state := conn.ConnectionState()
		if err == nil {
			_, err = conn.Write([]byte{1})
		}
		finished <- result{state, err}
	}()
	conn := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, Time: clock})
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	handshakeErr := conn.Handshake()
	if handshakeErr == nil {
		var b [1]byte
		_, handshakeErr = conn.Read(b[:])
	}
	got := <-finished
	if got.err == nil && handshakeErr != nil {
		t.Fatal("client failed despite server success", handshakeErr)
	}
	return got.state, got.err
}

func TestCertificateRotationOverlapUsesRealTLSAndSurvivesRestart(t *testing.T) {
	f := c24Input(t)
	now, _ := time.Parse(time.RFC3339, f.Now)
	clock := func() time.Time { return now }
	m := c24fixture.Generate(now, f.SensorID)
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	r := c24Rotator(t, store, m, clock)
	registered, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-register-synthetic-key"})
	if err != nil || registered.Revision != 1 {
		t.Fatal(registered, err)
	}
	guard := c24Guard(t, m, r, clock)
	oldState, err := c24Handshake(t, m, guard, m.Initial, m.InitialKey, clock)
	if err != nil {
		t.Fatal("initial TLS failed", err)
	}
	if err := guard.Allows(oldState, f.SensorID); err != nil {
		t.Fatal(err)
	}
	if _, err := sensor.Accept(ctx, store, f.SourceEvent); err != nil {
		t.Fatal("rotation record broke sensor sequence", err)
	}
	request := pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: time.Duration(f.LifetimeSeconds) * time.Second, Overlap: time.Duration(f.OverlapSeconds) * time.Second, IdempotencyKey: "c24-rotate-synthetic-key"}
	rotated, err := r.Rotate(ctx, request, c24Signer(t, m.AuthorityKey))
	if err != nil || rotated.Revision != 2 || rotated.OverlapUntil != "2026-01-01T01:00:00Z" {
		t.Fatal(rotated, err)
	}
	if _, err := c24Handshake(t, m, guard, m.Initial, m.InitialKey, clock); err != nil {
		t.Fatal("old cert rejected during overlap", err)
	}
	if _, err := c24Handshake(t, m, guard, rotated.CertificatePEM, m.Key, clock); err != nil {
		t.Fatal("new cert rejected during overlap", err)
	}
	now = now.Add(time.Hour - time.Nanosecond)
	if _, err := c24Handshake(t, m, guard, m.Initial, m.InitialKey, clock); err != nil {
		t.Fatal("old cert rejected before cutoff", err)
	}
	now = now.Add(time.Nanosecond)
	if _, err := c24Handshake(t, m, guard, m.Initial, m.InitialKey, clock); !errors.Is(err, pki.ErrRetired) {
		t.Fatal("old certificate survived cutoff", err)
	}
	if err := guard.Allows(oldState, f.SensorID); !errors.Is(err, pki.ErrRetired) {
		t.Fatal("existing connection transcript bypassed cutoff", err)
	}
	if _, err := c24Handshake(t, m, guard, rotated.CertificatePEM, m.Key, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, path, storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	r = c24Rotator(t, store, m, clock)
	guard = c24Guard(t, m, r, clock)
	if _, err := c24Handshake(t, m, guard, m.Initial, m.InitialKey, clock); !errors.Is(err, pki.ErrRetired) {
		t.Fatal("restart resurrected retired cert", err)
	}
	replay, err := r.Rotate(ctx, request, c24Signer(t, m.AuthorityKey))
	if err != nil || !replay.Replayed || replay.Receipt != rotated.Receipt || replay.CertificatePEM != rotated.CertificatePEM {
		t.Fatal("retry reissued certificate", replay, err)
	}
	writer := c17Open(t, c17Dir(t), events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 4, MaxBytesPerSegment: 32768})
	records, _ := store.Records(ctx)
	projected, err := writer.AppendRecords(ctx, records)
	if err != nil || projected.Appended != 1 || projected.Skipped != 2 {
		t.Fatal("rotation was treated as an event", projected, err)
	}
}

func TestCertificateRotationOfflineRecoveryConsumesScopedTokenAtomically(t *testing.T) {
	f := c24Input(t)
	now, _ := time.Parse(time.RFC3339, f.Now)
	clock := func() time.Time { return now }
	m := c24fixture.Generate(now, f.SensorID)
	ctx := context.Background()
	store := openStore(t, storePath(t), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	r := c24Rotator(t, store, m, clock)
	signer := c24Signer(t, m.AuthorityKey)
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-register-synthetic-key"}); err != nil {
		t.Fatal(err)
	}
	rotated, err := r.Rotate(ctx, pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-rotate-synthetic-key"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	tokens, err := enrollment.New(store, 15*time.Minute, clock)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokens.Issue(ctx, f.SensorID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := pki.RecoverCertificate{RotateCertificate: pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 2, CSRPEM: m.RecoveryCSR, Lifetime: 24 * time.Hour, IdempotencyKey: "c24-recover-synthetic-key"}, Token: token.Token}
	recovered, err := r.Recover(ctx, request, signer)
	if err != nil || recovered.Revision != 3 {
		t.Fatal(recovered, err)
	}
	if _, err := tokens.Consume(ctx, token.Token, f.SensorID); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatal("recovery did not atomically consume enrollment token", err)
	}
	replay, err := r.Recover(ctx, request, signer)
	if err != nil || !replay.Replayed || replay.Receipt != recovered.Receipt || replay.CertificatePEM != recovered.CertificatePEM {
		t.Fatal("recovery retry lost result", replay, err)
	}
	request.IdempotencyKey = "c24-another-recovery-key"
	request.ExpectedRevision = 3
	request.CSRPEM, _ = c24fixture.NewCSR(f.SensorID)
	if _, err := r.Recover(ctx, request, signer); !errors.Is(err, pki.ErrRecoveryTokenUsed) {
		t.Fatal("token accepted twice", err)
	}
	guard := c24Guard(t, m, r, clock)
	for _, pair := range [][2]string{{m.Initial, m.InitialKey}, {rotated.CertificatePEM, m.Key}} {
		if _, err := c24Handshake(t, m, guard, pair[0], pair[1], clock); !errors.Is(err, pki.ErrRetired) {
			t.Fatal("recovery retained old credential", err)
		}
	}
	if _, err := c24Handshake(t, m, guard, recovered.CertificatePEM, m.RecoveryKey, clock); err != nil {
		t.Fatal("offline sensor cannot reconnect", err)
	}
	records, _ := store.Records(ctx)
	for _, record := range records {
		if bytes.Contains(record.Input, []byte(token.Token)) || bytes.Contains(record.Input, []byte("PRIVATE KEY")) {
			t.Fatal("secret persisted in rotation state")
		}
	}
}

type c24TestSigner struct {
	crypto.Signer
	before func()
}

func (s c24TestSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.before != nil {
		s.before()
	}
	return s.Signer.Sign(random, digest, opts)
}

func TestCertificateRotationRejectsInvalidCSRPolicyAndStaleIntent(t *testing.T) {
	f := c24Input(t)
	at, _ := time.Parse(time.RFC3339, f.Now)
	m := c24fixture.Generate(at, f.SensorID)
	ctx := context.Background()
	store := openStore(t, storePath(t), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	clock := func() time.Time { return at }
	r := c24Rotator(t, store, m, clock)
	signer := c24Signer(t, m.AuthorityKey)
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-register-synthetic-key"}); err != nil {
		t.Fatal(err)
	}
	baseline, _ := store.Records(ctx)
	request := pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-rotate-synthetic-key"}
	for _, scenario := range []string{"malformed_csr", "invalid_csr_signature", "wrong_signer", "stale_revision", "overlap_exceeds_lifetime", "missing_prerequisite", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := request
			sign := signer
			runctx := ctx
			expected := pki.ErrInvalidInput
			switch scenario {
			case "malformed_csr":
				candidate.CSRPEM = "not a CSR"
			case "invalid_csr_signature":
				block, _ := pem.Decode([]byte(m.CSR))
				block.Bytes[len(block.Bytes)-1] ^= 1
				candidate.CSRPEM = string(pem.EncodeToMemory(block))
			case "wrong_signer":
				sign = c24Signer(t, m.InitialKey)
				expected = pki.ErrSigner
			case "stale_revision":
				candidate.ExpectedRevision = 2
				expected = pki.ErrRotationConflict
			case "overlap_exceeds_lifetime":
				candidate.Lifetime = time.Hour
			case "missing_prerequisite":
				sign = nil
				expected = pki.ErrSigner
			case "canceled":
				var cancel context.CancelFunc
				runctx, cancel = context.WithCancel(ctx)
				cancel()
				expected = context.Canceled
			}
			if _, err := r.Rotate(runctx, candidate, sign); !errors.Is(err, expected) {
				t.Fatalf("%s: %v want %v", scenario, err, expected)
			}
			records, _ := store.Records(ctx)
			if len(records) != len(baseline) {
				t.Fatal("rejected request changed durable history")
			}
		})
	}
	rotated, err := r.Rotate(ctx, request, signer)
	if err != nil {
		t.Fatal(err)
	}
	nextCSR, _ := c24fixture.NewCSR(f.SensorID)
	request.ExpectedRevision = 2
	request.CSRPEM = nextCSR
	request.IdempotencyKey = "c24-another-rotate-key"
	if _, err := r.Rotate(ctx, request, signer); !errors.Is(err, pki.ErrRotationBusy) {
		t.Fatal("more than two simultaneous credentials admitted", err)
	}
	snapshot, err := r.Snapshot(ctx)
	if err != nil || len(snapshot.Sensors) != 1 || snapshot.Sensors[0].Fingerprint != rotated.Fingerprint || snapshot.Sensors[0].Status != "overlap" {
		t.Fatal(snapshot, err)
	}
	snapshot.Sensors[0].Fingerprint = "forged"
	again, _ := r.Snapshot(ctx)
	if again.Sensors[0].Fingerprint != rotated.Fingerprint {
		t.Fatal("snapshot aliases policy")
	}
}

func TestCertificateRotationRecoverySerializesWithEnrollmentConsumption(t *testing.T) {
	f := c24Input(t)
	now, _ := time.Parse(time.RFC3339, f.Now)
	m := c24fixture.Generate(now, f.SensorID)
	ctx := context.Background()
	clock := func() time.Time { return now }
	store := openStore(t, storePath(t), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	r := c24Rotator(t, store, m, clock)
	signer := c24Signer(t, m.AuthorityKey)
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-race-register-key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx, pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-race-rotate-key"}, signer); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	tokens, _ := enrollment.New(store, 15*time.Minute, clock)
	token, err := tokens.Issue(ctx, f.SensorID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	recoveryResult := make(chan error, 1)
	consumptionResult := make(chan error, 1)
	go func() {
		<-gate
		_, err := r.Recover(ctx, pki.RecoverCertificate{RotateCertificate: pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 2, CSRPEM: m.RecoveryCSR, Lifetime: 24 * time.Hour, IdempotencyKey: "c24-race-recover-key"}, Token: token.Token}, signer)
		recoveryResult <- err
	}()
	go func() { <-gate; _, err := tokens.Consume(ctx, token.Token, f.SensorID); consumptionResult <- err }()
	close(gate)
	recoveryErr, consumptionErr := <-recoveryResult, <-consumptionResult
	if recoveryErr == nil {
		if !errors.Is(consumptionErr, enrollment.ErrReplay) {
			t.Fatal("recovery and enrollment both consumed token", consumptionErr)
		}
	} else if !errors.Is(recoveryErr, pki.ErrRecoveryTokenUsed) || consumptionErr != nil {
		t.Fatal("invalid cross-service race result", recoveryErr, consumptionErr)
	}
	records, err := store.Records(ctx)
	if err != nil || len(records) != 4 {
		t.Fatal("token race split publication", len(records), err)
	}
	if _, err := r.Snapshot(ctx); err != nil {
		t.Fatal("token race corrupted history", err)
	}
}

func TestCertificateRotationRecoveryRejectsCrossScopeExpiryAndLateSigner(t *testing.T) {
	f := c24Input(t)
	base, _ := time.Parse(time.RFC3339, f.Now)
	ctx := context.Background()
	for _, scenario := range []string{"wrong_sensor_token", "expired_token", "consumed_token", "late_signer", "canceled_signer"} {
		t.Run(scenario, func(t *testing.T) {
			now := base
			m := c24fixture.Generate(now, f.SensorID)
			store := openStore(t, storePath(t), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
			clock := func() time.Time { return now }
			r := c24Rotator(t, store, m, clock)
			signer := c24Signer(t, m.AuthorityKey)
			if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-register-synthetic-key"}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Rotate(ctx, pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-rotate-synthetic-key"}, signer); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Hour)
			tokens, _ := enrollment.New(store, 15*time.Minute, clock)
			scope := f.SensorID
			if scenario == "wrong_sensor_token" {
				scope = "another-sensor"
			}
			token, err := tokens.Issue(ctx, scope, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			expected := pki.ErrRecoveryToken
			runctx := ctx
			sign := crypto.Signer(signer)
			if scenario == "consumed_token" {
				if _, err := tokens.Consume(ctx, token.Token, f.SensorID); err != nil {
					t.Fatal(err)
				}
				expected = pki.ErrRecoveryTokenUsed
			}
			if scenario == "expired_token" {
				now = now.Add(time.Minute)
			}
			if scenario == "late_signer" {
				sign = c24TestSigner{Signer: signer, before: func() { now = now.Add(time.Minute) }}
			}
			if scenario == "canceled_signer" {
				var cancel context.CancelFunc
				runctx, cancel = context.WithCancel(ctx)
				sign = c24TestSigner{Signer: signer, before: cancel}
				expected = context.Canceled
			}
			records, _ := store.Records(ctx)
			request := pki.RecoverCertificate{RotateCertificate: pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 2, CSRPEM: m.RecoveryCSR, Lifetime: 24 * time.Hour, IdempotencyKey: "c24-recover-synthetic-key"}, Token: token.Token}
			if _, err := r.Recover(runctx, request, sign); !errors.Is(err, expected) {
				t.Fatalf("%s: %v want %v", scenario, err, expected)
			}
			after, _ := store.Records(ctx)
			if len(after) != len(records) {
				t.Fatal("rejected recovery consumed token or issued credential")
			}
		})
	}
}

func TestCertificateRotationConcurrentReplayAndForgedHistory(t *testing.T) {
	f := c24Input(t)
	now, _ := time.Parse(time.RFC3339, f.Now)
	m := c24fixture.Generate(now, f.SensorID)
	clock := func() time.Time { return now }
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	r := c24Rotator(t, store, m, clock)
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: f.SensorID, CertificatePEM: m.Initial, IdempotencyKey: "c24-register-synthetic-key"}); err != nil {
		t.Fatal(err)
	}
	request := pki.RotateCertificate{SensorID: f.SensorID, ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-rotate-synthetic-key"}
	other := c24Rotator(t, store, m, clock)
	signer := c24Signer(t, m.AuthorityKey)
	var wg sync.WaitGroup
	results := make(chan pki.CertificateResult, 8)
	failures := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			service := r
			if i%2 == 1 {
				service = other
			}
			result, err := service.Rotate(ctx, request, signer)
			results <- result
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	issued := 0
	var certificate string
	for result := range results {
		if !result.Replayed {
			issued++
		}
		if certificate != "" && certificate != result.CertificatePEM {
			t.Fatal("retries generated different certificates")
		}
		certificate = result.CertificatePEM
	}
	if issued != 1 {
		t.Fatal("concurrent requests reissued credential", issued)
	}
	records, _ := store.Records(ctx)
	if len(records) != 2 {
		t.Fatal("concurrent generation count", len(records))
	}
	request.CSRPEM = m.RecoveryCSR
	if _, err := r.Rotate(ctx, request, signer); !errors.Is(err, pki.ErrRotationConflict) {
		t.Fatal("same-key changed CSR accepted", err)
	}
	forged := *records[1].Rotation
	forged.Revision = 3
	forged.PreviousFingerprint = fingerprintDERForC24(t, certificate)
	forged.AcceptedAt = "2026-01-01T02:00:00Z"
	forged.OverlapUntil = "2026-01-01T03:00:00Z"
	forged.KeyDigest = strings.Repeat("b", 64)
	forged.RequestDigest = contracts.CertificateIntentDigest(forged)
	raw, _ := json.Marshal(forged)
	if _, err := store.Commit(ctx, "certificate/"+forged.KeyDigest, raw); err != nil {
		t.Fatal("could not set up semantically forged fixture", err)
	}
	if _, err := r.Snapshot(ctx); !errors.Is(err, storage.ErrRecovery) {
		t.Fatal("forged certificate history was trusted", err)
	}
}

func fingerprintDERForC24(t *testing.T, text string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("invalid certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestCertificateRotationBoundsAndNoEgress(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m := c24fixture.Generate(now, "sensor-24")
	dir := storePath(t)
	store := openStore(t, dir, storage.Limits{MaxOperations: 2, MaxBytes: 1048576, MaxManifestBytes: 65536})
	options := pki.RotationOptions{IssuerCertificatePEM: m.Authority, MaxSensors: 1, MaxLifetime: 24 * time.Hour, MaxOverlap: time.Hour, MaxRecoveryTTL: 15 * time.Minute, Clock: clock}
	if _, err := pki.NewRotator(ctx, nil, options); !errors.Is(err, pki.ErrInvalidInput) {
		t.Fatal("missing store accepted", err)
	}
	bad := options
	bad.MaxOverlap = bad.MaxLifetime
	if _, err := pki.NewRotator(ctx, store, bad); !errors.Is(err, pki.ErrInvalidInput) {
		t.Fatal("incoherent policy accepted", err)
	}
	r, err := pki.NewRotator(ctx, store, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: "sensor-24", CertificatePEM: m.Initial, IdempotencyKey: "c24-bounds-register-key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, pki.RegisterCertificate{SensorID: "other", CertificatePEM: m.Initial, IdempotencyKey: "c24-bounds-another-key"}); !errors.Is(err, storage.ErrQuota) {
		t.Fatal("sensor limit ignored", err)
	}
	if _, err := r.Rotate(ctx, pki.RotateCertificate{SensorID: "sensor-24", ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-bounds-rotate-key"}, c24Signer(t, m.AuthorityKey)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	csr, _ := c24fixture.NewCSR("sensor-24")
	before := c09ManifestDigest(t, dir)
	if _, err := r.Rotate(ctx, pki.RotateCertificate{SensorID: "sensor-24", ExpectedRevision: 2, CSRPEM: csr, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-bounds-over-quota"}, c24Signer(t, m.AuthorityKey)); !errors.Is(err, storage.ErrQuota) {
		t.Fatal("storage quota ignored", err)
	}
	if c09ManifestDigest(t, dir) != before {
		t.Fatal("quota changed active credential")
	}
	files, err := filepath.Glob("../internal/pki/*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("missing PKI source", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" {
				t.Fatal("PKI attempts external transport or process execution", path)
			}
		}
	}
}
