package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var c17CLIStorageLimits = storage.Limits{
	MaxOperations:    16,
	MaxBytes:         1 << 20,
	MaxManifestBytes: 1 << 16,
}

var c17CLISegmentLimits = events.Limits{
	MaxSegments:          8,
	MaxRecordsPerSegment: 2,
	MaxBytesPerSegment:   contracts.MaxInputBytes + 1,
}

type c17CLIFixture struct {
	FixtureVersion int      `json:"fixture_version"`
	License        string   `json:"license"`
	Provenance     string   `json:"provenance"`
	Events         []string `json:"events"`
}

func c17CLIEvents(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C17/positive.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture c17CLIFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FixtureVersion != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" || len(fixture.Events) < 3 {
		t.Fatal("invalid C17 runtime fixture")
	}
	return fixture.Events
}

func c17CLIStore(t *testing.T, directory string, events []string) []storage.Record {
	t.Helper()
	store, err := storage.Open(directory, c17CLIStorageLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	ctx := context.Background()
	for index, event := range events {
		if _, err := store.Commit(ctx, fmt.Sprintf("event-%02d", index+1), []byte(event)); err != nil {
			t.Fatal(err)
		}
	}
	gap, err := json.Marshal(contracts.SpoolGapRecord{
		SchemaVersion: contracts.SchemaVersion,
		Kind:          contracts.SpoolGap,
		SensorID:      "sensor-01",
		EventID:       "event-gap",
		Sequence:      99,
		InputDigest:   strings.Repeat("0", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, sensor.GapOperationID("sensor-01", 99), gap); err != nil {
		t.Fatal(err)
	}
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func c17CLIReadRecords(t *testing.T, directory string) []storage.Record {
	t.Helper()
	store, err := storage.Open(directory, c17CLIStorageLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	records, err := store.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return records
}

type c17CLIResult struct {
	outcome  segmentProjectionOutcome
	exitCode int
	stdout   string
	stderr   string
}

func c19CLIRun(t *testing.T, storageDir, segmentDir string, rateLimit, windowSeconds int) c17CLIResult {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSegmentProjectionCLIHelper$", "-test.timeout=20s")
	command.Env = append(os.Environ(),
		"MIRAGEMESH_C17_PROJECT_HELPER=1",
		"MIRAGEMESH_C17_STORAGE="+storageDir,
		"MIRAGEMESH_C17_SEGMENTS="+segmentDir,
		"MIRAGEMESH_C17_STORAGE_MAX_OPERATIONS="+strconv.Itoa(c17CLIStorageLimits.MaxOperations),
		"MIRAGEMESH_C17_STORAGE_MAX_BYTES="+strconv.FormatInt(c17CLIStorageLimits.MaxBytes, 10),
		"MIRAGEMESH_C17_STORAGE_MAX_MANIFEST_BYTES="+strconv.FormatInt(c17CLIStorageLimits.MaxManifestBytes, 10),
		"MIRAGEMESH_C17_SEGMENT_MAX_COUNT="+strconv.Itoa(c17CLISegmentLimits.MaxSegments),
		"MIRAGEMESH_C17_SEGMENT_MAX_RECORDS="+strconv.FormatInt(c17CLISegmentLimits.MaxRecordsPerSegment, 10),
		"MIRAGEMESH_C17_SEGMENT_MAX_BYTES="+strconv.FormatInt(c17CLISegmentLimits.MaxBytesPerSegment, 10),
		"MIRAGEMESH_C19_RATE_LIMIT="+strconv.Itoa(rateLimit),
		"MIRAGEMESH_C19_WINDOW_SECONDS="+strconv.Itoa(windowSeconds),
	)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("segment projection helper failed: %v", err)
		}
		exitCode = exit.ExitCode()
	}
	var outcome segmentProjectionOutcome
	if err := json.NewDecoder(bytes.NewReader(stdout.Bytes())).Decode(&outcome); err != nil {
		t.Fatalf("decode projection outcome: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return c17CLIResult{outcome: outcome, exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func c17CLIRun(t *testing.T, storageDir, segmentDir string) c17CLIResult {
	t.Helper()
	return c17CLIRunWithLimits(t, storageDir, segmentDir, c17CLIStorageLimits, c17CLISegmentLimits)
}

func c17CLIRunWithLimits(t *testing.T, storageDir, segmentDir string, storageLimits storage.Limits, segmentLimits events.Limits) c17CLIResult {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSegmentProjectionCLIHelper$", "-test.timeout=20s")
	command.Env = append(os.Environ(),
		"MIRAGEMESH_C17_PROJECT_HELPER=1",
		"MIRAGEMESH_C17_STORAGE="+storageDir,
		"MIRAGEMESH_C17_SEGMENTS="+segmentDir,
		"MIRAGEMESH_C17_STORAGE_MAX_OPERATIONS="+strconv.Itoa(storageLimits.MaxOperations),
		"MIRAGEMESH_C17_STORAGE_MAX_BYTES="+strconv.FormatInt(storageLimits.MaxBytes, 10),
		"MIRAGEMESH_C17_STORAGE_MAX_MANIFEST_BYTES="+strconv.FormatInt(storageLimits.MaxManifestBytes, 10),
		"MIRAGEMESH_C17_SEGMENT_MAX_COUNT="+strconv.Itoa(segmentLimits.MaxSegments),
		"MIRAGEMESH_C17_SEGMENT_MAX_RECORDS="+strconv.FormatInt(segmentLimits.MaxRecordsPerSegment, 10),
		"MIRAGEMESH_C17_SEGMENT_MAX_BYTES="+strconv.FormatInt(segmentLimits.MaxBytesPerSegment, 10),
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("segment projection helper failed: %v", err)
		}
		exitCode = exit.ExitCode()
	}
	var outcome segmentProjectionOutcome
	if err := json.NewDecoder(bytes.NewReader(stdout.Bytes())).Decode(&outcome); err != nil {
		t.Fatalf("decode projection outcome: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return c17CLIResult{outcome: outcome, exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func TestSegmentProjectionCLIHelper(t *testing.T) {
	if os.Getenv("MIRAGEMESH_C17_PROJECT_HELPER") != "1" {
		return
	}
	os.Args = []string{
		"miragemesh",
		"--project-segments",
		"--storage-dir", os.Getenv("MIRAGEMESH_C17_STORAGE"),
		"--segments-dir", os.Getenv("MIRAGEMESH_C17_SEGMENTS"),
		"--storage-max-operations", os.Getenv("MIRAGEMESH_C17_STORAGE_MAX_OPERATIONS"),
		"--storage-max-bytes", os.Getenv("MIRAGEMESH_C17_STORAGE_MAX_BYTES"),
		"--storage-max-manifest-bytes", os.Getenv("MIRAGEMESH_C17_STORAGE_MAX_MANIFEST_BYTES"),
		"--segments-max-count", os.Getenv("MIRAGEMESH_C17_SEGMENT_MAX_COUNT"),
		"--segments-max-records", os.Getenv("MIRAGEMESH_C17_SEGMENT_MAX_RECORDS"),
		"--segments-max-bytes", os.Getenv("MIRAGEMESH_C17_SEGMENT_MAX_BYTES"),
	}
	if rate := os.Getenv("MIRAGEMESH_C19_RATE_LIMIT"); rate != "" {
		os.Args = append(os.Args, "--alerts-rate-limit", rate)
	}
	if window := os.Getenv("MIRAGEMESH_C19_WINDOW_SECONDS"); window != "" {
		os.Args = append(os.Args, "--alerts-window-seconds", window)
	}
	main()
}

func TestSegmentProjectionWorkflowDerivesAndRebuildsAlerts(t *testing.T) {
	base := t.TempDir()
	storageDir, segmentsDir := filepath.Join(base, "storage"), filepath.Join(base, "segments")
	before := c17CLIStore(t, storageDir, c17CLIEvents(t)[:3])
	first := c19CLIRun(t, storageDir, segmentsDir, 3, 5)
	if first.exitCode != 0 || first.outcome.Alerts == nil {
		t.Fatalf("first projection = %+v exit=%d stderr=%s", first.outcome, first.exitCode, first.stderr)
	}
	want := *first.outcome.Alerts
	if !want.CoverageComplete || len(want.Interactions) != 3 || len(want.Rates) != 1 || len(want.SensorHealth) != 1 {
		t.Fatalf("unexpected alerts: %+v", want)
	}
	if want.Rates[0].SensorID != "sensor-01" || len(want.Rates[0].Sources) != 3 || want.SensorHealth[0].Count != 1 {
		t.Fatalf("unexpected rate/health evidence: %+v", want)
	}
	afterRestart := c19CLIRun(t, storageDir, segmentsDir, 3, 5)
	if afterRestart.exitCode != 0 || afterRestart.outcome.Appended != 0 || afterRestart.outcome.AlreadyProjected != 3 || afterRestart.outcome.Alerts == nil {
		t.Fatalf("rebuild = %+v exit=%d", afterRestart.outcome, afterRestart.exitCode)
	}
	got, _ := json.Marshal(afterRestart.outcome.Alerts)
	wantJSON, _ := json.Marshal(&want)
	if !bytes.Equal(got, wantJSON) {
		t.Fatalf("alerts changed after restart: got %s want %s", got, wantJSON)
	}
	after := c17CLIReadRecords(t, storageDir)
	if len(after) != len(before) {
		t.Fatalf("C05 records changed: before=%d after=%d", len(before), len(after))
	}
	for index := range before {
		if !bytes.Equal(before[index].Input, after[index].Input) || before[index].Receipt != after[index].Receipt {
			t.Fatalf("C05 record %d changed", index)
		}
	}
}

func TestSegmentProjectionRejectsIncompleteAlertPolicy(t *testing.T) {
	base := t.TempDir()
	storageDir := filepath.Join(base, "storage")
	c17CLIStore(t, storageDir, c17CLIEvents(t)[:1])
	result := c19CLIRun(t, storageDir, filepath.Join(base, "segments"), 3, 0)
	if result.exitCode != 2 || result.outcome.ErrorKind != "invalid_input" || result.outcome.Alerts != nil {
		t.Fatalf("incomplete policy result = %+v exit=%d", result.outcome, result.exitCode)
	}
}

func TestSegmentProjectionWorkflowProjectsC05Snapshot(t *testing.T) {
	fixtureEvents := c17CLIEvents(t)[:3]
	base := t.TempDir()
	storageDir := filepath.Join(base, "storage")
	segmentsDir := filepath.Join(base, "segments")
	before := c17CLIStore(t, storageDir, fixtureEvents)

	result := c17CLIRun(t, storageDir, segmentsDir)
	if result.exitCode != 0 {
		t.Fatalf("projection exit = %d\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
	}
	outcome := result.outcome
	if outcome.Scope != "event-segments" || outcome.Status != "projected" || outcome.Error != "" || outcome.ErrorKind != "" {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if outcome.Appended != 3 || outcome.Skipped != 1 || outcome.Segments != 2 || outcome.IncompleteSegments != 0 || len(outcome.Incomplete) != 0 {
		t.Fatalf("projection counts = %+v", outcome)
	}
	if !outcome.SegmentsKnown {
		t.Fatalf("projection reported an unknown segment state: %+v", outcome)
	}
	if !outcome.Deduplicated || outcome.AtomicWithC16 {
		t.Fatalf("projection guarantees = %+v", outcome)
	}
	if !outcome.IndexKnown || outcome.IndexRecords != 0 || outcome.IndexSensors != 0 || !outcome.IndexComplete ||
		outcome.IndexDuplicates != 0 || outcome.IndexIncompleteSegments != 0 || len(outcome.IndexMissingOrdinals) != 0 || outcome.AlreadyProjected != 0 {
		t.Fatalf("first projection index state = %+v", outcome)
	}

	after := c17CLIReadRecords(t, storageDir)
	if len(after) != len(before) {
		t.Fatalf("C05 records changed: before=%d after=%d", len(before), len(after))
	}
	for index := range before {
		if !bytes.Equal(before[index].Input, after[index].Input) || before[index].Receipt != after[index].Receipt {
			t.Fatalf("C05 record %d changed", index)
		}
	}

	writer, err := events.Open(segmentsDir, c17CLISegmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	segments, err := writer.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 2 || segments[0].Records != 2 || !segments[0].Sealed || segments[1].Records != 1 || segments[1].Sealed || segments[1].Incomplete != nil {
		t.Fatalf("segments = %+v", segments)
	}
}

func TestSegmentProjectionWorkflowDeduplicatesAndReportsIndexCoverage(t *testing.T) {
	base := t.TempDir()
	storageDir := filepath.Join(base, "storage")
	segmentsDir := filepath.Join(base, "segments")
	c17CLIStore(t, storageDir, c17CLIEvents(t))

	first := c17CLIRun(t, storageDir, segmentsDir)
	if first.exitCode != 0 || first.outcome.Appended != 5 || first.outcome.AlreadyProjected != 0 || first.outcome.Skipped != 1 {
		t.Fatalf("first projection = %+v exit = %d", first.outcome, first.exitCode)
	}
	if !first.outcome.IndexKnown || first.outcome.IndexRecords != 0 || first.outcome.Segments != 3 {
		t.Fatalf("first projection index = %+v", first.outcome)
	}

	second := c17CLIRun(t, storageDir, segmentsDir)
	if second.exitCode != 0 || second.outcome.Appended != 0 || second.outcome.AlreadyProjected != 5 || second.outcome.Skipped != 1 {
		t.Fatalf("deduplicated projection = %+v exit = %d", second.outcome, second.exitCode)
	}
	if !second.outcome.IndexKnown || second.outcome.IndexRecords != 5 || second.outcome.IndexSensors != 2 ||
		!second.outcome.IndexComplete || second.outcome.IndexDuplicates != 0 || second.outcome.Segments != 3 {
		t.Fatalf("second projection index = %+v", second.outcome)
	}

	sealed := filepath.Join(segmentsDir, "segment-00000000000000000002.sealed.jsonl")
	if err := os.Remove(sealed); err != nil {
		t.Fatal(err)
	}
	third := c17CLIRun(t, storageDir, segmentsDir)
	if third.exitCode != 0 || third.outcome.Appended != 2 || third.outcome.AlreadyProjected != 3 {
		t.Fatalf("projection after segment loss = %+v exit = %d", third.outcome, third.exitCode)
	}
	if third.outcome.IndexComplete || third.outcome.IndexRecords != 3 || len(third.outcome.IndexMissingOrdinals) != 1 ||
		third.outcome.IndexMissingOrdinals[0] != (segmentProjectionOrdinalGap{After: 1, Before: 3}) {
		t.Fatalf("index coverage after segment loss = %+v", third.outcome)
	}
}

func TestSegmentProjectionWorkflowReportsIncompleteTail(t *testing.T) {
	fixtureEvents := c17CLIEvents(t)[:2]
	base := t.TempDir()
	storageDir := filepath.Join(base, "storage")
	segmentsDir := filepath.Join(base, "segments")
	c17CLIStore(t, storageDir, fixtureEvents)
	if err := os.Mkdir(segmentsDir, 0700); err != nil {
		t.Fatal(err)
	}
	complete := []byte(fixtureEvents[0] + "\n")
	tail := []byte(fixtureEvents[1][:len(fixtureEvents[1])/2])
	raw := append(append([]byte(nil), complete...), tail...)
	if err := os.WriteFile(filepath.Join(segmentsDir, "segment-00000000000000000001.jsonl"), raw, 0600); err != nil {
		t.Fatal(err)
	}

	result := c17CLIRun(t, storageDir, segmentsDir)
	if result.exitCode != 0 {
		t.Fatalf("projection exit = %d\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
	}
	outcome := result.outcome
	if outcome.Status != "projected" || outcome.Appended != 1 || outcome.AlreadyProjected != 1 || outcome.Skipped != 1 ||
		outcome.IncompleteSegments != 1 || len(outcome.Incomplete) != 1 {
		t.Fatalf("projection counts = %+v", outcome)
	}
	if !outcome.IndexKnown || outcome.IndexRecords != 1 || outcome.IndexIncompleteSegments != 1 || outcome.IndexComplete {
		t.Fatalf("index state with incomplete tail = %+v", outcome)
	}
	digest := sha256.Sum256(tail)
	want := segmentProjectionIncomplete{
		Segment: "segment-00000000000000000001",
		Offset:  int64(len(complete)),
		Bytes:   int64(len(tail)),
		Digest:  hex.EncodeToString(digest[:]),
	}
	if outcome.Incomplete[0] != want {
		t.Fatalf("incomplete = %+v, want %+v", outcome.Incomplete[0], want)
	}
	incompletePath := filepath.Join(segmentsDir, "segment-00000000000000000001.incomplete.jsonl")
	preserved, err := os.ReadFile(incompletePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preserved, raw) {
		t.Fatalf("incomplete bytes changed: got %d bytes, want %d", len(preserved), len(raw))
	}
}

func TestSegmentProjectionWorkflowReportsTypedFailure(t *testing.T) {
	t.Run("invalid_configuration", func(t *testing.T) {
		result := c17CLIRun(t, "", filepath.Join(t.TempDir(), "segments"))
		if result.exitCode != 2 {
			t.Fatalf("exit = %d, want 2\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
		}
		if result.outcome.Status != "failed" || result.outcome.ErrorKind != "invalid_input" || result.outcome.Appended != 0 || result.outcome.Skipped != 0 {
			t.Fatalf("unexpected outcome: %+v", result.outcome)
		}
		if result.outcome.SegmentsKnown {
			t.Fatalf("invalid configuration claimed a known segment state: %+v", result.outcome)
		}
	})
	t.Run("overlapping_directories", func(t *testing.T) {
		base := t.TempDir()
		storageDir := filepath.Join(base, "storage")
		c17CLIStore(t, storageDir, c17CLIEvents(t)[:1])
		segmentsDir := filepath.Join(storageDir, "segments")
		result := c17CLIRun(t, storageDir, segmentsDir)
		if result.exitCode != 2 {
			t.Fatalf("exit = %d, want 2\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
		}
		if result.outcome.Status != "failed" || result.outcome.ErrorKind != "invalid_input" {
			t.Fatalf("unexpected outcome: %+v", result.outcome)
		}
		if _, err := os.Stat(segmentsDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("segment directory was created inside C05 storage: %v", err)
		}
	})
	t.Run("recovery_required", func(t *testing.T) {
		base := t.TempDir()
		storageDir := filepath.Join(base, "storage")
		segmentsDir := filepath.Join(base, "segments")
		fixtureEvents := c17CLIEvents(t)[:1]
		before := c17CLIStore(t, storageDir, fixtureEvents)
		if err := os.Mkdir(segmentsDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(segmentsDir, "unknown.jsonl"), []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		result := c17CLIRun(t, storageDir, segmentsDir)
		if result.exitCode != 1 {
			t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
		}
		if result.outcome.Status != "failed" || result.outcome.ErrorKind != "recovery" || result.outcome.Appended != 0 || result.outcome.Skipped != 0 {
			t.Fatalf("unexpected outcome: %+v", result.outcome)
		}
		after := c17CLIReadRecords(t, storageDir)
		if len(after) != len(before) {
			t.Fatalf("C05 records changed: before=%d after=%d", len(before), len(after))
		}
	})
}

func TestSegmentProjectionWorkflowReportsPartialQuotaState(t *testing.T) {
	base := t.TempDir()
	storageDir := filepath.Join(base, "storage")
	segmentsDir := filepath.Join(base, "segments")
	c17CLIStore(t, storageDir, c17CLIEvents(t)[:3])
	quotaLimits := c17CLISegmentLimits
	quotaLimits.MaxSegments = 1
	quotaLimits.MaxRecordsPerSegment = 1

	result := c17CLIRunWithLimits(t, storageDir, segmentsDir, c17CLIStorageLimits, quotaLimits)
	if result.exitCode != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", result.exitCode, result.stdout, result.stderr)
	}
	outcome := result.outcome
	if outcome.Status != "failed" || outcome.ErrorKind != "quota" {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if outcome.Appended != 1 || outcome.Skipped != 0 {
		t.Fatalf("partial projection counts = %+v", outcome)
	}
	if !outcome.SegmentsKnown || outcome.Segments != 1 || outcome.IncompleteSegments != 0 || len(outcome.Incomplete) != 0 {
		t.Fatalf("partial projection state = %+v", outcome)
	}

	writer, err := events.Open(segmentsDir, quotaLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	segments, err := writer.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 || segments[0].ID != "segment-00000000000000000001" || segments[0].Records != 1 || !segments[0].Sealed {
		t.Fatalf("durable segments = %+v", segments)
	}
}

func TestSegmentProjectionStateIsUnknownWhenTheWriterCannotReport(t *testing.T) {
	writer, err := events.Open(filepath.Join(t.TempDir(), "segments"), c17CLISegmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	outcome := segmentProjectionOutcome{}
	if err := captureSegmentState(writer, &outcome); !errors.Is(err, events.ErrClosed) {
		t.Fatalf("capture error = %v, want closed", err)
	}
	if outcome.SegmentsKnown || outcome.Segments != 0 {
		t.Fatalf("unknown state reported as known: %+v", outcome)
	}
}

func TestSegmentProjectionPreservesMultilineSources(t *testing.T) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(c17CLIEvents(t)[0]), "", "  "); err != nil {
		t.Fatal(err)
	}
	raw := bytes.TrimSuffix(pretty.Bytes(), []byte{'\n'})
	directory := filepath.Join(t.TempDir(), "store")
	store, err := storage.Open(directory, c17CLIStorageLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sensor.Accept(context.Background(), store, raw); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	options := segmentProjectionOptions{StorageDir: directory, SegmentsDir: filepath.Join(t.TempDir(), "segments"), StorageLimits: c17CLIStorageLimits, SegmentLimits: c17CLISegmentLimits, AlertsRequested: true, AlertsRateLimit: 1, AlertsWindowSeconds: 5}
	sum := sha256.Sum256(raw)
	for attempt := 0; attempt < 2; attempt++ {
		out, err := projectSegments(context.Background(), options)
		if err != nil || out.Alerts == nil || len(out.Alerts.Interactions) != 1 {
			t.Fatalf("projection %d: %+v %v", attempt, out, err)
		}
		if out.Alerts.Interactions[0].Sources[0].Digest != hex.EncodeToString(sum[:]) {
			t.Fatal("alert lost exact multiline payload identity")
		}
		if attempt == 1 && (out.Appended != 0 || out.AlreadyProjected != 1) {
			t.Fatalf("reprojection duplicated event: %+v", out)
		}
	}
}
