package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func fixtures(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "fixtures", "miragemesh", "C30"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "positive.json")); err != nil {
		t.Fatalf("C30 fixture directory: %v", err)
	}
	return dir
}

func copyDirectory(t *testing.T, source, destination string) {
	t.Helper()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		src := filepath.Join(source, entry.Name())
		dst := filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			copyDirectory(t, src, dst)
			continue
		}
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func readOutcome(t *testing.T, directory string) Outcome {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "outcome.json"))
	if err != nil {
		t.Fatal(err)
	}
	var outcome Outcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		t.Fatal(err)
	}
	return outcome
}

func checkExpected(t *testing.T, outcome Outcome) {
	t.Helper()
	fixture, err := Load(fixtures(t))
	if err != nil {
		t.Fatal(err)
	}
	expected := fixture.Expected
	if len(outcome.Steps) != len(expected.Steps) {
		t.Fatalf("steps = %d, want %d", len(outcome.Steps), len(expected.Steps))
	}
	for i, step := range outcome.Steps {
		if step.Name != expected.Steps[i] || step.Status != "passed" || step.Detail == "" {
			t.Fatalf("step %d = %+v, want %q passed with detail", i, step, expected.Steps[i])
		}
	}
	result := outcome.Result
	if result.EnrolledSensor != fixture.Positive.SensorID || result.AppliedRevision != fixture.Positive.Config.Revision {
		t.Fatalf("enrolled sensor/revision = %s/%d", result.EnrolledSensor, result.AppliedRevision)
	}
	if !equalSequences(result.AcceptedSequences, expected.AcceptedSequences) ||
		!equalSequences(result.AcknowledgedSequences, expected.AcknowledgedSeqs) {
		t.Fatalf("accepted/acknowledged = %v/%v", result.AcceptedSequences, result.AcknowledgedSequences)
	}
	if result.DroppedSequence != expected.DroppedSequence || result.Loss.Count != expected.Loss.Count ||
		result.Loss.SensorID != fixture.Positive.SensorID || len(result.Loss.Gaps) != len(expected.Loss.Gaps) {
		t.Fatalf("loss = %+v", result.Loss)
	}
	for i, gap := range expected.Loss.Gaps {
		if result.Loss.Gaps[i] != gap {
			t.Fatalf("loss gap %d = %+v, want %+v", i, result.Loss.Gaps[i], gap)
		}
	}
	if result.Counts.Config != expected.Counts["config"] || result.Counts.Event != expected.Counts["event"] ||
		result.Counts.Ack != expected.Counts["ack"] || result.Counts.Gap != expected.Counts["gap"] {
		t.Fatalf("counts = %+v", result.Counts)
	}
	if len(result.Segments) != expected.Segments.Count || len(result.SegmentDigests) != expected.Segments.Count {
		t.Fatalf("segments = %+v digests=%v", result.Segments, result.SegmentDigests)
	}
	if result.Segments[0].Records+result.Segments[1].Records != expected.Segments.Records ||
		!result.Segments[0].Sealed || result.Segments[1].Sealed {
		t.Fatalf("segment states = %+v", result.Segments)
	}
	if result.TriageEntries != expected.TriageEntries || result.RetentionEligible != expected.Retention.Eligible ||
		result.CoverageComplete != expected.Retention.CoverageComplete || result.IncidentCount < expected.IncidentsMin ||
		result.IncidentID == "" {
		t.Fatalf("triage/retention/incident result = %+v", result)
	}
	if result.Sensor.ConfigStatus != expected.Sensor.ConfigStatus ||
		result.Sensor.DroppedEventCount != expected.Sensor.DroppedEventCount ||
		result.Sensor.Offline != expected.Sensor.Offline {
		t.Fatalf("sensor = %+v", result.Sensor)
	}
	if !result.Restarted || !result.Restored || !result.RestoreEquivalent || len(result.ManifestDigest) != 64 {
		t.Fatalf("restart/restore result = %+v", result)
	}
	for _, digest := range result.SegmentDigests {
		if len(digest) != 64 {
			t.Fatalf("segment digest = %q", digest)
		}
	}
}

// TestC30ReferenceWorkflowCompletes proves the composed enrollment, mTLS,
// signed configuration, durable ingest, offline spool, overflow loss,
// duplicate delivery, triage and non-destructive retention preview path against
// real C05/C17 files in a fresh directory.
func TestC30ReferenceWorkflowCompletes(t *testing.T) {
	root := t.TempDir()
	outcome, err := Run(context.Background(), Options{Directory: filepath.Join(root, "run"), FixtureDir: fixtures(t)})
	if err != nil {
		t.Fatal(err)
	}
	checkExpected(t, outcome)
	persisted := readOutcome(t, filepath.Join(root, "run"))
	if persisted.SchemaVersion != outcome.SchemaVersion || persisted.Result.ManifestDigest != outcome.Result.ManifestDigest || len(persisted.Steps) != len(outcome.Steps) {
		t.Fatalf("persisted outcome differs: %+v", persisted)
	}
	for _, name := range []string{"outcome.json", "runtime.json", "sensor-config.pub", "issuer.pem"} {
		if info, err := os.Stat(filepath.Join(root, "run", name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%s: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "run", "outcome.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE KEY", "CERTIFICATE REQUEST", "client-key.pem"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("outcome contains %q", forbidden)
		}
	}
	if outcome.Result.Counts.Incident != 1 || outcome.Result.Counts.Rotation != 1 || outcome.Result.Counts.Enrollment != 2 {
		t.Fatalf("durable acceptance counts = %+v", outcome.Result.Counts)
	}
}

// TestC30RestartRestoreKeepsExactAcceptedState proves the readable state,
// segment bytes, manifest, index, triage history and loss accounting survive a
// real store/writer restart and an independent restored copy.
func TestC30RestartRestoreKeepsExactAcceptedState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	outcome, err := Run(context.Background(), Options{Directory: root, FixtureDir: fixtures(t)})
	if err != nil {
		t.Fatal(err)
	}
	checkExpected(t, outcome)
	if _, err := os.Stat(filepath.Join(root, "restore", "state", "manifest.json")); err != nil {
		t.Fatalf("restored store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "restore", "segments")); err != nil {
		t.Fatalf("restored segments: %v", err)
	}
	before, err := manifestDigest(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := manifestDigest(filepath.Join(root, "restore", "state"))
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("restored manifest = %s, want %s", after, before)
	}
	// Restoring again must use new directories and must never overwrite the
	// accepted original.
	if _, err := Run(context.Background(), Options{Directory: root, FixtureDir: fixtures(t)}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("repeat run error = %v", err)
	}
	if current, err := manifestDigest(filepath.Join(root, "state")); err != nil || current != before {
		t.Fatalf("repeat run changed the accepted manifest: %v %s", err, current)
	}
}

// TestC30NegativeCasesAreExplicit proves every required failure is observed as
// its declared typed outcome, including after a restart of the fixture run.
func TestC30NegativeCasesAreExplicit(t *testing.T) {
	fixture, err := Load(fixtures(t))
	if err != nil {
		t.Fatal(err)
	}
	firstRoot := filepath.Join(t.TempDir(), "negative-1")
	first, err := RunNegativeCases(context.Background(), Options{Directory: firstRoot, FixtureDir: fixtures(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(fixture.Negative.Cases) {
		t.Fatalf("negative results = %d, want %d", len(first), len(fixture.Negative.Cases))
	}
	for i, result := range first {
		want := fixture.Negative.Cases[i]
		if result.Name != want.Name || result.Expected != want.Expected || result.Observed != want.Expected || !result.Passed {
			t.Fatalf("negative %d = %+v, want %+v", i, result, want)
		}
	}
	second, err := RunNegativeCases(context.Background(), Options{Directory: filepath.Join(t.TempDir(), "negative-2"), FixtureDir: fixtures(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Fatalf("second run negative results = %d", len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("negative %d changed after restart: %+v vs %+v", i, first[i], second[i])
		}
	}
	if _, err := os.Stat(filepath.Join(firstRoot, "unexpected")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("negative run left unexpected state: %v", err)
	}
}

func mutatedFixture(t *testing.T, edit func(directory string)) (Fixtures, error) {
	t.Helper()
	directory := t.TempDir()
	copyDirectory(t, fixtures(t), directory)
	edit(directory)
	return Load(directory)
}

// TestC30RejectsMalformedFixturesAndMissingPrerequisites proves the acceptance
// harness fails explicitly for missing, malformed or unlicensed fixtures and
// never writes a placeholder state directory.
func TestC30RejectsMalformedFixturesAndMissingPrerequisites(t *testing.T) {
	cases := map[string]func(string){
		"missing negative fixture": func(directory string) { os.Remove(filepath.Join(directory, "negative.json")) },
		"unlicensed positive fixture": func(directory string) {
			raw, _ := os.ReadFile(filepath.Join(directory, "positive.json"))
			_ = os.WriteFile(filepath.Join(directory, "positive.json"), []byte(strings.Replace(string(raw), `"license": "Apache-2.0"`, `"license": "proprietary"`, 1)), 0600)
		},
		"malformed expected output": func(directory string) {
			_ = os.WriteFile(filepath.Join(directory, "expected-output.json"), []byte("{"), 0600)
		},
		"missing batch": func(directory string) {
			raw, _ := os.ReadFile(filepath.Join(directory, "positive.json"))
			_ = os.WriteFile(filepath.Join(directory, "positive.json"), []byte(strings.Replace(string(raw), `"duplicate": { "id": "batch-02", "event_indexes": [1, 2], "first_sequence": 2, "last_sequence": 3 },`, "", 1)), 0600)
		},
		"out-of-bounds settings": func(directory string) {
			raw, _ := os.ReadFile(filepath.Join(directory, "positive.json"))
			_ = os.WriteFile(filepath.Join(directory, "positive.json"), []byte(strings.Replace(string(raw), `"event_batch_limit": 2`, `"event_batch_limit": 99`, 1)), 0600)
		},
		"mismatched negative outcome": func(directory string) {
			raw, _ := os.ReadFile(filepath.Join(directory, "negative.json"))
			_ = os.WriteFile(filepath.Join(directory, "negative.json"), []byte(strings.Replace(string(raw), `"sensor.ErrUnconfigured"`, `"placeholder.success"`, 1)), 0600)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := mutatedFixture(t, edit); !errors.Is(err, ErrFixture) || err == nil {
				t.Fatalf("Load error = %v", err)
			}
		})
	}
	root := filepath.Join(t.TempDir(), "run")
	if _, err := Run(context.Background(), Options{Directory: root, FixtureDir: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, ErrFixture) {
		t.Fatalf("missing fixture run error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing fixture created state: %v", err)
	}
	if _, err := Run(nil, Options{Directory: root, FixtureDir: fixtures(t)}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := RunNegativeCases(context.Background(), Options{Directory: "", FixtureDir: fixtures(t)}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("empty directory error = %v", err)
	}
}

// TestC30FixtureLicensesAndSyntheticProvenance proves the versioned fixtures
// carry an explicit Apache-2.0 license and a synthetic-data provenance note,
// and that the expected output cannot drift into unknown report values.
func TestC30FixtureLicensesAndSyntheticProvenance(t *testing.T) {
	fixture, err := Load(fixtures(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, provenance := range map[string]string{
		"positive": fixture.Positive.Provenance, "negative": fixture.Negative.Provenance, "expected-output": fixture.Expected.Provenance,
	} {
		if !strings.Contains(strings.ToLower(provenance), "synthetic") || !strings.Contains(strings.ToLower(provenance), "repository-authored") {
			t.Fatalf("%s provenance = %q", name, provenance)
		}
		raw, err := os.ReadFile(filepath.Join(fixtures(t), name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil || value["license"] != "Apache-2.0" || value["fixture_version"] != float64(1) {
			t.Fatalf("%s version/license = %v %v %v", name, value["fixture_version"], value["license"], err)
		}
	}
	if fixture.Expected.Retention.Eligible != 0 || !fixture.Expected.Retention.CoverageComplete {
		t.Fatalf("retention preview must stay non-destructive: %+v", fixture.Expected.Retention)
	}
}

// TestC30HarnessStaysOnLoopbackAndContainsNoPrivateMaterial proves the test-only
// TLS envelope is not a product listener: it has no HTTP or command execution
// imports, every listener is a literal loopback address, and no fixture or
// harness source contains private key material.
func TestC30HarnessStaysOnLoopbackAndContainsNoPrivateMaterial(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("harness sources: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "net/http" || importPath == "os/exec" || importPath == "syscall" ||
				importPath == "plugin" || importPath == "C" {
				t.Fatalf("%s imports %q; the acceptance harness must not be able to egress", file, importPath)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Listen" || len(call.Args) != 2 {
				return true
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || literal.Value != `"127.0.0.1:0"` {
				t.Fatalf("%s listener address is not literal loopback: %#v", file, call.Args[1])
			}
			return true
		})
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "BEGIN PRIVATE KEY") {
			t.Fatalf("%s contains private key material", file)
		}
	}
	for _, name := range []string{"positive.json", "negative.json", "expected-output.json"} {
		raw, err := os.ReadFile(filepath.Join(fixtures(t), name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "token=") {
			t.Fatalf("%s contains secret material", name)
		}
	}
}
