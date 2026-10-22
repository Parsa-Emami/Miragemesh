package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c20Positive struct {
	FixtureVersion int             `json:"fixture_version"`
	License        string          `json:"license"`
	Provenance     string          `json:"provenance"`
	Limits         storage.Limits  `json:"limits"`
	SourceEvents   []string        `json:"source_events"`
	Triage         []c20TriageCase `json:"triage"`
}

type c20TriageCase struct {
	Name           string          `json:"name"`
	IncidentID     string          `json:"incident_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Body           json.RawMessage `json:"body"`
}

type c20Expected struct {
	FixtureVersion   int    `json:"fixture_version"`
	License          string `json:"license"`
	Provenance       string `json:"provenance"`
	RecordCount      int    `json:"record_count"`
	SourceEventCount int    `json:"source_event_count"`
	SourceUnchanged  bool   `json:"source_unchanged"`
	Entries          []struct {
		IncidentID string `json:"incident_id"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
	} `json:"entries"`
}

type c20Negative struct {
	FixtureVersion int               `json:"fixture_version"`
	License        string            `json:"license"`
	Provenance     string            `json:"provenance"`
	Cases          []c20NegativeCase `json:"cases"`
}

type c20NegativeCase struct {
	Name           string `json:"name"`
	BodyRaw        string `json:"body_raw"`
	StatusRepeat   int    `json:"status_repeat"`
	ReasonRepeat   int    `json:"reason_repeat"`
	IncidentRepeat int    `json:"incident_repeat"`
	IdempotencyKey string `json:"idempotency_key"`
	ExpectedError  string `json:"expected_error"`
}

func c20Fixture(t *testing.T) (c20Positive, c20Expected) {
	t.Helper()
	var positive c20Positive
	var expected c20Expected
	for path, target := range map[string]any{
		"positive.json":        &positive,
		"expected-output.json": &expected,
	} {
		raw, err := os.ReadFile(filepath.Join("fixtures", "miragemesh", "C20", path))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || positive.Provenance == "" || expected.Provenance == "" {
		t.Fatal("invalid C20 fixture metadata")
	}
	if len(positive.SourceEvents) != expected.SourceEventCount || len(positive.Triage) != expected.RecordCount || len(expected.Entries) != expected.RecordCount || !expected.SourceUnchanged {
		t.Fatal("C20 fixture expectations are inconsistent")
	}
	return positive, expected
}

func c20NegativeFixture(t *testing.T) c20Negative {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("fixtures", "miragemesh", "C20", "negative.json"))
	if err != nil {
		t.Fatal(err)
	}
	var negative c20Negative
	if json.Unmarshal(raw, &negative) != nil || negative.FixtureVersion != 1 || negative.License != "Apache-2.0" || negative.Provenance == "" || len(negative.Cases) == 0 {
		t.Fatal("invalid C20 negative fixture metadata")
	}
	return negative
}

func c20EventRecords(t *testing.T, ctx context.Context, store *storage.Store) []storage.Record {
	t.Helper()
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]storage.Record, 0, len(records))
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			result = append(result, record)
		}
	}
	return result
}

func c20DirectorySnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = string(raw)
	}
	return snapshot
}

func TestTriagePersistsStatusAndReasonWithoutAlteringSourceEvent(t *testing.T) {
	fixture, expected := c20Fixture(t)
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	if _, err := sensor.Accept(ctx, store, []byte(fixture.SourceEvents[0])); err != nil {
		t.Fatal(err)
	}
	segments := filepath.Join(t.TempDir(), "segments")
	writer, err := events.Open(segments, events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 8, MaxBytesPerSegment: 16384})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AppendRecords(ctx, mustRecords(t, ctx, store)); err != nil {
		t.Fatal(err)
	}
	indexBefore, err := writer.Index()
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := c20EventRecords(t, ctx, store)
	filesBefore := c20DirectorySnapshot(t, segments)
	if len(eventsBefore) != 1 || len(indexBefore.Entries()) != 1 {
		t.Fatalf("unexpected source state: events=%d index=%d", len(eventsBefore), len(indexBefore.Entries()))
	}

	service, err := incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	generation := uint64(len(mustRecords(t, ctx, store)))
	incidentID := fixture.Triage[0].IncidentID
	for i, request := range fixture.Triage {
		result, err := service.Triage(ctx, request.IncidentID, request.IdempotencyKey, request.Body)
		if err != nil {
			t.Fatalf("%s: %v", request.Name, err)
		}
		if result.Replayed || result.Entry.Status != expected.Entries[i].Status || result.Entry.Reason != expected.Entries[i].Reason || result.Receipt.Generation != generation+uint64(i)+1 {
			t.Fatalf("%s outcome = %+v", request.Name, result)
		}
	}

	eventsAfter := c20EventRecords(t, ctx, store)
	filesAfter := c20DirectorySnapshot(t, segments)
	if !reflect.DeepEqual(eventsBefore, eventsAfter) {
		t.Fatal("triage changed the observed C05 event record")
	}
	if !reflect.DeepEqual(filesBefore, filesAfter) {
		t.Fatal("triage changed immutable event segments")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err = events.Open(segments, events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 8, MaxBytesPerSegment: 16384})
	if err != nil {
		t.Fatal(err)
	}
	indexAfter, err := writer.Index()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(indexBefore.Entries(), indexAfter.Entries()) || indexAfter.Records != indexBefore.Records {
		t.Fatal("triage changed the rebuilt C18 source index")
	}
	projection, err := writer.AppendRecords(ctx, mustRecords(t, ctx, store))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Appended != 0 || projection.AlreadyProjected != 1 || projection.Skipped != len(fixture.Triage) {
		t.Fatalf("projection after triage = %+v", projection)
	}

	// A triage record is not a sensor event: the next contiguous sequence is accepted.
	if _, err := sensor.Accept(ctx, store, []byte(fixture.SourceEvents[1])); err != nil {
		t.Fatalf("triage broke sensor sequence: %v", err)
	}
	projection, err = writer.AppendRecords(ctx, mustRecords(t, ctx, store))
	if err != nil || projection.Appended != 1 {
		t.Fatalf("projection of next event = %+v: %v", projection, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, path, fixture.Limits)
	service, err = incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	history, err := service.History(ctx, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != len(expected.Entries) {
		t.Fatalf("history = %+v", history)
	}
	for i, entry := range history {
		if entry.IncidentID != expected.Entries[i].IncidentID || entry.Status != expected.Entries[i].Status || entry.Reason != expected.Entries[i].Reason || entry.TriagedAt.IsZero() {
			t.Fatalf("history %d = %+v", i, entry)
		}
	}
	records := c20EventRecords(t, ctx, store)
	if len(records) != 2 || !reflect.DeepEqual(records[0], eventsBefore[0]) {
		t.Fatal("restart changed the observed source event")
	}
}

func TestTriageRejectsInvalidRequestsBeforeDurableChange(t *testing.T) {
	fixture, _ := c20Fixture(t)
	ctx := context.Background()
	if _, err := incidents.New(nil, nil); !errors.Is(err, incidents.ErrInvalidInput) {
		t.Fatalf("nil prerequisites error = %v", err)
	}
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	if _, err := sensor.Accept(ctx, store, []byte(fixture.SourceEvents[0])); err != nil {
		t.Fatal(err)
	}
	service, err := incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents := c20EventRecords(t, ctx, store)
	for name, body := range map[string]string{
		"missing-status":  `{"reason":"why"}`,
		"missing-reason":  `{"status":"open"}`,
		"unknown-field":   `{"status":"open","reason":"why","sensor_id":"sensor-01"}`,
		"duplicate-field": `{"status":"open","status":"closed","reason":"why"}`,
		"trailing-value":  `{"status":"open","reason":"why"}{}`,
	} {
		if _, err := service.Triage(ctx, "incident-01", "triage-key-000001", []byte(body)); !errors.Is(err, incidents.ErrInvalidInput) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	if _, err := service.Triage(ctx, "incident-01", "short", fixture.Triage[0].Body); !errors.Is(err, incidents.ErrInvalidInput) {
		t.Fatalf("short key error = %v", err)
	}
	if _, err := service.Triage(ctx, strings.Repeat("i", 256), "triage-key-000001", fixture.Triage[0].Body); !errors.Is(err, incidents.ErrInvalidInput) {
		t.Fatalf("incident id error = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.Triage(cancelled, "incident-01", "triage-key-000001", fixture.Triage[0].Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	afterManifest, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if string(beforeManifest) != string(afterManifest) || !reflect.DeepEqual(beforeEvents, c20EventRecords(t, ctx, store)) {
		t.Fatal("invalid triage changed durable state")
	}
	history, err := service.History(ctx, "incident-01")
	if err != nil || len(history) != 0 {
		t.Fatalf("invalid triage history = %+v: %v", history, err)
	}
	quotaStore := openStore(t, storePath(t), storage.Limits{MaxOperations: 2, MaxBytes: 131072, MaxManifestBytes: 65536})
	if _, err := sensor.Accept(ctx, quotaStore, []byte(fixture.SourceEvents[0])); err != nil {
		t.Fatal(err)
	}
	quotaService, err := incidents.New(ctx, quotaStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quotaService.Triage(ctx, "incident-01", "triage-key-000001", fixture.Triage[0].Body); err != nil {
		t.Fatal(err)
	}
	if _, err := quotaService.Triage(ctx, "incident-01", "triage-key-000002", fixture.Triage[1].Body); !errors.Is(err, storage.ErrQuota) {
		t.Fatalf("quota error = %v", err)
	}
	if err := quotaStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Triage(ctx, "incident-01", "triage-key-000003", fixture.Triage[1].Body); !errors.Is(err, storage.ErrClosed) {
		t.Fatalf("closed service error = %v", err)
	}
}

func TestTriageReplaysAfterRestartAndRejectsKeyReuse(t *testing.T) {
	fixture, expected := c20Fixture(t)
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	if _, err := sensor.Accept(ctx, store, []byte(fixture.SourceEvents[0])); err != nil {
		t.Fatal(err)
	}
	service, err := incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.Triage[0]
	initial, err := service.Triage(ctx, first.IncidentID, first.IdempotencyKey, first.Body)
	if err != nil || initial.Replayed {
		t.Fatalf("initial triage = %+v: %v", initial, err)
	}
	beforeManifest, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	beforeEvents := c20EventRecords(t, ctx, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, path, fixture.Limits)
	service, err = incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Triage(ctx, first.IncidentID, first.IdempotencyKey, first.Body)
	if err != nil || !replay.Replayed || replay.Receipt != initial.Receipt || replay.Entry.Status != initial.Entry.Status || !replay.Entry.TriagedAt.Equal(initial.Entry.TriagedAt) {
		t.Fatalf("replay = %+v: %v", replay, err)
	}
	afterManifest, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if string(beforeManifest) != string(afterManifest) {
		t.Fatal("idempotent replay published a new generation")
	}
	conflictBody, _ := json.Marshal(map[string]string{"status": "resolved", "reason": "changed"})
	if _, err := service.Triage(ctx, first.IncidentID, first.IdempotencyKey, conflictBody); !errors.Is(err, incidents.ErrConflict) {
		t.Fatalf("key reuse error = %v", err)
	}
	unchanged, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if string(afterManifest) != string(unchanged) {
		t.Fatal("idempotency conflict changed durable state")
	}
	second := fixture.Triage[1]
	updated, err := service.Triage(ctx, second.IncidentID, second.IdempotencyKey, second.Body)
	if err != nil || updated.Replayed || updated.Receipt.Generation != initial.Receipt.Generation+1 {
		t.Fatalf("follow-up triage = %+v: %v", updated, err)
	}
	history, err := service.History(ctx, first.IncidentID)
	if err != nil || len(history) != 2 || history[1].Status != expected.Entries[1].Status || history[1].Reason != expected.Entries[1].Reason {
		t.Fatalf("history = %+v: %v", history, err)
	}
	if !reflect.DeepEqual(beforeEvents, c20EventRecords(t, ctx, store)) {
		t.Fatal("triage/replay changed the observed source event")
	}
	if empty, err := service.History(ctx, "incident-unknown"); err != nil || len(empty) != 0 {
		t.Fatalf("unknown incident history = %+v: %v", empty, err)
	}
}

func TestTriageHistoryFailsClosedOnForgedRecord(t *testing.T) {
	fixture, _ := c20Fixture(t)
	ctx := context.Background()
	store := openStore(t, storePath(t), fixture.Limits)
	key := sha256.Sum256([]byte("triage-key-000001"))
	record := contracts.IncidentTriageRecord{
		SchemaVersion: contracts.SchemaVersion,
		Kind:          contracts.IncidentTriage,
		IncidentID:    "incident-01",
		Status:        "open",
		Reason:        "forged",
		KeyDigest:     hex.EncodeToString(key[:]),
		TriagedAt:     "2026-01-01T00:00:00Z",
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, "forged-operation", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := incidents.New(ctx, store); !errors.Is(err, storage.ErrRecovery) {
		t.Fatalf("forged history error = %v", err)
	}
}

func TestTriageNegativeFixtureCases(t *testing.T) {
	fixture, _ := c20Fixture(t)
	negative := c20NegativeFixture(t)
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	if _, err := sensor.Accept(ctx, store, []byte(fixture.SourceEvents[0])); err != nil {
		t.Fatal(err)
	}
	service, err := incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	beforeEvents := c20EventRecords(t, ctx, store)
	for _, item := range negative.Cases {
		t.Run(item.Name, func(t *testing.T) {
			incident, key := "incident-01", "triage-key-000001"
			body := []byte(item.BodyRaw)
			switch {
			case item.StatusRepeat > 0:
				body, _ = json.Marshal(map[string]string{"status": strings.Repeat("s", item.StatusRepeat), "reason": "why"})
			case item.ReasonRepeat > 0:
				body, _ = json.Marshal(map[string]string{"status": "open", "reason": strings.Repeat("r", item.ReasonRepeat)})
			}
			if item.IncidentRepeat > 0 {
				incident = strings.Repeat("i", item.IncidentRepeat)
			}
			if item.IdempotencyKey != "" {
				key = item.IdempotencyKey
			}
			_, err := service.Triage(ctx, incident, key, body)
			if item.ExpectedError != "invalid_input" || !errors.Is(err, incidents.ErrInvalidInput) {
				t.Fatalf("error = %v, want %s", err, item.ExpectedError)
			}
		})
	}
	afterManifest, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if string(beforeManifest) != string(afterManifest) || !reflect.DeepEqual(beforeEvents, c20EventRecords(t, ctx, store)) {
		t.Fatal("negative fixture changed durable state")
	}
	if history, err := service.History(ctx, "incident-01"); err != nil || len(history) != 0 {
		t.Fatalf("negative fixture history = %+v: %v", history, err)
	}
}

func TestTriageAcceptsMaximumASCIIAndRejectsUnstorableMultibyte(t *testing.T) {
	fixture, _ := c20Fixture(t)
	ctx := context.Background()
	path := storePath(t)
	store := openStore(t, path, fixture.Limits)
	service, err := incidents.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	status := strings.Repeat("s", contracts.MaxIncidentStatusRunes)
	reason := strings.Repeat("r", contracts.MaxIncidentReasonRunes)
	body, _ := json.Marshal(map[string]string{"status": status, "reason": reason})
	result, err := service.Triage(ctx, "incident-max", "triage-key-000001", body)
	if err != nil || result.Entry.Status != status || result.Entry.Reason != reason {
		t.Fatalf("maximum ASCII triage = %+v: %v", result, err)
	}
	history, err := service.History(ctx, "incident-max")
	if err != nil || len(history) != 1 || len([]rune(history[0].Reason)) != contracts.MaxIncidentReasonRunes {
		t.Fatalf("maximum ASCII history = %+v: %v", history, err)
	}
	before, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	multibyte, _ := json.Marshal(map[string]string{"status": status, "reason": strings.Repeat("中", contracts.MaxIncidentReasonRunes)})
	if len(multibyte) <= contracts.MaxStoredInputBytes {
		t.Fatalf("multibyte body %d does not exceed the stored-record bound", len(multibyte))
	}
	if _, err := service.Triage(ctx, "incident-max", "triage-key-000002", multibyte); !errors.Is(err, incidents.ErrInvalidInput) {
		t.Fatalf("unstorable multibyte error = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if string(before) != string(after) {
		t.Fatal("rejected request changed durable state")
	}
}

func TestTriageHasNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("../internal/incidents/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("incident sources = %v: %v", files, err)
	}
	allowed := map[string]bool{
		"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true,
		"encoding/json": true, "errors": true, "strconv": true, "time": true,
		"unicode/utf8": true,
		"github.com/Parsa-Emami/Miragemesh/internal/contracts": true,
		"github.com/Parsa-Emami/Miragemesh/internal/storage":   true,
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if !allowed[path] {
				t.Fatalf("unexpected incident import %q in %s", path, filepath.Base(name))
			}
		}
	}
}

func mustRecords(t *testing.T, ctx context.Context, store *storage.Store) []storage.Record {
	t.Helper()
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestIncidentTriageRecordValidation(t *testing.T) {
	base := contracts.IncidentTriageRecord{
		SchemaVersion: contracts.SchemaVersion,
		Kind:          contracts.IncidentTriage,
		IncidentID:    "incident-01",
		Status:        "open",
		Reason:        "synthetic reason",
		KeyDigest:     strings.Repeat("a", 64),
		TriagedAt:     "2026-01-01T00:00:00Z",
	}
	canonical, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := contracts.DecodeIncidentTriage(context.Background(), canonical); err != nil || decoded != base {
		t.Fatalf("canonical record = %+v: %v", decoded, err)
	}
	mutate := func(change func(*contracts.IncidentTriageRecord)) []byte {
		copy := base
		change(&copy)
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	unknown := map[string]any{}
	if err := json.Unmarshal(canonical, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["event"] = map[string]string{"raw": "{}"}
	unknownRaw, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"nil":                nil,
		"trailing-newline":   append(append([]byte{}, canonical...), '\n'),
		"duplicate-field":    append(append([]byte{}, canonical[:len(canonical)-1]...), []byte(`,"status":"closed"}`)...),
		"unknown-field":      unknownRaw,
		"bad-schema":         mutate(func(r *contracts.IncidentTriageRecord) { r.SchemaVersion = "2" }),
		"bad-kind":           mutate(func(r *contracts.IncidentTriageRecord) { r.Kind = "event" }),
		"empty-incident":     mutate(func(r *contracts.IncidentTriageRecord) { r.IncidentID = "" }),
		"long-incident":      mutate(func(r *contracts.IncidentTriageRecord) { r.IncidentID = strings.Repeat("i", 256) }),
		"empty-status":       mutate(func(r *contracts.IncidentTriageRecord) { r.Status = "" }),
		"long-status":        mutate(func(r *contracts.IncidentTriageRecord) { r.Status = strings.Repeat("s", 4097) }),
		"empty-reason":       mutate(func(r *contracts.IncidentTriageRecord) { r.Reason = "" }),
		"long-reason":        mutate(func(r *contracts.IncidentTriageRecord) { r.Reason = strings.Repeat("r", 4097) }),
		"uppercase-digest":   mutate(func(r *contracts.IncidentTriageRecord) { r.KeyDigest = strings.Repeat("A", 64) }),
		"short-digest":       mutate(func(r *contracts.IncidentTriageRecord) { r.KeyDigest = "abc" }),
		"non-UTC-time":       mutate(func(r *contracts.IncidentTriageRecord) { r.TriagedAt = "2026-01-01T00:00:00+00:00" }),
		"invalid-time":       mutate(func(r *contracts.IncidentTriageRecord) { r.TriagedAt = "not-a-time" }),
		"unpaired-surrogate": []byte(`{"schema_version":"1","kind":"incident.triage","incident_id":"incident-01","status":"open","reason":"\ud800","key_digest":"` + strings.Repeat("a", 64) + `","triaged_at":"2026-01-01T00:00:00Z"}`),
		"oversized":          mutate(func(r *contracts.IncidentTriageRecord) { r.Reason = strings.Repeat("r", contracts.MaxStoredInputBytes) }),
	}
	for name, raw := range cases {
		if _, err := contracts.DecodeIncidentTriage(context.Background(), raw); err == nil {
			t.Fatalf("%s record was accepted", name)
		}
	}
}
