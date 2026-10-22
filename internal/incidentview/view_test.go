package incidentview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func TestReplayViewReadsSegmentsAndPersistsTriageAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	limits := storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072}
	segmentLimits := events.Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768}
	fixture, err := os.ReadFile("../../tests/fixtures/miragemesh/C22/positive.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		SourceEvents []string `json:"source_events"`
	}
	if err := json.Unmarshal(fixture, &data); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(root, "state"), limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	writer, err := events.Open(filepath.Join(root, "segments"), segmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { writer.Close() }()
	for _, raw := range data.SourceEvents {
		if _, err := sensor.Accept(ctx, store, []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Append(ctx, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	view, err := NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := view.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Incidents) != 4 || !snapshot.Coverage.Complete || snapshot.UnprojectedEvents != 0 {
		t.Fatalf("bad view: %+v", snapshot)
	}
	var incidentID string
	for _, incident := range snapshot.Incidents {
		if len(incident.Events) != len(incident.Finding.Sources) {
			t.Fatal("missing source replay")
		}
		for _, event := range incident.Events {
			raw := []byte(data.SourceEvents[event.Event.Sequence-1])
			sum := sha256.Sum256(raw)
			if event.Source.Digest != hex.EncodeToString(sum[:]) {
				t.Fatal("source digest changed")
			}
			if event.Event.Sequence == 1 && (event.Source.Segment != "segment-00000000000000000001" || event.Source.Record != 1) {
				t.Fatalf("wrong first source: %+v", event.Source)
			}
		}
		if incident.Finding.Class == "attack_signal" {
			incidentID = incident.ID
			if len(incident.Events) != 3 {
				t.Fatal("rate replay missing events")
			}
		}
	}
	before, _ := os.ReadFile(filepath.Join(root, "segments", "segment-00000000000000000001.sealed.jsonl"))
	body := []byte(`{"status":"investigating","reason":"Synthetic review <script>globalThis.c22Sentinel=2</script>"}`)
	result, err := view.Triage(ctx, incidentID, "synthetic-c22-key-0001", body)
	if err != nil || result.Replayed {
		t.Fatalf("triage: %+v %v", result, err)
	}
	writer.Close()
	store.Close()
	store, err = storage.Open(filepath.Join(root, "state"), limits)
	if err != nil {
		t.Fatal(err)
	}
	writer, err = events.Open(filepath.Join(root, "segments"), segmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	view, err = NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	result, err = view.Triage(ctx, incidentID, "synthetic-c22-key-0001", body)
	if err != nil || !result.Replayed {
		t.Fatalf("restart replay: %+v %v", result, err)
	}
	if _, err = view.Triage(ctx, incidentID, "synthetic-c22-key-0001", []byte(`{"status":"resolved","reason":"different"}`)); !errors.Is(err, incidents.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	snapshot, err = view.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, incident := range snapshot.Incidents {
		if incident.ID == incidentID && (len(incident.History) != 1 || incident.History[0].Status != "investigating") {
			t.Fatal("lost or duplicate history")
		}
	}
	after, _ := os.ReadFile(filepath.Join(root, "segments", "segment-00000000000000000001.sealed.jsonl"))
	if !bytes.Equal(before, after) || len(before) == 0 {
		t.Fatal("triage changed source segment")
	}
	if _, err = view.Triage(ctx, "incident-forged", "synthetic-c22-key-0002", body); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forged incident admitted: %v", err)
	}
}

func TestReplayViewRejectsOverBoundWithoutDroppingEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 512, MaxBytes: 8388608, MaxManifestBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	writer, err := events.Open(filepath.Join(root, "segments"), events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 512, MaxBytesPerSegment: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for sequence := 1; sequence <= 257; sequence++ {
		raw := []byte(fmt.Sprintf(`{"schema_version":"1","sensor_id":"sensor-22","event_id":"event-%d","sequence":%d,"observed_at":"2026-10-22T10:00:00Z","kind":"http.request","metadata":{"path":"/synthetic"}}`, sequence, sequence))
		if _, err := writer.Append(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	view, err := NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = view.Snapshot(ctx); !errors.Is(err, ErrViewLimit) {
		t.Fatalf("over-bound replay must fail explicitly: %v", err)
	}
	index, err := writer.Index()
	if err != nil || index.Records != 257 {
		t.Fatal("view limit removed evidence")
	}
}

func TestReplayViewRejectsReindexedSourceConflict(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 16, MaxBytes: 524288, MaxManifestBytes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	limits := events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768}
	writer, err := events.Open(filepath.Join(root, "segments"), limits)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema_version":"1","sensor_id":"sensor-22","event_id":"event-01","sequence":1,"observed_at":"2026-10-22T10:00:00Z","kind":"http.request","metadata":{"path":"/safe"}}`)
	if _, err := sensor.Accept(ctx, store, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Append(ctx, raw); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if err := os.WriteFile(filepath.Join(root, "segments", "segment-00000000000000000001.jsonl"), bytes.ReplaceAll(append(raw, '\n'), []byte("/safe"), []byte("/evil")), 0600); err != nil {
		t.Fatal(err)
	}
	writer, err = events.Open(filepath.Join(root, "segments"), limits)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	view, err := NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = view.Snapshot(ctx); !errors.Is(err, events.ErrIndexConflict) {
		t.Fatalf("reindexed changed event must conflict with C05 authority: %v", err)
	}
}

func TestReplayViewFailsClosedOnChangedSegmentAndCancellation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 16, MaxBytes: 524288, MaxManifestBytes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	writer, err := events.Open(filepath.Join(root, "segments"), events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	view, err := NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := view.Snapshot(ctx)
	if err != nil || len(snapshot.Incidents) != 0 {
		t.Fatal("empty store was not explicit")
	}
	raw := []byte(`{"schema_version":"1","sensor_id":"sensor-22","event_id":"event-01","sequence":1,"observed_at":"2026-10-22T10:00:00Z","kind":"http.request","metadata":{"path":"/safe"}}`)
	if _, err := sensor.Accept(ctx, store, raw); err != nil {
		t.Fatal(err)
	}
	snapshot, err = view.Snapshot(ctx)
	if err != nil || snapshot.UnprojectedEvents != 1 || snapshot.Coverage.Complete {
		t.Fatal("unprojected event hidden")
	}
	if _, err := writer.Append(ctx, raw); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = view.Snapshot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	path := filepath.Join(root, "segments", "segment-00000000000000000001.jsonl")
	if err := os.WriteFile(path, bytes.ReplaceAll(append(raw, '\n'), []byte("/safe"), []byte("/evil")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = view.Snapshot(ctx); err == nil {
		t.Fatal("tampered segment presented as trusted replay")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = view.Snapshot(ctx); err == nil {
		t.Fatal("missing segment presented as empty")
	}
}
