package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidentview"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c23Fixture struct {
	FixtureVersion int      `json:"fixture_version"`
	License        string   `json:"license"`
	Provenance     string   `json:"provenance"`
	SourceEvents   []string `json:"source_events"`
	Before         string   `json:"before"`
	Reason         string   `json:"reason"`
	Key            string   `json:"idempotency_key"`
	Expected       struct {
		ExpiredSegments    int   `json:"expired_segments"`
		ExpiredEvents      int   `json:"expired_events"`
		LiveEvents         int64 `json:"live_events"`
		ProjectionRetained int   `json:"projection_retained"`
		ProjectionAlready  int   `json:"projection_already"`
	}
}

func c23Load(t *testing.T) (c23Fixture, events.RetentionRequest) {
	t.Helper()
	var f c23Fixture
	raw, err := os.ReadFile("fixtures/miragemesh/C23/positive.json")
	if err != nil || json.Unmarshal(raw, &f) != nil || f.FixtureVersion != 1 || f.License != "Apache-2.0" || f.Provenance == "" || len(f.SourceEvents) != 6 {
		t.Fatal("missing or malformed C23 fixture", err)
	}
	for _, name := range []string{"expected-output", "negative"} {
		raw, err := os.ReadFile("fixtures/miragemesh/C23/" + name + ".json")
		var metadata struct {
			FixtureVersion int    `json:"fixture_version"`
			License        string `json:"license"`
			Provenance     string `json:"provenance"`
		}
		if err != nil || json.Unmarshal(raw, &metadata) != nil || metadata.FixtureVersion != 1 || metadata.License != "Apache-2.0" || metadata.Provenance == "" {
			t.Fatal("missing or malformed C23", name, err)
		}
		if name == "expected-output" {
			if json.Unmarshal(raw, &f.Expected) != nil || f.Expected.ExpiredSegments < 1 || f.Expected.ExpiredEvents < 1 || f.Expected.LiveEvents < 1 {
				t.Fatal("invalid expected output")
			}
		}
	}
	before, err := time.Parse(time.RFC3339, f.Before)
	if err != nil {
		t.Fatal(err)
	}
	return f, events.RetentionRequest{Before: before, Reason: f.Reason, IdempotencyKey: f.Key}
}

func TestRetentionExpiresSealedSegmentsAndPreservesAuditAfterRestart(t *testing.T) {
	f, request := c23Load(t)
	ctx := context.Background()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "state"), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	limits := events.Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768}
	segments := filepath.Join(dir, "segments")
	w := c17Open(t, segments, limits)
	for _, raw := range f.SourceEvents {
		if _, err := sensor.Accept(ctx, store, []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Append(ctx, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	manifest := mustRead(t, filepath.Join(dir, "state", "manifest.json"))
	plan, err := w.PlanRetention(ctx, request)
	if err != nil || plan.Applied || len(plan.Segments) != f.Expected.ExpiredSegments {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(segments, "retention.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created an audit", err)
	}
	result, err := w.Expire(ctx, request)
	if err != nil || !result.Applied || result.Replayed || len(result.Segments) != 2 {
		t.Fatalf("expire: %+v %v", result, err)
	}
	index, err := w.Index()
	if err != nil || index.Records != f.Expected.LiveEvents || len(index.Retention) != f.Expected.ExpiredSegments || index.Complete {
		t.Fatalf("index: %+v %v", index, err)
	}
	if _, ok := index.Lookup("sensor-23", "event-01"); ok {
		t.Fatal("expired source remains indexed")
	}
	if old, ok := index.Retained("sensor-23", "event-01"); !ok || old.Sequence != 1 || old.Digest == "" {
		t.Fatal("missing retired identity", old, ok)
	}
	if len(c17SealedPaths(t, segments)) != 0 {
		t.Fatal("expired sealed files remain")
	}
	view, err := incidentview.NewView(ctx, store, w, alerts.Policy{RateLimit: 10, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := view.Snapshot(ctx)
	if err != nil || snapshot.RetainedEvents != f.Expected.ExpiredEvents || snapshot.UnprojectedEvents != 0 || len(snapshot.Coverage.Retention) != f.Expected.ExpiredSegments || snapshot.Coverage.Complete || int64(len(snapshot.Incidents)) != f.Expected.LiveEvents {
		t.Fatalf("incident snapshot: %+v %v", snapshot, err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w = c17Open(t, segments, limits)
	replay, err := w.Expire(ctx, request)
	if err != nil || !replay.Applied || !replay.Replayed || !reflect.DeepEqual(replay.Segments, result.Segments) {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := w.AppendRecords(ctx, records)
	if err != nil || projection.Appended != 0 || projection.Retained != f.Expected.ProjectionRetained || projection.AlreadyProjected != f.Expected.ProjectionAlready {
		t.Fatalf("projection resurrected: %+v %v", projection, err)
	}
	if _, err := w.Append(ctx, []byte(f.SourceEvents[0])); !errors.Is(err, events.ErrRetained) {
		t.Fatal("direct resurrection", err)
	}
	changed := strings.Replace(f.SourceEvents[0], "/synthetic/1", "/changed", 1)
	if _, err := w.Append(ctx, []byte(changed)); !errors.Is(err, events.ErrIndexConflict) {
		t.Fatal("changed retained identity", err)
	}
	request.Reason = "different body"
	if _, err := w.Expire(ctx, request); !errors.Is(err, events.ErrRetentionConflict) {
		t.Fatal("same key changed request", err)
	}
	audit := mustRead(t, filepath.Join(segments, "retention.json"))
	if bytes.Contains(audit, []byte(f.Key)) || bytes.Contains(audit, []byte("/synthetic/")) {
		t.Fatal("raw key or event payload leaked")
	}
	if !bytes.Equal(manifest, mustRead(t, filepath.Join(dir, "state", "manifest.json"))) {
		t.Fatal("retention changed C05")
	}
}

func TestRetentionRejectsInvalidRequestsAndPreservesActiveAndBoundarySegments(t *testing.T) {
	f, request := c23Load(t)
	w := c17Open(t, c17Dir(t), events.Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768})
	c17AppendAll(t, w, f.SourceEvents)
	for _, change := range []func(*events.RetentionRequest){
		func(r *events.RetentionRequest) { r.Before = time.Time{} },
		func(r *events.RetentionRequest) { r.Before = time.Now().Add(time.Hour) },
		func(r *events.RetentionRequest) { r.Reason = " \n" },
		func(r *events.RetentionRequest) { r.Reason = strings.Repeat("x", 1025) },
		func(r *events.RetentionRequest) { r.IdempotencyKey = "short" },
		func(r *events.RetentionRequest) { r.Reason = string([]byte{255}) },
	} {
		r := request
		change(&r)
		if _, err := w.Expire(context.Background(), r); !errors.Is(err, events.ErrInvalidInput) {
			t.Fatal("invalid request accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Expire(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	request.Before = time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	result, err := w.Expire(context.Background(), request)
	if err != nil || len(result.Segments) != 1 {
		t.Fatalf("strict cutoff: %+v %v", result, err)
	}
	index, _ := w.Index()
	if index.Records != 4 {
		t.Fatal("boundary segment partially expired", index.Records)
	}
	request.IdempotencyKey = "c23-synthetic-key-02"
	request.Before = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	result, err = w.Expire(context.Background(), request)
	if err != nil || len(result.Segments) != 1 {
		t.Fatalf("active protection: %+v %v", result, err)
	}
	index, _ = w.Index()
	if index.Records != 2 {
		t.Fatal("active segment deleted", index.Records)
	}
	t.Run("empty decision cannot delete newly sealed sources on retry", func(t *testing.T) {
		w := c17Open(t, c17Dir(t), events.Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768})
		c17AppendAll(t, w, f.SourceEvents[:2])
		_, request := c23Load(t)
		result, err := w.Expire(context.Background(), request)
		if err != nil || len(result.Segments) != 0 || !result.Applied {
			t.Fatalf("empty decision %+v %v", result, err)
		}
		c17AppendAll(t, w, f.SourceEvents[2:3])
		result, err = w.Expire(context.Background(), request)
		if err != nil || !result.Replayed || len(result.Segments) != 0 {
			t.Fatalf("replayed empty decision %+v %v", result, err)
		}
		index, _ := w.Index()
		if index.Records != 3 || !index.Complete {
			t.Fatal("empty replay expired new candidates", index)
		}
		w.Close()
		if _, err := w.Expire(context.Background(), request); !errors.Is(err, events.ErrClosed) {
			t.Fatal("closed writer accepted retention", err)
		}
	})
}
