package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c38Fixture struct {
	Version    int               `json:"fixture_version"`
	License    string            `json:"license"`
	Provenance string            `json:"provenance"`
	Events     []json.RawMessage `json:"events"`
	Event      json.RawMessage   `json:"event"`
	Retention  struct {
		Before string `json:"before"`
		Reason string `json:"reason"`
		Key    string `json:"key"`
	} `json:"retention"`
	Accepted int               `json:"accepted_operations"`
	Expired  int               `json:"expired_segments"`
	Live     int64             `json:"live_segment_records"`
	Retained int               `json:"retained_records"`
	Appended int               `json:"reprojection_appended"`
	Errors   map[string]string `json:"errors"`
}

func c38Load(t *testing.T, name string) c38Fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "miragemesh", "C38", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f c38Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || f.License != "Apache-2.0" || f.Provenance == "" {
		t.Fatal("unsupported or unlicensed C38 fixture")
	}
	return f
}

func c38Files(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	files := map[string][32]byte{}
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0700 {
				return fmt.Errorf("unsafe copied directory mode: %s", entry.Name())
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("unsafe copied file mode: %s", entry.Name())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files[name] = sha256.Sum256(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// A stopped copy is a real complete file set, not an API projection. Replaying
// at quota and refusing a corrupt independent copy must preserve the original.
func TestC38StoppedCopyPreservesExactAcceptedState(t *testing.T) {
	positive, negative, expected := c38Load(t, "positive"), c38Load(t, "negative"), c38Load(t, "expected-output")
	if len(positive.Events) != expected.Accepted || expected.Accepted != 2 {
		t.Fatal("invalid C38 expected operation count")
	}
	ctx := context.Background()
	root := t.TempDir()
	state, backup := filepath.Join(root, "state"), filepath.Join(root, "backup")
	limits := storage.Limits{MaxOperations: expected.Accepted, MaxBytes: 1048576, MaxManifestBytes: 65536}
	store, err := storage.Open(state, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	receipts := make([]storage.Receipt, len(positive.Events))
	for i, input := range positive.Events {
		receipts[i], err = store.Commit(ctx, fmt.Sprintf("c38-operation-%d", i), input)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	original := c38Files(t, state)
	copyDirectory(t, state, backup)
	if !reflect.DeepEqual(original, c38Files(t, backup)) {
		t.Fatal("stopped copy changed accepted bytes")
	}
	restored, err := storage.Open(backup, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restored.Close() })
	for i, input := range positive.Events {
		replay, err := restored.Commit(ctx, receipts[i].OperationID, input)
		if err != nil || replay != receipts[i] {
			t.Fatalf("restored replay: %+v %v", replay, err)
		}
		record, err := restored.Read(ctx, receipts[i].OperationID)
		if err != nil || !bytes.Equal(record.Input, input) {
			t.Fatalf("restored exact read: %v", err)
		}
	}
	if _, err := restored.Commit(ctx, "c38-new-at-quota", positive.Events[0]); !errors.Is(err, storage.ErrQuota) || expected.Errors["new_operation_at_quota"] != "storage.ErrQuota" {
		t.Fatalf("quota: %v", err)
	}
	if _, err := restored.Commit(ctx, "c38-invalid", negative.Event); !errors.Is(err, storage.ErrInvalidInput) || expected.Errors["invalid_event"] != "storage.ErrInvalidInput" {
		t.Fatalf("invalid event: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, c38Files(t, backup)) {
		t.Fatal("replay or rejected write changed backup")
	}
	corrupt := filepath.Join(root, "corrupt")
	copyDirectory(t, backup, corrupt)
	object := filepath.Join(corrupt, "object-"+receipts[0].InputDigest+".json")
	if err := os.WriteFile(object, []byte("C38 corrupt restored bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	before := c38Files(t, corrupt)
	opened, err := storage.Open(corrupt, limits)
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, storage.ErrRecovery) || expected.Errors["corrupted_restored_object"] != "storage.ErrRecovery" {
		t.Fatalf("corrupt restore: %v", err)
	}
	if !reflect.DeepEqual(before, c38Files(t, corrupt)) || !reflect.DeepEqual(original, c38Files(t, state)) {
		t.Fatal("corrupt-copy refusal changed evidence or original")
	}
}

func TestC38RetentionKeepsAuthoritativeCopiesAndAudit(t *testing.T) {
	positive, expected := c38Load(t, "positive"), c38Load(t, "expected-output")
	ctx := context.Background()
	root := t.TempDir()
	state, segments := filepath.Join(root, "state"), filepath.Join(root, "segments")
	limits := storage.Limits{MaxOperations: 16, MaxBytes: 1048576, MaxManifestBytes: 65536}
	segmentLimits := events.Limits{MaxSegments: 8, MaxRecordsPerSegment: 1, MaxBytesPerSegment: 32768}
	store, err := storage.Open(state, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	writer, err := events.Open(segments, segmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	for _, input := range positive.Events {
		if _, err := sensor.Accept(ctx, store, input); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Append(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	original := c38Files(t, state)
	before, err := time.Parse(time.RFC3339, positive.Retention.Before)
	if err != nil {
		t.Fatal(err)
	}
	request := events.RetentionRequest{Before: before, Reason: positive.Retention.Reason, IdempotencyKey: positive.Retention.Key}
	plan, err := writer.PlanRetention(ctx, request)
	if err != nil || plan.Applied || len(plan.Segments) != expected.Expired {
		t.Fatalf("preview: %+v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(segments, "retention.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created audit: %v", err)
	}
	result, err := writer.Expire(ctx, request)
	if err != nil || !result.Applied || len(result.Segments) != expected.Expired {
		t.Fatalf("retention: %+v %v", result, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, c38Files(t, state)) {
		t.Fatal("segment retention changed C05 authoritative copies")
	}
	restoredState, restoredSegments := filepath.Join(root, "restored-state"), filepath.Join(root, "restored-segments")
	copyDirectory(t, state, restoredState)
	copyDirectory(t, segments, restoredSegments)
	if !reflect.DeepEqual(c38Files(t, segments), c38Files(t, restoredSegments)) {
		t.Fatal("backup lost retention audit or exact segment bytes")
	}
	restored, err := storage.Open(restoredState, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	reopened, err := events.Open(restoredSegments, segmentLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records, err := restored.Records(ctx)
	if err != nil || len(records) != expected.Accepted {
		t.Fatalf("retained C05 records: %d %v", len(records), err)
	}
	projection, err := reopened.AppendRecords(ctx, records)
	if err != nil || projection.Appended != expected.Appended || projection.Retained != expected.Retained || projection.AlreadyProjected != int(expected.Live) {
		t.Fatalf("restored projection resurrected source: %+v %v", projection, err)
	}
	index, err := reopened.Index()
	if err != nil || index.Complete || index.Records != expected.Live || len(index.Retention) != expected.Expired {
		t.Fatalf("restored retained coverage: %+v %v", index, err)
	}
	replay, err := reopened.Expire(ctx, request)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Segments, result.Segments) {
		t.Fatalf("restored retention replay: %+v %v", replay, err)
	}
	request.Reason = "different C38 request"
	if _, err := reopened.Expire(ctx, request); !errors.Is(err, events.ErrRetentionConflict) || expected.Errors["changed_retention_request"] != "events.ErrRetentionConflict" {
		t.Fatalf("changed retained request: %v", err)
	}
	if !reflect.DeepEqual(original, c38Files(t, restoredState)) {
		t.Fatal("restore or retention replay changed C05")
	}
}
