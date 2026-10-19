package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func storageFixture(t *testing.T) ([]byte, storage.Limits, storage.Receipt) {
	t.Helper()
	var fixture struct {
		FixtureVersion int             `json:"fixture_version"`
		License        string          `json:"license"`
		Provenance     string          `json:"provenance"`
		Input          string          `json:"input"`
		Limits         storage.Limits  `json:"limits"`
		Receipt        storage.Receipt `json:"receipt"`
	}
	data, err := os.ReadFile("fixtures/miragemesh/C05/positive.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.FixtureVersion != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" {
		t.Fatal("unlicensed fixture")
	}
	return []byte(fixture.Input), fixture.Limits, fixture.Receipt
}
func storePath(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "store") }
func openStore(t *testing.T, path string, limits storage.Limits) *storage.Store {
	t.Helper()
	s, err := storage.Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestStorageExactBytesReplayAndReopen(t *testing.T) {
	input, limits, want := storageFixture(t)
	path := storePath(t)
	s := openStore(t, path, limits)
	receipt, err := s.Commit(context.Background(), want.OperationID, input)
	if err != nil || receipt != want {
		t.Fatalf("receipt %+v: %v", receipt, err)
	}
	before, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Open(path, limits); !errors.Is(err, storage.ErrLocked) {
		t.Fatalf("second writer: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, limits)
	replay, err := s.Commit(context.Background(), want.OperationID, input)
	if err != nil || replay != want {
		t.Fatalf("replay %+v: %v", replay, err)
	}
	after, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("replay changed manifest")
	}
	record, err := s.Read(context.Background(), want.OperationID)
	if err != nil || record.Receipt != want || !bytes.Equal(record.Input, input) || record.Event.SensorID != "sensor-01" || record.Event.Sequence != 1 {
		t.Fatalf("record %+v: %v", record, err)
	}
	record.Input[0] = '!'
	if _, err = s.Commit(context.Background(), want.OperationID, append(input, ' ')); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err = s.Read(context.Background(), "absent"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	s.Close()
	if _, err = s.Read(context.Background(), want.OperationID); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
}
func TestStorageQuotasValidationAndCancellation(t *testing.T) {
	input, limits, want := storageFixture(t)
	for _, item := range []struct {
		name   string
		limits storage.Limits
	}{
		{"records", storage.Limits{MaxOperations: 1, MaxBytes: limits.MaxBytes, MaxManifestBytes: limits.MaxManifestBytes}},
		{"bytes", storage.Limits{MaxOperations: 16, MaxBytes: int64(len(input)), MaxManifestBytes: limits.MaxManifestBytes}},
		{"manifest", storage.Limits{MaxOperations: 16, MaxBytes: limits.MaxBytes, MaxManifestBytes: 300}},
	} {
		t.Run(item.name, func(t *testing.T) {
			s := openStore(t, storePath(t), item.limits)
			if _, err := s.Commit(context.Background(), want.OperationID, input); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Commit(context.Background(), "op-02", input); !errors.Is(err, storage.ErrQuota) {
				t.Fatalf("quota: %v", err)
			}
			if receipt, err := s.Commit(context.Background(), want.OperationID, input); err != nil || receipt != want {
				t.Fatalf("quota blocked replay: %v", err)
			}
		})
	}
	s := openStore(t, storePath(t), limits)
	for _, id := range []string{"", strings.Repeat("x", 129), string([]byte{0xff})} {
		if _, err := s.Commit(context.Background(), id, input); !errors.Is(err, storage.ErrInvalidInput) {
			t.Fatalf("id: %v", err)
		}
	}
	if _, err := s.Commit(context.Background(), "invalid", []byte(`{"private":"sentinel"}`)); !errors.Is(err, storage.ErrInvalidInput) || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("input: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Commit(ctx, want.OperationID, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, want.OperationID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if receipt, err := s.Commit(context.Background(), strings.Repeat("ع", 128), input); err != nil || receipt.Generation != 1 {
		t.Fatalf("Unicode ID: %v", err)
	}
}
func TestStorageConcurrentCallsDoNotDuplicate(t *testing.T) {
	input, limits, want := storageFixture(t)
	s := openStore(t, storePath(t), limits)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.Commit(context.Background(), want.OperationID, input)
			if err != nil || got != want {
				t.Errorf("concurrent %+v: %v", got, err)
			}
		}()
	}
	wg.Wait()
}
func TestStorageRejectsUnsafeDirectoriesAndLimits(t *testing.T) {
	_, limits, _ := storageFixture(t)
	for _, bad := range []storage.Limits{{}, {MaxOperations: -1, MaxBytes: 10, MaxManifestBytes: 64}, {MaxOperations: 1, MaxBytes: 0, MaxManifestBytes: 64}, {MaxOperations: 1, MaxBytes: 10, MaxManifestBytes: 0}} {
		path := storePath(t)
		if _, err := storage.Open(path, bad); !errors.Is(err, storage.ErrInvalidInput) {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("invalid limits created state")
		}
	}
	path := storePath(t)
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(path, limits); !errors.Is(err, storage.ErrRecovery) {
		t.Fatalf("permissions: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Open(link, limits); !errors.Is(err, storage.ErrRecovery) {
		t.Fatalf("symlink: %v", err)
	}
}
func TestStorageRejectsCorruptionAndPreservesUnknownFiles(t *testing.T) {
	input, limits, want := storageFixture(t)
	for _, kind := range []string{"bad-json", "version", "duplicate", "missing", "digest", "symlink", "hardlink", "mode", "unknown", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := storePath(t)
			s := openStore(t, path, limits)
			if _, err := s.Commit(context.Background(), want.OperationID, input); err != nil {
				t.Fatal(err)
			}
			s.Close()
			manifest := filepath.Join(path, "manifest.json")
			object := filepath.Join(path, "object-"+want.InputDigest+".json")
			switch kind {
			case "bad-json":
				os.WriteFile(manifest, []byte("{"), 0600)
			case "version":
				data, _ := os.ReadFile(manifest)
				os.WriteFile(manifest, bytes.Replace(data, []byte(`"schema_version":"1"`), []byte(`"schema_version":"9"`), 1), 0600)
			case "duplicate":
				data, _ := os.ReadFile(manifest)
				os.WriteFile(manifest, bytes.Replace(data, []byte(`"generation":1`), []byte(`"generation":1,"generation":1`), 1), 0600)
			case "missing":
				os.Remove(object)
			case "digest":
				os.WriteFile(object, bytes.Repeat([]byte("x"), len(input)), 0600)
			case "symlink":
				os.Remove(object)
				os.Symlink(manifest, object)
			case "hardlink":
				os.Link(object, filepath.Join(t.TempDir(), "alias"))
			case "mode":
				os.Chmod(object, 0644)
			case "unknown":
				os.WriteFile(filepath.Join(path, "do-not-delete.txt"), []byte("private sentinel"), 0600)
			case "fifo":
				os.Remove(object)
				if err := syscall.Mkfifo(object, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := storage.Open(path, limits); !errors.Is(err, storage.ErrRecovery) {
				t.Fatalf("corrupt %s: %v", kind, err)
			}
			if kind == "unknown" {
				if _, err := os.Stat(filepath.Join(path, "do-not-delete.txt")); err != nil {
					t.Fatal("unknown file removed")
				}
			}
		})
	}
}

func TestStorageCompatibilityFixtures(t *testing.T) {
	input, limits, _ := storageFixture(t)
	s := openStore(t, storePath(t), limits)
	var expected struct {
		Receipts []storage.Receipt `json:"receipts"`
	}
	raw, err := os.ReadFile("fixtures/miragemesh/C05/expected-output.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for _, want := range expected.Receipts {
		got, err := s.Commit(context.Background(), want.OperationID, input)
		if err != nil || got != want {
			t.Fatalf("distinct operation %+v: %v", got, err)
		}
	}
	var negative struct {
		Cases []struct {
			Name        string `json:"name"`
			OperationID string `json:"operation_id"`
			Input       string `json:"input"`
			Error       string `json:"error"`
		} `json:"cases"`
	}
	raw, err = os.ReadFile("fixtures/miragemesh/C05/invalid.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &negative); err != nil {
		t.Fatal(err)
	}
	for _, item := range negative.Cases {
		t.Run(item.Name, func(t *testing.T) {
			if item.Error != "INVALID_INPUT" {
				t.Fatal("unknown expectation")
			}
			if _, err := s.Commit(context.Background(), item.OperationID, []byte(item.Input)); !errors.Is(err, storage.ErrInvalidInput) {
				t.Fatalf("fixture: %v", err)
			}
		})
	}
}
func TestStorageOpaqueIDsAndHostileMetadataRemainInert(t *testing.T) {
	input, limits, _ := storageFixture(t)
	parent := t.TempDir()
	path := filepath.Join(parent, "store")
	s := openStore(t, path, limits)
	marker := filepath.Join(parent, "private-sentinel")
	if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	hostile := bytes.Replace(input, []byte("/health"), []byte("https://example.invalid/../../private-sentinel;$(touch injected)"), 1)
	id := "../../private-sentinel"
	if _, err := s.Commit(context.Background(), id, hostile); err != nil {
		t.Fatal(err)
	}
	record, err := s.Read(context.Background(), id)
	if err != nil || !bytes.Equal(record.Input, hostile) {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(marker)
	if err != nil || string(actual) != "unchanged" {
		t.Fatal("metadata or ID used as path", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 2 {
		t.Fatal("unexpected filesystem effect", err)
	}
}
