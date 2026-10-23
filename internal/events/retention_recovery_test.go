package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var retentionTestLimits = Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768}

func retentionTestRequest() RetentionRequest {
	return RetentionRequest{Before: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), Reason: "Synthetic recovery test", IdempotencyKey: "c23-recovery-key-01"}
}

func retentionTestOpen(t *testing.T, dir string) *Writer {
	t.Helper()
	w, err := Open(dir, retentionTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func retentionTestRaw(i, day int) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"1","sensor_id":"sensor-23","event_id":"event-%02d","sequence":%d,"observed_at":"2026-01-%02dT00:00:00Z","kind":"http.request","metadata":{"path":"/synthetic/%d"}}`, i, i, day, i))
}

func retentionTestSeed(t *testing.T, dir string) *Writer {
	t.Helper()
	w := retentionTestOpen(t, dir)
	for i := 1; i <= 5; i++ {
		day := i
		if i == 5 {
			day = 10
		}
		if _, err := w.Append(context.Background(), retentionTestRaw(i, day)); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestRetentionCrashChild(t *testing.T) {
	dir, phase := os.Getenv("C23_CRASH_DIR"), os.Getenv("C23_CRASH_PHASE")
	if dir == "" {
		return
	}
	w := retentionTestOpen(t, dir)
	kill := func(at string) {
		if at == phase {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	create, write, flush, rename, remove := w.ops.create, w.ops.write, w.ops.sync, w.ops.rename, w.ops.remove
	w.ops.create = func(name string) (*os.File, error) {
		f, e := create(name)
		if e == nil && name == retentionStage {
			kill("stage_created")
		}
		return f, e
	}
	w.ops.write = func(f *os.File, b []byte) (int, error) {
		n, e := write(f, b)
		if e == nil && strings.HasSuffix(f.Name(), retentionStage) {
			kill("stage_written")
		}
		return n, e
	}
	deleting := false
	w.ops.sync = func(f *os.File) error {
		e := flush(f)
		if e == nil {
			info, _ := f.Stat()
			if strings.HasSuffix(f.Name(), retentionStage) {
				kill("stage_synced")
			}
			if info.IsDir() {
				if deleting {
					kill("deletion_directory_synced")
				} else {
					kill("audit_directory_synced")
				}
			}
		}
		return e
	}
	w.ops.rename = func(a, b string) error {
		e := rename(a, b)
		if e == nil && b == retentionName {
			kill("audit_renamed")
		}
		return e
	}
	w.ops.remove = func(name string) error {
		e := remove(name)
		if e == nil && strings.HasSuffix(name, ".sealed.jsonl") {
			deleting = true
			kill("first_unlinked")
		}
		return e
	}
	if _, err := w.Expire(context.Background(), retentionTestRequest()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("requested crash boundary was not reached")
}

func TestRetentionSIGKILLAtPublicationAndDeletionBoundaries(t *testing.T) {
	for i, phase := range []string{"stage_created", "stage_written", "stage_synced", "audit_renamed", "audit_directory_synced", "first_unlinked", "deletion_directory_synced"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "segments")
			w := retentionTestSeed(t, dir)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestRetentionCrashChild$")
			cmd.Env = append(os.Environ(), "C23_CRASH_DIR="+dir, "C23_CRASH_PHASE="+phase)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("not killed: %v %s", err, out)
			}
			w = retentionTestOpen(t, dir)
			index, err := w.Index()
			if err != nil {
				t.Fatal(err)
			}
			if i < 3 {
				if index.Records != 5 || len(index.Retention) != 0 {
					t.Fatalf("unpublished decision changed state: %+v", index)
				}
			} else if index.Records != 1 || len(index.Retention) != 2 || index.Complete {
				t.Fatalf("published decision lost: %+v", index)
			}
			result, err := w.Expire(context.Background(), retentionTestRequest())
			if err != nil || len(result.Segments) != 2 {
				t.Fatalf("retry %+v %v", result, err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			w = retentionTestOpen(t, dir)
			index, _ = w.Index()
			if index.Records != 1 || len(index.Retention) != 2 {
				t.Fatal("second reopen lost audit", index)
			}
		})
	}
}

func TestRetentionSyscallFailuresPreserveRecoverableState(t *testing.T) {
	for _, phase := range []string{"create", "short_write", "write", "file_sync", "rename", "audit_directory_sync", "remove", "deletion_directory_sync"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "segments")
			w := retentionTestSeed(t, dir)
			create, write, flush, rename, remove := w.ops.create, w.ops.write, w.ops.sync, w.ops.rename, w.ops.remove
			injected, deleting := false, false
			inject := func(at string) bool {
				if !injected && at == phase {
					injected = true
					return true
				}
				return false
			}
			w.ops.create = func(n string) (*os.File, error) {
				if n == retentionStage && inject("create") {
					return nil, syscall.ENOSPC
				}
				return create(n)
			}
			w.ops.write = func(f *os.File, b []byte) (int, error) {
				if strings.HasSuffix(f.Name(), retentionStage) {
					if inject("short_write") {
						n, _ := write(f, b[:len(b)/2])
						return n, nil
					}
					if inject("write") {
						return 0, io.ErrClosedPipe
					}
				}
				return write(f, b)
			}
			w.ops.sync = func(f *os.File) error {
				info, _ := f.Stat()
				if info.IsDir() {
					if deleting && inject("deletion_directory_sync") || !deleting && inject("audit_directory_sync") {
						return syscall.EIO
					}
				} else if inject("file_sync") {
					return syscall.EIO
				}
				return flush(f)
			}
			w.ops.rename = func(a, b string) error {
				if b == retentionName && inject("rename") {
					return syscall.EIO
				}
				return rename(a, b)
			}
			w.ops.remove = func(n string) error {
				if strings.HasSuffix(n, ".sealed.jsonl") {
					if inject("remove") {
						return syscall.EIO
					}
					deleting = true
				}
				return remove(n)
			}
			if _, err := w.Expire(context.Background(), retentionTestRequest()); !errors.Is(err, ErrIO) || !injected {
				t.Fatalf("failure not explicit: %v injected %v", err, injected)
			}
			if _, err := w.Index(); !errors.Is(err, ErrRecovery) {
				t.Fatal("ambiguous index exposed", err)
			}
			w.Close()
			w = retentionTestOpen(t, dir)
			if _, err := w.Expire(context.Background(), retentionTestRequest()); err != nil {
				t.Fatal(err)
			}
			index, _ := w.Index()
			if index.Records != 1 || len(index.Retention) != 2 {
				t.Fatal("recovery did not converge", index)
			}
		})
	}
}

func TestRetentionRecoveryFlushesAuditBeforeAnyUnlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "segments")
	w := retentionTestSeed(t, dir)
	w.ops.remove = func(string) error { return syscall.EIO }
	if _, err := w.Expire(context.Background(), retentionTestRequest()); !errors.Is(err, ErrIO) {
		t.Fatal(err)
	}
	w.Close()
	fileSynced, dirSynced, removed := false, false, false
	w, err := openWithOps(dir, retentionTestLimits, func(w *Writer) {
		flush, remove := w.ops.sync, w.ops.remove
		w.ops.sync = func(f *os.File) error {
			e := flush(f)
			if e == nil {
				info, _ := f.Stat()
				if strings.HasSuffix(f.Name(), retentionName) {
					fileSynced = true
				}
				if info.IsDir() && fileSynced {
					dirSynced = true
				}
			}
			return e
		}
		w.ops.remove = func(n string) error {
			if strings.HasSuffix(n, ".sealed.jsonl") {
				if !fileSynced || !dirSynced {
					t.Error("unlink before durable audit fence")
				}
				removed = true
			}
			return remove(n)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !removed {
		t.Fatal("recovery did not finish pending deletion")
	}
}

func TestRetentionRejectsCorruptAuditAndChangedPendingBytes(t *testing.T) {
	for _, scenario := range []string{"checksum", "unknown_field", "symlink", "hardlink", "pending_bytes", "pending_metadata"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "segments")
			w := retentionTestSeed(t, dir)
			w.ops.remove = func(string) error { return syscall.EIO }
			if _, err := w.Expire(context.Background(), retentionTestRequest()); !errors.Is(err, ErrIO) {
				t.Fatal(err)
			}
			w.Close()
			path := filepath.Join(dir, retentionName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "checksum":
				raw = bytes.Replace(raw, []byte("Synthetic recovery test"), []byte("Synthetic altered test!"), 1)
				os.WriteFile(path, raw, 0600)
			case "unknown_field":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
				os.WriteFile(path, raw, 0600)
			case "symlink", "hardlink":
				target := filepath.Join(t.TempDir(), "audit")
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				os.Remove(path)
				if scenario == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "pending_bytes":
				target := filepath.Join(dir, segmentName(1, kindSealed))
				b, _ := os.ReadFile(target)
				b = bytes.Replace(b, []byte("synthetic"), []byte("different"), 1)
				os.WriteFile(target, b, 0600)
			case "pending_metadata":
				var state retentionState
				if err := json.Unmarshal(raw, &state); err != nil {
					t.Fatal(err)
				}
				state.Operations[0].Segments[0].Events[0].EventID = "forged-event"
				state.Operations[0].Checksum = retentionChecksum(state.Operations[0])
				raw, _ = json.Marshal(state)
				os.WriteFile(path, raw, 0600)
			}
			w, err = Open(dir, retentionTestLimits)
			if w != nil {
				w.Close()
			}
			if !errors.Is(err, ErrRecovery) {
				t.Fatalf("unsafe audit accepted: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, segmentName(1, kindSealed))); err != nil {
				t.Fatal("unverified bytes were deleted", err)
			}
		})
	}
}

func TestRetentionKeepsOrdinalHighWaterAndSerializesReplay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "segments")
	w := retentionTestOpen(t, dir)
	if _, err := w.Append(context.Background(), retentionTestRaw(1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := w.sealLocked(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan RetentionResult, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := w.Expire(context.Background(), retentionTestRequest())
			results <- r
			failures <- e
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
	applied := 0
	for r := range results {
		if !r.Replayed {
			applied++
		}
	}
	if applied != 1 {
		t.Fatal("concurrent replay published multiple decisions", applied)
	}
	w.Close()
	w = retentionTestOpen(t, dir)
	index, _ := w.Index()
	if index.Records != 0 || len(index.Retention) != 1 || index.Complete {
		t.Fatal("empty log lost retention", index)
	}
	ref, err := w.Append(context.Background(), retentionTestRaw(2, 2))
	if err != nil || ref.Segment != "segment-00000000000000000002" {
		t.Fatalf("ordinal reused: %+v %v", ref, err)
	}
}

func TestRetentionPreservesMixedActiveIncompleteAndDuplicateEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "segments")
	w := retentionTestOpen(t, dir)
	ctx := context.Background()
	for _, raw := range [][]byte{retentionTestRaw(1, 1), retentionTestRaw(2, 2), retentionTestRaw(1, 1), retentionTestRaw(3, 10), retentionTestRaw(4, 1)} {
		if _, err := w.Append(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	active := filepath.Join(dir, segmentName(3, kindActive))
	f, err := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{")
	f.Close()
	w = retentionTestOpen(t, dir)
	incompletePath := filepath.Join(dir, segmentName(3, kindIncomplete))
	before, _ := os.ReadFile(incompletePath)
	result, err := w.Expire(ctx, retentionTestRequest())
	if err != nil || len(result.Segments) != 1 {
		t.Fatalf("mixed protection: %+v %v", result, err)
	}
	index, _ := w.Index()
	entry, ok := index.Lookup("sensor-23", "event-01")
	if !ok || entry.Segment != "segment-00000000000000000002" || index.Records != 3 || len(index.Incomplete) != 1 {
		t.Fatal("surviving duplicate not reindexed", index, entry)
	}
	after, _ := os.ReadFile(incompletePath)
	if !bytes.Equal(before, after) {
		t.Fatal("incomplete tail changed")
	}
}

func TestRetentionQuotaRejectsBeforeDeletionAndSnapshotsOwnAuditSlices(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "segments")
	w := retentionTestSeed(t, dir)
	ctx := context.Background()
	r, err := w.Expire(ctx, retentionTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	r.Segments[0].Events[0].Digest = "changed"
	index, _ := w.Index()
	index.Retention[0].Events[0].Digest = "changed"
	replay, err := w.Expire(ctx, retentionTestRequest())
	if err != nil || replay.Segments[0].Events[0].Digest == "changed" {
		t.Fatal("returned metadata aliases audit")
	}
	if err := w.sealLocked(); err != nil {
		t.Fatal(err)
	}
	state := w.retention
	for len(state.Operations) < retentionMaxOperations {
		op := state.Operations[0]
		op.KeyDigest = digest([]byte(fmt.Sprintf("c23-historical-noop-%04d", len(state.Operations))))
		op.Segments = []RetentionGap{}
		op.Checksum = retentionChecksum(op)
		state.Operations = append(state.Operations, op)
	}
	w.Close()
	raw, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, retentionName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	w = retentionTestOpen(t, dir)
	request := retentionTestRequest()
	request.Before = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	request.IdempotencyKey = "c23-over-quota-key"
	if _, err := w.Expire(ctx, request); !errors.Is(err, ErrQuota) {
		t.Fatal("unbounded audit accepted", err)
	}
	index, _ = w.Index()
	if index.Records != 1 {
		t.Fatal("quota deleted live event", index)
	}
	if _, err := os.Stat(filepath.Join(dir, segmentName(3, kindSealed))); err != nil {
		t.Fatal(err)
	}
}
