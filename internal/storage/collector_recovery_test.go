package storage_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type collectorFixture struct {
	applyFixture
	SensorID string   `json:"sensor_id"`
	Events   []string `json:"events"`
}

func collectorFiles(t *testing.T) collectorFixture {
	t.Helper()
	var f collectorFixture
	raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C16/positive.json")
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("missing or malformed C16 fixture", err)
	}
	if f.FixtureVersion != 1 || f.License != "Apache-2.0" || f.Provenance == "" || f.SensorID == "" || len(f.Events) != 8 {
		t.Fatal("invalid C16 recovery fixture")
	}
	return f
}

func collectorBatch(f collectorFixture) collector.Batch {
	return collector.Batch{ID: "batch-01", FirstSequence: 1, LastSequence: 1, Events: [][]byte{[]byte(f.Events[0])}}
}

func collectorCounts(t *testing.T, records []storage.Record) (events, acks int) {
	t.Helper()
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			events++
		}
		if record.Ack != nil {
			acks++
		}
	}
	return events, acks
}

// interruptCollector stops the child after the named publication boundary.
// The counters cover the event commit first and the acknowledgement commit
// second: two directory syncs and two manifest renames per commit.
func interruptCollector(s *storage.Store, phase string, stop func()) {
	base := s.FileOpsForTest()
	ops := base
	dirs := 0
	manifests := 0
	ops.Sync = func(f *os.File) error {
		if err := base.Sync(f); err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			dirs++
			switch phase {
			case "after-event":
				if dirs == 2 {
					stop()
				}
			case "ack-not-published":
				if dirs == 3 {
					stop()
				}
			case "after-ack":
				if dirs == 4 {
					stop()
				}
			}
		}
		return nil
	}
	ops.Rename = func(from, to string) error {
		if phase == "ack-before-manifest" && to == "manifest.json" {
			manifests++
			if manifests == 2 {
				stop()
			}
		}
		return base.Rename(from, to)
	}
	s.SetFileOpsForTest(ops)
}

func TestCollectorCrashProcessHelper(t *testing.T) {
	if os.Getenv("MIRAGEMESH_COLLECTOR_HELPER") != "1" {
		return
	}
	f := collectorFiles(t)
	private := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if _, err := io.ReadFull(os.Stdin, private); err != nil {
		t.Fatal(err)
	}
	v := applyVerifier(t, f.applyFixture, private.Public().(ed25519.PublicKey))
	s, a := openApplier(t, os.Getenv("MIRAGEMESH_COLLECTOR_PATH"), f.applyFixture, v)
	interruptCollector(s, os.Getenv("MIRAGEMESH_COLLECTOR_PHASE"), func() {
		fmt.Println("boundary")
		select {}
	})
	ing, err := collector.New(s, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ing.Ingest(context.Background(), f.SensorID, collectorBatch(f)); err != nil {
		t.Fatal(err)
	}
	t.Fatal("ingest completed without reaching the requested boundary")
}

func TestCollectorSIGKILLAtAcknowledgementBoundaries(t *testing.T) {
	f := collectorFiles(t)
	for _, phase := range []string{"after-event", "ack-not-published", "ack-before-manifest", "after-ack"} {
		t.Run(phase, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f.applyFixture, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f.applyFixture, v)
			applyPayload(t, a, private, f.Payloads["initial"])
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=^TestCollectorCrashProcessHelper$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "MIRAGEMESH_COLLECTOR_HELPER=1", "MIRAGEMESH_COLLECTOR_PATH="+path, "MIRAGEMESH_COLLECTOR_PHASE="+phase)
			cmd.Stdin = bytes.NewReader(private)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			})
			reached := make(chan bool, 1)
			go func() { scanner := bufio.NewScanner(stdout); reached <- scanner.Scan() && scanner.Text() == "boundary" }()
			select {
			case ok := <-reached:
				if !ok {
					t.Fatal("child did not reach boundary")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("boundary timeout")
			}
			if other, err := storage.Open(path, f.StorageLimits); !errors.Is(err, storage.ErrLocked) {
				if other != nil {
					other.Close()
				}
				t.Fatal("second writer was admitted", err)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			var exit *exec.ExitError
			if err = cmd.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("child was not SIGKILLed", err)
			}

			s, a = openApplier(t, path, f.applyFixture, v)
			records, err := s.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			events, acks := collectorCounts(t, records)
			if events != 1 {
				t.Fatalf("recovered %d events, want exactly 1", events)
			}
			if phase == "after-ack" && acks != 1 {
				t.Fatalf("acknowledgement was not durable: %d", acks)
			}
			if phase != "after-ack" && acks != 0 {
				t.Fatalf("acknowledgement appeared before its boundary: %d", acks)
			}
			ing, err := collector.New(s, a)
			if err != nil {
				t.Fatal(err)
			}
			result, err := ing.Ingest(context.Background(), f.SensorID, collectorBatch(f))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Events) != 1 || result.Events[0].AckReceipt.OperationID != sensor.AckOperationID(f.SensorID, 1) {
				t.Fatalf("retry did not converge: %+v", result)
			}
			records, err = s.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			events, acks = collectorCounts(t, records)
			if events != 1 || acks != 1 {
				t.Fatalf("retry duplicated records: events=%d acks=%d", events, acks)
			}
		})
	}
}

func TestCollectorSyscallFailuresPreserveRecoverableState(t *testing.T) {
	f := collectorFiles(t)
	points := []string{
		"ack-write", "ack-short-write", "ack-stage-sync", "ack-object-rename",
		"ack-object-directory-sync", "ack-manifest-write", "ack-manifest-sync",
		"ack-manifest-rename", "ack-manifest-directory-sync",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f.applyFixture, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f.applyFixture, v)
			applyPayload(t, a, private, f.Payloads["initial"])
			base := s.FileOpsForTest()
			ops := base
			writes, syncs, dirs, renames := 0, 0, 0, 0
			ops.Write = func(file *os.File, b []byte) (int, error) {
				writes++
				if point == "ack-write" && writes == 3 || point == "ack-manifest-write" && writes == 4 {
					return 0, syscall.ENOSPC
				}
				if point == "ack-short-write" && writes == 3 {
					return base.Write(file, b[:len(b)/2])
				}
				return base.Write(file, b)
			}
			ops.Sync = func(file *os.File) error {
				info, err := file.Stat()
				if err != nil {
					return err
				}
				if info.IsDir() {
					dirs++
					if point == "ack-object-directory-sync" && dirs == 3 || point == "ack-manifest-directory-sync" && dirs == 4 {
						return syscall.EIO
					}
				} else {
					syncs++
					if point == "ack-stage-sync" && syncs == 3 || point == "ack-manifest-sync" && syncs == 4 {
						return syscall.ENOSPC
					}
				}
				return base.Sync(file)
			}
			ops.Rename = func(from, to string) error {
				renames++
				if point == "ack-object-rename" && renames == 3 || point == "ack-manifest-rename" && renames == 4 {
					return syscall.ENOSPC
				}
				return base.Rename(from, to)
			}
			s.SetFileOpsForTest(ops)
			ing, err := collector.New(s, a)
			if err != nil {
				t.Fatal(err)
			}
			result, err := ing.Ingest(context.Background(), f.SensorID, collectorBatch(f))
			wantError := storage.ErrIO
			if point == "ack-manifest-directory-sync" {
				wantError = storage.ErrRecovery
			}
			if !errors.Is(err, wantError) || len(result.Events) != 0 || strings.Contains(err.Error(), path) {
				t.Fatalf("false success or leaked path: %+v %v", result, err)
			}
			if _, err := s.Records(context.Background()); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("poisoned store served records", err)
			}
			s.Close()
			s, a = openApplier(t, path, f.applyFixture, v)
			records, err := s.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			events, acks := collectorCounts(t, records)
			if events != 1 {
				t.Fatalf("recovered %d events, want 1", events)
			}
			wantAcks := 0
			if point == "ack-manifest-directory-sync" {
				wantAcks = 1
			}
			if acks != wantAcks {
				t.Fatalf("recovered %d acknowledgements, want %d", acks, wantAcks)
			}
			ing, err = collector.New(s, a)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ing.Ingest(context.Background(), f.SensorID, collectorBatch(f)); err != nil {
				t.Fatal(err)
			}
			records, err = s.Records(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			events, acks = collectorCounts(t, records)
			if events != 1 || acks != 1 {
				t.Fatalf("retry did not converge: events=%d acks=%d", events, acks)
			}
		})
	}
}
