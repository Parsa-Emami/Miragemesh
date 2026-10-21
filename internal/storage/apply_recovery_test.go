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

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type applyFixture struct {
	FixtureVersion int                               `json:"fixture_version"`
	License        string                            `json:"license"`
	Provenance     string                            `json:"provenance"`
	Now            string                            `json:"now"`
	Payloads       map[string]string                 `json:"payloads"`
	StorageLimits  storage.Limits                    `json:"storage_limits"`
	Bounds         map[string]struct{ Min, Max int } `json:"bounds"`
	Limits         struct {
		MaxSensors int `json:"max_sensors"`
	} `json:"limits"`
}

func applyFiles(t *testing.T) (applyFixture, map[string]int64) {
	t.Helper()
	var f applyFixture
	var expected struct {
		FixtureVersion int              `json:"fixture_version"`
		License        string           `json:"license"`
		Provenance     string           `json:"provenance"`
		Revisions      map[string]int64 `json:"interrupted_revision"`
	}
	for file, target := range map[string]any{"positive": &f, "expected-output": &expected} {
		raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C11/" + file + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatal("missing or malformed C11 fixture", err)
		}
	}
	if f.FixtureVersion != 1 || f.License != "Apache-2.0" || f.Provenance == "" || expected.FixtureVersion != 1 || expected.License != "Apache-2.0" || expected.Provenance == "" || len(expected.Revisions) != 5 {
		t.Fatal("invalid C11 recovery fixtures")
	}
	return f, expected.Revisions
}

func applyVerifier(t *testing.T, f applyFixture, public ed25519.PublicKey) config.Verifier {
	t.Helper()
	now, err := time.Parse(time.RFC3339Nano, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	h, s, b := f.Bounds["heartbeat_seconds"], f.Bounds["spool_limit_events"], f.Bounds["event_batch_limit"]
	return config.Verifier{PublicKey: public, Clock: func() time.Time { return now }, MaxSensors: f.Limits.MaxSensors, Bounds: config.Bounds{MinHeartbeatSeconds: h.Min, MaxHeartbeatSeconds: h.Max, MinSpoolLimitEvents: s.Min, MaxSpoolLimitEvents: s.Max, MinEventBatchLimit: b.Min, MaxEventBatchLimit: b.Max}}
}

func openApplier(t *testing.T, path string, f applyFixture, v config.Verifier) (*storage.Store, *sensor.Applier) {
	t.Helper()
	s, err := storage.Open(path, f.StorageLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a, err := sensor.NewApplier(context.Background(), s, v)
	if err != nil {
		t.Fatal(err)
	}
	return s, a
}

func applyPayload(t *testing.T, a *sensor.Applier, private ed25519.PrivateKey, text string) config.Applied {
	t.Helper()
	raw := []byte(text)
	result, err := a.Apply(context.Background(), raw, ed25519.Sign(private, raw))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Arm only after initialization/recovery so boundaries refer to the new apply.
func interruptApply(s *storage.Store, phase string, stop func()) {
	base := s.FileOpsForTest()
	ops := base
	dirs := 0
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
			if phase == "before-ack" && dirs == 2 {
				stop()
			}
		} else if phase == "staged" {
			stop()
		}
		return nil
	}
	ops.Rename = func(from, to string) error {
		if phase == "before-manifest" && to == "manifest.json" {
			stop()
		}
		if err := base.Rename(from, to); err != nil {
			return err
		}
		if phase == "object" && strings.HasPrefix(to, "object-") || phase == "manifest" && to == "manifest.json" {
			stop()
		}
		return nil
	}
	s.SetFileOpsForTest(ops)
}

func TestApplyCrashProcessHelper(t *testing.T) {
	if os.Getenv("MIRAGEMESH_APPLY_HELPER") != "1" {
		return
	}
	f, _ := applyFiles(t)
	// The ephemeral key crosses an anonymous pipe, never disk, argv or env.
	private := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if _, err := io.ReadFull(os.Stdin, private); err != nil {
		t.Fatal(err)
	}
	v := applyVerifier(t, f, private.Public().(ed25519.PublicKey))
	s, a := openApplier(t, os.Getenv("MIRAGEMESH_APPLY_PATH"), f, v)
	interruptApply(s, os.Getenv("MIRAGEMESH_APPLY_PHASE"), func() {
		fmt.Println("boundary")
		for {
			time.Sleep(time.Hour)
		}
	})
	applyPayload(t, a, private, f.Payloads["next"])
	t.Fatal("apply completed without reaching the requested boundary")
}

func TestApplySIGKILLAtPublicationBoundaries(t *testing.T) {
	f, expected := applyFiles(t)
	for _, phase := range []string{"staged", "object", "before-manifest", "manifest", "before-ack"} {
		t.Run(phase, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f, v)
			prior := applyPayload(t, a, private, f.Payloads["initial"])
			s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestApplyCrashProcessHelper$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "MIRAGEMESH_APPLY_HELPER=1", "MIRAGEMESH_APPLY_PATH="+path, "MIRAGEMESH_APPLY_PHASE="+phase)
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
			s, a = openApplier(t, path, f, v)
			got, exists, err := a.Active(context.Background(), prior.SensorID)
			want := f.Payloads["initial"]
			if expected[phase] == 2 {
				want = f.Payloads["next"]
			}
			if err != nil || !exists || got.Revision != expected[phase] || !bytes.Equal(got.Payload, []byte(want)) {
				t.Fatalf("recovered revision %d, want %d: %v", got.Revision, expected[phase], err)
			}
			replay := applyPayload(t, a, private, f.Payloads["next"])
			if replay.Revision != 2 {
				t.Fatal("retry did not converge")
			}
			records, err := s.Records(context.Background())
			if err != nil || len(records) != 2 {
				t.Fatal("duplicate or incomplete apply", err)
			}
		})
	}
}

func TestApplySyscallFailuresPreserveRecoverableState(t *testing.T) {
	f, _ := applyFiles(t)
	for _, point := range []string{"write", "short-write", "stage-sync", "object-rename", "object-directory-sync", "manifest-write", "manifest-sync", "manifest-rename", "manifest-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f, v)
			prior := applyPayload(t, a, private, f.Payloads["initial"])
			base := s.FileOpsForTest()
			ops := base
			writes, syncs, dirs := 0, 0, 0
			ops.Write = func(file *os.File, b []byte) (int, error) {
				writes++
				if point == "write" && writes == 1 || point == "manifest-write" && writes == 2 {
					return 0, syscall.ENOSPC
				}
				if point == "short-write" && writes == 1 {
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
					if point == "object-directory-sync" && dirs == 1 || point == "manifest-directory-sync" && dirs == 2 {
						return syscall.EIO
					}
				} else {
					syncs++
					if point == "stage-sync" && syncs == 1 || point == "manifest-sync" && syncs == 2 {
						return syscall.ENOSPC
					}
				}
				return base.Sync(file)
			}
			ops.Rename = func(from, to string) error {
				if point == "object-rename" && strings.HasPrefix(to, "object-") || point == "manifest-rename" && to == "manifest.json" {
					return syscall.ENOSPC
				}
				return base.Rename(from, to)
			}
			s.SetFileOpsForTest(ops)
			raw := []byte(f.Payloads["next"])
			result, err := a.Apply(context.Background(), raw, ed25519.Sign(private, raw))
			wantError := storage.ErrIO
			if point == "manifest-directory-sync" {
				wantError = storage.ErrRecovery
			}
			if !errors.Is(err, wantError) || result.Revision != 0 || strings.Contains(err.Error(), path) {
				t.Fatal("false success or leaked path", err)
			}
			if _, _, err = a.Active(context.Background(), prior.SensorID); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("poisoned store served active state", err)
			}
			s.Close()
			s, a = openApplier(t, path, f, v)
			got, exists, err := a.Active(context.Background(), prior.SensorID)
			want := int64(1)
			if point == "manifest-directory-sync" {
				want = 2
			}
			if err != nil || !exists || got.Revision != want {
				t.Fatal("unexpected recovered revision", got.Revision, err)
			}
			applyPayload(t, a, private, f.Payloads["next"])
			records, err := s.Records(context.Background())
			if err != nil || len(records) != 2 {
				t.Fatal("retry did not converge", err)
			}
		})
	}
}
