package storage_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"github.com/Parsa-Emami/Miragemesh/internal/update"
	f "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C25"
)

var updateCrashAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
var updateCrashLimits = storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536}

func updateCrashService(t *testing.T, s *storage.Store, m f.Material) *update.Verifier {
	t.Helper()
	v, err := update.New(context.Background(), s, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 8, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: func() time.Time { return updateCrashAt }})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func updateCrashSeed(t *testing.T, dir string) (*storage.Store, f.Material) {
	t.Helper()
	m := f.Generate()
	s, err := storage.Open(dir, updateCrashLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	v := updateCrashService(t, s, m)
	p := f.Metadata(updateCrashAt, 1, "sensor-25", nil, 2, 4)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), update.Request{SensorID: "sensor-25", Version: 4, Artifact: bytes.NewReader(f.Artifact(4))}); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func updateCrashAction(v *update.Verifier, m f.Material, action string) (bool, error) {
	if action == "metadata" {
		p := f.Metadata(updateCrashAt, 2, "sensor-25", []uint64{4}, 2)
		r, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p))
		return r.Replayed, err
	}
	g := f.Grant(updateCrashAt, "crash-recovery-25", "sensor-25", 1, 4, 2)
	r, err := v.Verify(context.Background(), update.Request{SensorID: "sensor-25", Version: 2, Artifact: bytes.NewReader(f.Artifact(2)), RecoveryPayload: g, RecoverySignature: ed25519.Sign(m.Recovery, g)})
	return r.Replayed, err
}

func updateCrashAssert(t *testing.T, dir string, m f.Material, action string, published bool) {
	t.Helper()
	s, err := storage.Open(dir, updateCrashLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v := updateCrashService(t, s, m)
	snap, err := v.Snapshot(context.Background())
	if err != nil || len(snap.Sensors) != 1 {
		t.Fatal(snap, err)
	}
	state := snap.Sensors[0]
	if state.HighWaterVersion != 4 {
		t.Fatal("lost high-water authority", state)
	}
	if action == "metadata" {
		want := uint64(1)
		if published {
			want = 2
		}
		if state.Revision != want {
			t.Fatal("split metadata publication", state)
		}
	} else {
		want := uint64(4)
		if published {
			want = 2
		}
		if state.Version != want || state.Recovery != published {
			t.Fatal("split recovery decision and grant consumption", state)
		}
	}
	replayed, err := updateCrashAction(v, m, action)
	if err != nil || replayed != published {
		t.Fatal("retry failed to converge", replayed, published, err)
	}
	records, err := s.Records(context.Background())
	if err != nil || len(records) != 3 {
		t.Fatal("duplicate update publication", len(records), err)
	}
	if action == "recovery" {
		if _, err := v.Verify(context.Background(), update.Request{SensorID: "sensor-25", Version: 4, Artifact: bytes.NewReader(f.Artifact(4))}); err != nil {
			t.Fatal(err)
		}
		if _, err := updateCrashAction(v, m, action); !errors.Is(err, update.ErrRecovery) {
			t.Fatal("recovery grant was not consumed", err)
		}
	} else {
		p := f.Metadata(updateCrashAt, 1, "sensor-25", nil, 2, 4)
		if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, update.ErrStale) {
			t.Fatal("rollback replaced authority", err)
		}
		if _, err := v.Verify(context.Background(), update.Request{SensorID: "sensor-25", Version: 4, Artifact: bytes.NewReader(f.Artifact(4))}); !errors.Is(err, update.ErrRevoked) {
			t.Fatal("revocation lost", err)
		}
	}
}

func TestUpdateCrashChild(t *testing.T) {
	dir, phase, action := os.Getenv("C25_CRASH_DIR"), os.Getenv("C25_CRASH_PHASE"), os.Getenv("C25_CRASH_ACTION")
	if dir == "" {
		return
	}
	var m f.Material
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&m); err != nil {
		t.Fatal(err)
	}
	s, err := storage.Open(dir, updateCrashLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v := updateCrashService(t, s, m)
	kill := func(name string) {
		if name == phase {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	base := s.FileOpsForTest()
	ops := base
	files, dirs := 0, 0
	ops.Sync = func(file *os.File) error {
		err := base.Sync(file)
		if err != nil {
			return err
		}
		info, _ := file.Stat()
		if info.IsDir() {
			dirs++
			if dirs == 2 {
				kill("before_ack")
			}
		} else {
			files++
			if files == 1 {
				kill("object_synced")
			}
			if files == 2 {
				kill("manifest_synced")
			}
		}
		return nil
	}
	ops.Rename = func(a, b string) error {
		err := base.Rename(a, b)
		if err == nil {
			if strings.HasPrefix(b, "object-") {
				kill("object_published")
			}
			if b == "manifest.json" {
				kill("manifest_published")
			}
		}
		return err
	}
	s.SetFileOpsForTest(ops)
	if _, err := updateCrashAction(v, m, action); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary not reached")
}

func TestUpdateSIGKILLPreservesAuthorityAndRecoveryConsumption(t *testing.T) {
	for _, action := range []string{"metadata", "recovery"} {
		for _, phase := range []string{"object_synced", "object_published", "manifest_synced", "manifest_published", "before_ack"} {
			t.Run(action+"/"+phase, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "state")
				s, m := updateCrashSeed(t, dir)
				s.Close()
				raw, _ := json.Marshal(m)
				cmd := exec.Command(os.Args[0], "-test.run=^TestUpdateCrashChild$", "-test.timeout=20s")
				cmd.Env = append(os.Environ(), "C25_CRASH_DIR="+dir, "C25_CRASH_PHASE="+phase, "C25_CRASH_ACTION="+action)
				cmd.Stdin = bytes.NewReader(raw)
				out, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("child not killed at %s: %v %s", phase, err, out)
				}
				updateCrashAssert(t, dir, m, action, phase == "manifest_published" || phase == "before_ack")
			})
		}
	}
}

func TestUpdateSyscallFailuresPreserveAuthorityAndRecoveryConsumption(t *testing.T) {
	for _, action := range []string{"metadata", "recovery"} {
		for _, phase := range []string{"object_write", "short_write", "object_sync", "object_rename", "object_directory_sync", "manifest_write", "manifest_sync", "manifest_rename", "manifest_directory_sync"} {
			t.Run(action+"/"+phase, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "state")
				s, m := updateCrashSeed(t, dir)
				v := updateCrashService(t, s, m)
				base := s.FileOpsForTest()
				ops := base
				writes, files, dirs := 0, 0, 0
				injected := false
				fail := func(name string) bool {
					if !injected && phase == name {
						injected = true
						return true
					}
					return false
				}
				ops.Write = func(file *os.File, raw []byte) (int, error) {
					writes++
					if writes == 1 {
						if fail("object_write") {
							return 0, syscall.ENOSPC
						}
						if fail("short_write") {
							n, _ := base.Write(file, raw[:len(raw)/2])
							return n, nil
						}
					} else if fail("manifest_write") {
						return 0, syscall.ENOSPC
					}
					return base.Write(file, raw)
				}
				ops.Sync = func(file *os.File) error {
					info, _ := file.Stat()
					if info.IsDir() {
						dirs++
						if dirs == 1 && fail("object_directory_sync") || dirs == 2 && fail("manifest_directory_sync") {
							return syscall.EIO
						}
					} else {
						files++
						if files == 1 && fail("object_sync") || files == 2 && fail("manifest_sync") {
							return syscall.EIO
						}
					}
					return base.Sync(file)
				}
				ops.Rename = func(a, b string) error {
					if strings.HasPrefix(b, "object-") && fail("object_rename") || b == "manifest.json" && fail("manifest_rename") {
						return syscall.EIO
					}
					return base.Rename(a, b)
				}
				s.SetFileOpsForTest(ops)
				if _, err := updateCrashAction(v, m, action); !injected || !errors.Is(err, storage.ErrIO) && !errors.Is(err, storage.ErrRecovery) {
					t.Fatal("uncertain write claimed success", injected, err)
				}
				if _, err := v.Snapshot(context.Background()); !errors.Is(err, storage.ErrRecovery) {
					t.Fatal("uncertain state reported trusted", err)
				}
				s.Close()
				updateCrashAssert(t, dir, m, action, phase == "manifest_directory_sync")
			})
		}
	}
}
