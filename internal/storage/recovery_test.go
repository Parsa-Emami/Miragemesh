package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func input(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C04/valid-event.txt")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func limits() Limits { return Limits{MaxOperations: 16, MaxBytes: 131072, MaxManifestBytes: 65536} }
func fresh(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	s, err := Open(path, limits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestStorageSyscallFailuresPreserveRecoverableState(t *testing.T) {
	for _, point := range []string{"write", "short-write", "stage-sync", "object-rename", "object-directory-sync", "manifest-write", "manifest-sync", "manifest-rename", "manifest-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			s, path := fresh(t)
			raw := input(t)
			if _, err := s.Commit(context.Background(), "prior", raw); err != nil {
				t.Fatal(err)
			}
			next := append(append([]byte{}, raw...), ' ')
			base := s.ops
			writes, syncs, dirs := 0, 0, 0
			s.ops.write = func(f *os.File, b []byte) (int, error) {
				writes++
				if point == "write" && writes == 1 || point == "manifest-write" && writes == 2 {
					return 0, syscall.ENOSPC
				}
				if point == "short-write" && writes == 1 {
					return base.write(f, b[:len(b)/2])
				}
				return base.write(f, b)
			}
			s.ops.sync = func(f *os.File) error {
				stat, _ := f.Stat()
				if stat.IsDir() {
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
				return base.sync(f)
			}
			s.ops.rename = func(from, to string) error {
				if point == "object-rename" && strings.HasPrefix(to, "object-") || point == "manifest-rename" && to == "manifest.json" {
					return syscall.ENOSPC
				}
				return base.rename(from, to)
			}
			receipt, err := s.Commit(context.Background(), "next", next)
			want := ErrIO
			if point == "manifest-directory-sync" {
				want = ErrRecovery
			}
			if !errors.Is(err, want) || receipt != (Receipt{}) || strings.Contains(err.Error(), path) {
				t.Fatalf("result %+v: %v", receipt, err)
			}
			if _, err = s.Commit(context.Background(), "another", raw); !errors.Is(err, ErrRecovery) {
				t.Fatalf("failed handle still writable: %v", err)
			}
			s.Close()
			reopened, err := Open(path, limits())
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if record, err := reopened.Read(context.Background(), "prior"); err != nil || !bytes.Equal(record.Input, raw) {
				t.Fatalf("prior: %v", err)
			}
			record, err := reopened.Read(context.Background(), "next")
			if point == "manifest-directory-sync" {
				if err != nil || !bytes.Equal(record.Input, next) {
					t.Fatalf("published generation: %v", err)
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Fatalf("partial generation visible: %v", err)
			}
			receipt, err = reopened.Commit(context.Background(), "next", next)
			if err != nil || receipt.Generation != 2 {
				t.Fatalf("retry %+v: %v", receipt, err)
			}
		})
	}
}
func TestStorageCancellationAroundPublication(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			s, path := fresh(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base := s.ops
			s.ops.rename = func(from, to string) error {
				if to == "manifest.json" && !after {
					cancel()
				}
				err := base.rename(from, to)
				if to == "manifest.json" && after {
					cancel()
				}
				return err
			}
			// Cancellation before the final pre-publication check is tested at manifest staging.
			if !after {
				s.ops = base
				s.ops.sync = func(f *os.File) error {
					err := base.sync(f)
					stat, _ := f.Stat()
					if !stat.IsDir() {
						cancel()
					}
					return err
				}
			}
			raw := input(t)
			receipt, err := s.Commit(ctx, "op", raw)
			if after {
				if err != nil || receipt.Generation != 1 {
					t.Fatalf("published commit cancelled: %v", err)
				}
			} else {
				if !errors.Is(err, context.Canceled) || receipt != (Receipt{}) {
					t.Fatalf("prepublication: %v", err)
				}
			}
			s.Close()
			r, err := Open(path, limits())
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			_, err = r.Read(context.Background(), "op")
			if after && err != nil || !after && !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
		})
	}
}

func TestStorageProcessHelper(t *testing.T) {
	if os.Getenv("MIRAGEMESH_STORAGE_HELPER") != "1" {
		return
	}
	path := os.Getenv("MIRAGEMESH_STORAGE_PATH")
	phase := os.Getenv("MIRAGEMESH_STORAGE_PHASE")
	s, err := Open(path, limits())
	if err != nil {
		fmt.Println("open failed")
		os.Exit(3)
	}
	defer s.Close()
	pause := func() {
		fmt.Println("boundary")
		for {
			time.Sleep(time.Hour)
		}
	}
	base := s.ops
	dirs := 0
	s.ops.sync = func(f *os.File) error {
		err := base.sync(f)
		if err != nil {
			return err
		}
		stat, _ := f.Stat()
		if stat.IsDir() {
			dirs++
			if phase == "before-ack" && dirs == 2 {
				pause()
			}
		} else if phase == "staged" {
			pause()
		}
		return nil
	}
	s.ops.rename = func(from, to string) error {
		if phase == "before-manifest" && to == "manifest.json" {
			pause()
		}
		err := base.rename(from, to)
		if err != nil {
			return err
		}
		if phase == "object" && strings.HasPrefix(to, "object-") || phase == "manifest" && to == "manifest.json" {
			pause()
		}
		return nil
	}
	raw := append(input(t), ' ')
	if _, err = s.Commit(context.Background(), "next", raw); err != nil {
		fmt.Println("commit failed")
		os.Exit(4)
	}
	os.Exit(5)
}
func TestStorageSIGKILLAtPublicationBoundaries(t *testing.T) {
	rawExpected, err := os.ReadFile("../../tests/fixtures/miragemesh/C05/expected-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Visibility map[string]bool `json:"interrupted_visibility"`
	}
	if err = json.Unmarshal(rawExpected, &expected); err != nil || len(expected.Visibility) != 5 {
		t.Fatal("invalid recovery expectations", err)
	}
	for _, phase := range []string{"staged", "object", "before-manifest", "manifest", "before-ack"} {
		t.Run(phase, func(t *testing.T) {
			s, path := fresh(t)
			raw := input(t)
			if _, err := s.Commit(context.Background(), "prior", raw); err != nil {
				t.Fatal(err)
			}
			s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestStorageProcessHelper$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "MIRAGEMESH_STORAGE_HELPER=1", "MIRAGEMESH_STORAGE_PATH="+path, "MIRAGEMESH_STORAGE_PHASE="+phase)
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
			if _, err = Open(path, limits()); !errors.Is(err, ErrLocked) {
				t.Fatalf("cross-process lock: %v", err)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v", err)
			}
			r, err := Open(path, limits())
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if prior, err := r.Read(context.Background(), "prior"); err != nil || !bytes.Equal(prior.Input, raw) {
				t.Fatal("prior state lost", err)
			}
			_, err = r.Read(context.Background(), "next")
			published, known := expected.Visibility[phase]
			if !known {
				t.Fatal("missing recovery expectation")
			}
			if published && err != nil || !published && !errors.Is(err, ErrNotFound) {
				t.Fatalf("unexpected visibility: %v", err)
			}
			receipt, err := r.Commit(context.Background(), "next", append(raw, ' '))
			if err != nil || receipt.Generation != 2 {
				t.Fatalf("retry %+v: %v", receipt, err)
			}
		})
	}
}
func TestStorageRecognizedOrphansAndMissingManifest(t *testing.T) {
	s, path := fresh(t)
	raw := input(t)
	s.Close()
	orphan := filepath.Join(path, objectName(digest(raw)))
	if err := os.WriteFile(orphan, raw, 0600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(path, ".stage-"+strings.Repeat("a", 32))
	os.WriteFile(stage, []byte("incomplete"), 0600)
	r, err := Open(path, limits())
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	for _, name := range []string{orphan, stage} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("orphan retained", err)
		}
	}
	os.WriteFile(orphan, raw, 0600)
	os.Remove(filepath.Join(path, "manifest.json"))
	if _, err = Open(path, limits()); !errors.Is(err, ErrRecovery) {
		t.Fatal("missing manifest reset state", err)
	}
	if _, err = os.Stat(orphan); err != nil {
		t.Fatal("evidence deleted", err)
	}
}

func TestStorageOversizedStagingIsPreserved(t *testing.T) {
	s, path := fresh(t)
	s.Close()
	stage := filepath.Join(path, ".stage-"+strings.Repeat("b", 32))
	if err := os.WriteFile(stage, bytes.Repeat([]byte("x"), int(limits().MaxManifestBytes)+1), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, limits())
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrRecovery) {
		t.Fatalf("suspicious staging accepted: %v", err)
	}
	if _, err = os.Stat(stage); err != nil {
		t.Fatal("suspicious staging removed", err)
	}
}
