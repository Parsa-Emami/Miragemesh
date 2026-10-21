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

	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func spoolInputs(t *testing.T) ([]string, map[string]int) {
	t.Helper()
	var positive struct {
		Events []string `json:"events"`
	}
	var expected struct {
		InterruptedEvents map[string]int `json:"interrupted_events"`
	}
	for file, target := range map[string]any{"positive": &positive, "expected-output": &expected} {
		raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C14/" + file + ".json")
		var meta struct {
			FixtureVersion      int `json:"fixture_version"`
			License, Provenance string
		}
		if err != nil || json.Unmarshal(raw, target) != nil || json.Unmarshal(raw, &meta) != nil || meta.FixtureVersion != 1 || meta.License != "Apache-2.0" || meta.Provenance == "" {
			t.Fatal("invalid C14 recovery fixture", err)
		}
	}
	if len(positive.Events) != 4 || len(expected.InterruptedEvents) != 5 {
		t.Fatal("incomplete C14 recovery fixture")
	}
	return positive.Events, expected.InterruptedEvents
}

func TestSpoolCrashProcessHelper(t *testing.T) {
	if os.Getenv("MIRAGEMESH_SPOOL_HELPER") != "1" {
		return
	}
	f, _ := applyFiles(t)
	events, _ := spoolInputs(t)
	private := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	if _, err := io.ReadFull(os.Stdin, private); err != nil {
		t.Fatal(err)
	}
	v := applyVerifier(t, f, private.Public().(ed25519.PublicKey))
	s, a := openApplier(t, os.Getenv("MIRAGEMESH_SPOOL_PATH"), f, v)
	q, err := spool.New(s, a)
	if err != nil {
		t.Fatal(err)
	}
	interruptApply(s, os.Getenv("MIRAGEMESH_SPOOL_PHASE"), func() { fmt.Println("boundary"); select {} })
	if _, err = q.Enqueue(context.Background(), []byte(events[1])); err != nil {
		t.Fatal(err)
	}
	t.Fatal("enqueue completed without reaching boundary")
}

func TestSpoolSIGKILLAtPublicationBoundaries(t *testing.T) {
	f, _ := applyFiles(t)
	events, expected := spoolInputs(t)
	for _, phase := range []string{"staged", "object", "before-manifest", "manifest", "before-ack"} {
		t.Run(phase, func(t *testing.T) {
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f, v)
			applyPayload(t, a, key, f.Payloads["initial"])
			q, _ := spool.New(s, a)
			if _, err = q.Enqueue(context.Background(), []byte(events[0])); err != nil {
				t.Fatal(err)
			}
			s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolCrashProcessHelper$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "MIRAGEMESH_SPOOL_HELPER=1", "MIRAGEMESH_SPOOL_PATH="+path, "MIRAGEMESH_SPOOL_PHASE="+phase)
			cmd.Stdin = bytes.NewReader(key)
			cmd.Stderr = os.Stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
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
					t.Fatal("child missed boundary")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("boundary timeout")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			var exit *exec.ExitError
			if err = cmd.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("child was not SIGKILLed", err)
			}
			s, a = openApplier(t, path, f, v)
			q, _ = spool.New(s, a)
			records, err := s.Records(context.Background())
			if err != nil || len(records) != expected[phase]+1 {
				t.Fatal("partial or wrong recovered generation", len(records), err)
			}
			for i, r := range records[1:] {
				if !bytes.Equal(r.Input, []byte(events[i])) {
					t.Fatal("recovered partial event")
				}
			}
			receipt, err := q.Enqueue(context.Background(), []byte(events[1]))
			if err != nil || receipt.Generation != 3 {
				t.Fatal("retry did not converge", receipt, err)
			}
			if again, err := q.Enqueue(context.Background(), []byte(events[1])); err != nil || again != receipt {
				t.Fatal("lost acknowledgement duplicated event", again, err)
			}
		})
	}
}

func TestSpoolSyscallFailuresPreserveRecoverableState(t *testing.T) {
	f, _ := applyFiles(t)
	events, _ := spoolInputs(t)
	for _, point := range []string{"write", "short-write", "stage-sync", "object-rename", "object-directory-sync", "manifest-write", "manifest-sync", "manifest-rename", "manifest-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			v := applyVerifier(t, f, public)
			path := filepath.Join(t.TempDir(), "store")
			s, a := openApplier(t, path, f, v)
			applyPayload(t, a, key, f.Payloads["initial"])
			q, _ := spool.New(s, a)
			if _, err = q.Enqueue(context.Background(), []byte(events[0])); err != nil {
				t.Fatal(err)
			}
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
			got, err := q.Enqueue(context.Background(), []byte(events[1]))
			want := storage.ErrIO
			if point == "manifest-directory-sync" {
				want = storage.ErrRecovery
			}
			if !errors.Is(err, want) || got != (storage.Receipt{}) {
				t.Fatal("false success", got, err)
			}
			if _, err = q.Enqueue(context.Background(), []byte(events[1])); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("poisoned handle writable", err)
			}
			s.Close()
			s, a = openApplier(t, path, f, v)
			q, _ = spool.New(s, a)
			records, err := s.Records(context.Background())
			wantCount := 2
			if point == "manifest-directory-sync" {
				wantCount = 3
			}
			if err != nil || len(records) != wantCount || !bytes.Equal(records[1].Input, []byte(events[0])) {
				t.Fatal("prior state lost or partial commit", err)
			}
			first, err := q.Enqueue(context.Background(), []byte(events[1]))
			if err != nil {
				t.Fatal(err)
			}
			if replay, err := q.Enqueue(context.Background(), []byte(events[1])); err != nil || replay != first {
				t.Fatal("retry did not converge", err)
			}
		})
	}
}
