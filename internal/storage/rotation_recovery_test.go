package storage_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	c24fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

var rotationRecoveryLimits = storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536}

type rotationCrashInput struct {
	Material c24fixture.Material
	Token    string
}

func rotationTestSigner(t *testing.T, m c24fixture.Material) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode([]byte(m.AuthorityKey))
	if block == nil {
		t.Fatal("missing temporary signing material")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key.(crypto.Signer)
}

func rotationTestService(t *testing.T, store *storage.Store, m c24fixture.Material, at time.Time) *pki.Rotator {
	t.Helper()
	r, err := pki.NewRotator(context.Background(), store, pki.RotationOptions{IssuerCertificatePEM: m.Authority, MaxSensors: 8, MaxLifetime: 24 * time.Hour, MaxOverlap: time.Hour, MaxRecoveryTTL: 15 * time.Minute, Clock: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rotationRecoveryRequest(input rotationCrashInput) pki.RecoverCertificate {
	return pki.RecoverCertificate{RotateCertificate: pki.RotateCertificate{SensorID: "sensor-24", ExpectedRevision: 2, CSRPEM: input.Material.RecoveryCSR, Lifetime: 24 * time.Hour, IdempotencyKey: "c24-recovery-crash-key"}, Token: input.Token}
}

func rotationRecoverySeed(t *testing.T, dir string) (*storage.Store, rotationCrashInput) {
	t.Helper()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := c24fixture.Generate(at, "sensor-24")
	s, err := storage.Open(dir, rotationRecoveryLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r := rotationTestService(t, s, m, at)
	if _, err := r.Register(context.Background(), pki.RegisterCertificate{SensorID: "sensor-24", CertificatePEM: m.Initial, IdempotencyKey: "c24-register-crash-key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(context.Background(), pki.RotateCertificate{SensorID: "sensor-24", ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-rotate-crash-key"}, rotationTestSigner(t, m)); err != nil {
		t.Fatal(err)
	}
	tokens, _ := enrollment.New(s, 15*time.Minute, func() time.Time { return at.Add(2 * time.Hour) })
	token, err := tokens.Issue(context.Background(), "sensor-24", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s, rotationCrashInput{m, token.Token}
}

func TestCertificateRotationCrashChild(t *testing.T) {
	dir, phase := os.Getenv("C24_CRASH_DIR"), os.Getenv("C24_CRASH_PHASE")
	if dir == "" {
		return
	}
	var input rotationCrashInput
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 65536)).Decode(&input); err != nil {
		t.Fatal(err)
	}
	s, err := storage.Open(dir, rotationRecoveryLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
	r := rotationTestService(t, s, input.Material, at)
	kill := func(name string) {
		if name == phase {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
	base := s.FileOpsForTest()
	ops := base
	files, dirs := 0, 0
	ops.Sync = func(f *os.File) error {
		err := base.Sync(f)
		if err != nil {
			return err
		}
		info, _ := f.Stat()
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
	if _, err := r.Recover(context.Background(), rotationRecoveryRequest(input), rotationTestSigner(t, input.Material)); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary not reached")
}

func rotationAssertRecovery(t *testing.T, dir string, input rotationCrashInput, published bool) {
	t.Helper()
	s, err := storage.Open(dir, rotationRecoveryLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
	r := rotationTestService(t, s, input.Material, at)
	snapshot, err := r.Snapshot(context.Background())
	want := uint64(2)
	if published {
		want = 3
	}
	if err != nil || len(snapshot.Sensors) != 1 || snapshot.Sensors[0].Revision != want {
		t.Fatal("certificate/token publication split", snapshot, err)
	}
	result, err := r.Recover(context.Background(), rotationRecoveryRequest(input), rotationTestSigner(t, input.Material))
	if err != nil || result.Revision != 3 || result.Replayed != published {
		t.Fatal("recovery retry did not converge", result.Revision, result.Replayed, err)
	}
	tokens, _ := enrollment.New(s, 15*time.Minute, func() time.Time { return at })
	if _, err := tokens.Consume(context.Background(), input.Token, "sensor-24"); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatal("committed recovery did not claim token", err)
	}
	records, err := s.Records(context.Background())
	if err != nil || len(records) != 4 {
		t.Fatal("duplicate or partial rotation history", len(records), err)
	}
	again, err := r.Recover(context.Background(), rotationRecoveryRequest(input), nil)
	if err != nil || !again.Replayed || again.Receipt != result.Receipt || again.CertificatePEM != result.CertificatePEM {
		t.Fatal("lost acknowledgement did not replay original signed result", err)
	}
}

func TestCertificateRotationSIGKILLAtPublicationBoundaries(t *testing.T) {
	for _, phase := range []string{"object_synced", "object_published", "manifest_synced", "manifest_published", "before_ack"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, input := rotationRecoverySeed(t, dir)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(input)
			cmd := exec.Command(os.Args[0], "-test.run=^TestCertificateRotationCrashChild$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "C24_CRASH_DIR="+dir, "C24_CRASH_PHASE="+phase)
			cmd.Stdin = bytes.NewReader(raw)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("child was not killed at %s: %v %s", phase, err, out)
			}
			rotationAssertRecovery(t, dir, input, phase == "manifest_published" || phase == "before_ack")
		})
	}
}

func TestCertificateRotationSyscallFailuresPreserveAtomicRecovery(t *testing.T) {
	for _, phase := range []string{"object_write", "short_write", "object_sync", "object_rename", "object_directory_sync", "manifest_write", "manifest_sync", "manifest_rename", "manifest_directory_sync"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, input := rotationRecoverySeed(t, dir)
			r := rotationTestService(t, s, input.Material, time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC))
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
			ops.Write = func(f *os.File, b []byte) (int, error) {
				writes++
				if writes == 1 {
					if fail("object_write") {
						return 0, syscall.ENOSPC
					}
					if fail("short_write") {
						n, _ := base.Write(f, b[:len(b)/2])
						return n, nil
					}
				} else if fail("manifest_write") {
					return 0, syscall.ENOSPC
				}
				return base.Write(f, b)
			}
			ops.Sync = func(f *os.File) error {
				info, _ := f.Stat()
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
				return base.Sync(f)
			}
			ops.Rename = func(a, b string) error {
				if strings.HasPrefix(b, "object-") && fail("object_rename") || b == "manifest.json" && fail("manifest_rename") {
					return syscall.EIO
				}
				return base.Rename(a, b)
			}
			s.SetFileOpsForTest(ops)
			result, err := r.Recover(context.Background(), rotationRecoveryRequest(input), rotationTestSigner(t, input.Material))
			if !injected || !errors.Is(err, storage.ErrIO) && !errors.Is(err, storage.ErrRecovery) || result.CertificatePEM != "" {
				t.Fatal("storage failure claimed issuance", injected, err)
			}
			if _, err := r.Snapshot(context.Background()); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("uncertain state exposed", err)
			}
			s.Close()
			rotationAssertRecovery(t, dir, input, phase == "manifest_directory_sync")
		})
	}
}
