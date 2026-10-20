package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type enrollmentFixture struct {
	FixtureVersion int            `json:"fixture_version"`
	License        string         `json:"license"`
	Provenance     string         `json:"provenance"`
	SensorID       string         `json:"sensor_id"`
	Now            time.Time      `json:"now"`
	MaxTTLSeconds  int            `json:"max_ttl_seconds"`
	Limits         storage.Limits `json:"limits"`
}

func enrollmentInput(t *testing.T) enrollmentFixture {
	t.Helper()
	var f enrollmentFixture
	raw, err := os.ReadFile("fixtures/miragemesh/C08/positive.json")
	if err != nil || json.Unmarshal(raw, &f) != nil || f.FixtureVersion != 1 || f.License != "Apache-2.0" || f.Provenance == "" {
		t.Fatal("invalid enrollment fixture", err)
	}
	return f
}

func enrollmentService(t *testing.T, store *storage.Store, now func() time.Time) *enrollment.Service {
	t.Helper()
	f := enrollmentInput(t)
	s, err := enrollment.New(store, time.Duration(f.MaxTTLSeconds)*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestEnrollmentIssueConsumeAndRestart(t *testing.T) {
	f := enrollmentInput(t)
	path := storePath(t)
	store := openStore(t, path, f.Limits)
	s := enrollmentService(t, store, func() time.Time { return f.Now })
	issued, err := s.Issue(context.Background(), f.SensorID, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(issued.Token)
	if err != nil || len(decoded) != 32 || !issued.ExpiresAt.Equal(f.Now.Add(30*time.Second)) {
		t.Fatal("invalid issued token contract")
	}
	marshaled, err := json.Marshal(issued)
	if err != nil || bytes.Contains(marshaled, []byte(issued.Token)) {
		t.Fatal("token leaked through generic JSON output")
	}
	store.Close()
	store = openStore(t, path, f.Limits)
	s = enrollmentService(t, store, func() time.Time { return f.Now.Add(time.Second) })
	result, err := s.Consume(context.Background(), issued.Token, f.SensorID)
	if err != nil || result.SensorID != f.SensorID || result.Receipt.Generation != 2 {
		t.Fatal("consume did not commit enrollment", err)
	}
	if _, err = s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatal("replay succeeded", err)
	}
	store.Close()
	store = openStore(t, path, f.Limits)
	s = enrollmentService(t, store, func() time.Time { return f.Now.Add(2 * time.Second) })
	if _, err = s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatal("post-restart replay succeeded", err)
	}
	for _, prefix := range []string{"enrollment/issue/", "enrollment/consume/"} {
		r, err := store.Read(context.Background(), prefix+tokenHash(issued.Token))
		if err != nil || r.Enrollment == nil || r.Enrollment.SensorID != f.SensorID {
			t.Fatal("missing durable enrollment record", err)
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil || bytes.Contains(raw, []byte(issued.Token)) || bytes.Contains(raw, decoded) {
			t.Fatal("raw token persisted", err)
		}
	}
}

func TestEnrollmentRejectsInvalidExpiredAndScopedTokens(t *testing.T) {
	f := enrollmentInput(t)
	path := storePath(t)
	store := openStore(t, path, f.Limits)
	now := f.Now
	s := enrollmentService(t, store, func() time.Time { return now })
	for _, maxTTL := range []time.Duration{0, -time.Second} {
		if _, err := enrollment.New(store, maxTTL, time.Now); !errors.Is(err, enrollment.ErrInvalidInput) {
			t.Fatal("invalid max TTL accepted", err)
		}
	}
	if _, err := enrollment.New(nil, time.Minute, time.Now); !errors.Is(err, enrollment.ErrInvalidInput) {
		t.Fatal("missing store accepted", err)
	}
	if _, err := enrollment.New(store, time.Minute, nil); !errors.Is(err, enrollment.ErrInvalidInput) {
		t.Fatal("missing clock accepted", err)
	}
	var invalid struct {
		Cases []struct {
			Name       string `json:"name"`
			TTLSeconds int    `json:"ttl_seconds"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile("fixtures/miragemesh/C08/invalid.json")
	if err != nil || json.Unmarshal(raw, &invalid) != nil || len(invalid.Cases) != 3 {
		t.Fatal("invalid negative fixture", err)
	}
	for _, c := range invalid.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := s.Issue(context.Background(), f.SensorID, time.Duration(c.TTLSeconds)*time.Second); !errors.Is(err, enrollment.ErrInvalidTTL) {
				t.Fatal("invalid TTL accepted", err)
			}
		})
	}
	for _, id := range []string{"", strings.Repeat("x", 129), string([]byte{255})} {
		if _, err := s.Issue(context.Background(), id, time.Second); !errors.Is(err, enrollment.ErrInvalidInput) {
			t.Fatal("invalid sensor accepted", err)
		}
	}
	issued, err := s.Issue(context.Background(), f.SensorID, time.Duration(f.MaxTTLSeconds)*time.Second)
	if err != nil {
		t.Fatal("max TTL boundary rejected", err)
	}
	before, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "secret-sentinel", strings.Repeat("A", 44), strings.Repeat("B", 43), strings.Repeat("A", 43)} {
		if _, err := s.Consume(context.Background(), token, f.SensorID); !errors.Is(err, enrollment.ErrInvalidToken) || strings.Contains(err.Error(), "secret-sentinel") {
			t.Fatal("invalid/unknown token accepted or leaked")
		}
	}
	if _, err := s.Consume(context.Background(), issued.Token, "other-sensor"); !errors.Is(err, enrollment.ErrScope) {
		t.Fatal("wrong scope accepted", err)
	}
	now = f.Now.Add(-time.Second)
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, enrollment.ErrInvalidInput) {
		t.Fatal("clock before issuance accepted", err)
	}
	now = issued.ExpiresAt
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, enrollment.ErrExpired) {
		t.Fatal("expiry boundary accepted", err)
	}
	if _, err := store.Read(context.Background(), "enrollment/consume/"+tokenHash(issued.Token)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("rejected token had side effects", err)
	}
	after, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected tokens changed authoritative state", err)
	}
	now = f.Now
	valid, err := s.Issue(context.Background(), f.SensorID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), valid.Token, "other-sensor"); !errors.Is(err, enrollment.ErrScope) {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), valid.Token, f.SensorID); err != nil {
		t.Fatal("scope rejection consumed token", err)
	}
}

func TestEnrollmentConcurrentConsumptionAndSensorCompatibility(t *testing.T) {
	f := enrollmentInput(t)
	path := storePath(t)
	store := openStore(t, path, f.Limits)
	events, _, _ := sensorEvents(t)
	first, err := sensor.Accept(context.Background(), store, events[0])
	if err != nil {
		t.Fatal(err)
	}
	s := enrollmentService(t, store, func() time.Time { return f.Now })
	issued, err := s.Issue(context.Background(), f.SensorID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		other := enrollmentService(t, store, func() time.Time { return f.Now })
		wg.Go(func() {
			_, err := other.Consume(context.Background(), issued.Token, f.SensorID)
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, enrollment.ErrReplay) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("successful consumers: %d", success.Load())
	}
	if _, err := sensor.Accept(context.Background(), store, events[1]); err != nil {
		t.Fatal("enrollment broke sensor sequence", err)
	}
	store.Close()
	store = openStore(t, path, f.Limits)
	if replay, err := sensor.Accept(context.Background(), store, events[0]); err != nil || replay != first {
		t.Fatal("enrollment broke exact sensor replay", err)
	}
	if _, err := sensor.Accept(context.Background(), store, events[2]); err != nil {
		t.Fatal("mixed-record recovery broke sequence", err)
	}
}

func TestEnrollmentStorageFailuresAndCancellation(t *testing.T) {
	f := enrollmentInput(t)
	path := storePath(t)
	limits := f.Limits
	limits.MaxOperations = 1
	store := openStore(t, path, limits)
	s := enrollmentService(t, store, func() time.Time { return f.Now })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Issue(ctx, f.SensorID, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	issued, err := s.Issue(context.Background(), f.SensorID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(ctx, issued.Token, f.SensorID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, storage.ErrQuota) {
		t.Fatal("quota ignored", err)
	}
	store.Close()
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, storage.ErrClosed) {
		t.Fatal("closed store authorized consumption", err)
	}
	store = openStore(t, path, f.Limits)
	s = enrollmentService(t, store, func() time.Time { return f.Now })
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); err != nil {
		t.Fatal("quota/cancellation consumed token", err)
	}
	store.Close()
	entries, _ := os.ReadDir(path)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "object-") {
			os.WriteFile(filepath.Join(path, entry.Name()), []byte("corrupt"), 0600)
			break
		}
	}
	if reopened, err := storage.Open(path, f.Limits); !errors.Is(err, storage.ErrRecovery) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("corruption accepted", err)
	}
}

func TestEnrollmentRechecksClockBeforePublication(t *testing.T) {
	f := enrollmentInput(t)
	store := openStore(t, storePath(t), f.Limits)
	calls := 0
	s := enrollmentService(t, store, func() time.Time {
		calls++
		if calls == 1 {
			return f.Now
		}
		return f.Now.Add(time.Second)
	})
	if _, err := s.Issue(context.Background(), f.SensorID, time.Second); !errors.Is(err, enrollment.ErrExpired) {
		t.Fatal("issued token expired while waiting for writer", err)
	}
	s = enrollmentService(t, store, func() time.Time { return f.Now })
	issued, err := s.Issue(context.Background(), f.SensorID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	s = enrollmentService(t, store, func() time.Time {
		calls++
		if calls == 1 {
			return f.Now
		}
		return issued.ExpiresAt
	})
	if _, err := s.Consume(context.Background(), issued.Token, f.SensorID); !errors.Is(err, enrollment.ErrExpired) {
		t.Fatal("consumed after expiry under writer lock", err)
	}
	if _, err := store.Read(context.Background(), "enrollment/consume/"+tokenHash(issued.Token)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("expired consumption published", err)
	}
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s = enrollmentService(t, store, func() time.Time { return now })
		if _, err := s.Issue(context.Background(), f.SensorID, time.Second); !errors.Is(err, enrollment.ErrInvalidInput) {
			t.Fatal("invalid clock accepted", err)
		}
	}
}

func TestEnrollmentRejectsForgedStoredIdentity(t *testing.T) {
	f := enrollmentInput(t)
	token := strings.Repeat("A", 43)
	events, _, _ := sensorEvents(t)
	for _, raw := range [][]byte{
		events[0],
		[]byte(`{"schema_version":"1","kind":"enrollment.consume","sensor_id":"sensor-01","token_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issued_at":"2026-10-20T00:00:00Z","expires_at":"2026-10-20T00:01:00Z","consumed_at":"2026-10-20T00:00:01Z"}`),
	} {
		path := storePath(t)
		store := openStore(t, path, f.Limits)
		if _, err := store.Commit(context.Background(), "enrollment/issue/"+tokenHash(token), raw); err != nil {
			t.Fatal(err)
		}
		s := enrollmentService(t, store, func() time.Time { return f.Now })
		before, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
		if _, err := s.Consume(context.Background(), token, f.SensorID); !errors.Is(err, storage.ErrRecovery) {
			t.Fatal("forged stored identity authorized enrollment", err)
		}
		after, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("forged identity caused publication")
		}
	}
}
