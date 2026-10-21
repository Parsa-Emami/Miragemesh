package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func c11Files(t *testing.T) (*c10Positive, storage.Limits, *c10Invalid) {
	t.Helper()
	var fixture struct {
		c10Positive
		StorageLimits storage.Limits `json:"storage_limits"`
	}
	var invalid c10Invalid
	var expected struct {
		FixtureVersion int    `json:"fixture_version"`
		License        string `json:"license"`
		Provenance     string `json:"provenance"`
		NegativeRows   int    `json:"negative_rows"`
	}
	for name, target := range map[string]any{"positive": &fixture, "invalid": &invalid, "expected-output": &expected} {
		raw, err := os.ReadFile("fixtures/miragemesh/C11/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C11 fixture %s: %v", name, err)
		}
	}
	if fixture.FixtureVersion != 1 || invalid.FixtureVersion != 1 || expected.FixtureVersion != 1 || fixture.License != "Apache-2.0" || invalid.License != "Apache-2.0" || expected.License != "Apache-2.0" || fixture.Provenance == "" || invalid.Provenance == "" || expected.Provenance == "" || expected.NegativeRows != len(invalid.Cases) || len(invalid.Cases) == 0 {
		t.Fatal("invalid C11 fixture metadata")
	}
	return &fixture.c10Positive, fixture.StorageLimits, &invalid
}

func c11Applier(t *testing.T, s *storage.Store, verifier config.Verifier) *sensor.Applier {
	t.Helper()
	a, err := sensor.NewApplier(context.Background(), s, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func c11Apply(t *testing.T, a *sensor.Applier, key ed25519.PrivateKey, payload string) config.Applied {
	t.Helper()
	raw := []byte(payload)
	result, err := a.Apply(context.Background(), raw, ed25519.Sign(key, raw))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestApplyDurableRevisionAndRestart(t *testing.T) {
	f, limits, _ := c11Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, f, public, f.Bounds)
	path := storePath(t)
	s := openStore(t, path, limits)
	a := c11Applier(t, s, v)
	events, _, _ := sensorEvents(t)
	if _, err := sensor.Accept(context.Background(), s, events[0]); err != nil {
		t.Fatal(err)
	}
	first := c11Apply(t, a, key, f.Payloads["initial"])
	want := c11Apply(t, a, key, f.Payloads["next"])
	if first.Revision != 1 || want.Revision != 2 || !bytes.Equal(want.Payload, []byte(f.Payloads["next"])) {
		t.Fatal("unexpected applied state")
	}
	e, err := enrollment.New(s, time.Minute, v.Clock)
	if err != nil {
		t.Fatal(err)
	}
	token, err := e.Issue(context.Background(), f.SensorID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Consume(context.Background(), token.Token, f.SensorID); err != nil {
		t.Fatal(err)
	}
	if _, err = sensor.Accept(context.Background(), s, events[1]); err != nil {
		t.Fatal("config broke event sequence", err)
	}
	before, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = openStore(t, path, limits)
	v.Clock = func() time.Time { return want.AppliedAt.Add(time.Second) }
	a = c11Applier(t, s, v)
	got, exists, err := a.Active(context.Background(), f.SensorID)
	if err != nil || !exists || !reflect.DeepEqual(got, want) {
		t.Fatalf("recovered %+v: %v", got, err)
	}
	if replay := c11Apply(t, a, key, f.Payloads["next"]); !reflect.DeepEqual(replay, want) {
		t.Fatal("retry changed original apply time or bytes")
	}
	after, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("retry wrote a new generation")
	}
	got.Payload[0] = '!'
	again, _, err := a.Active(context.Background(), f.SensorID)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("returned payload aliases durable state", err)
	}
	// Expiration does not erase the historical applied revision or permit rollback.
	v.Clock = func() time.Time { return want.AppliedAt.AddDate(1, 0, 0) }
	a = c11Applier(t, s, v)
	got, exists, err = a.Active(context.Background(), f.SensorID)
	if err != nil || !exists || !reflect.DeepEqual(got, want) {
		t.Fatal("expired history lost its revision", err)
	}
	if _, err = a.Apply(context.Background(), want.Payload, ed25519.Sign(key, want.Payload)); !errors.Is(err, config.ErrExpired) {
		t.Fatal("expired document readmitted", err)
	}
}

func TestApplyRejectsInvalidDesiredStateWithoutDurableChanges(t *testing.T) {
	f, limits, invalid := c11Files(t)
	public, key := c10Key(t)
	_, other := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, limits)
	a := c11Applier(t, s, c10Verifier(t, f, public, f.Bounds))
	want := c11Apply(t, a, key, f.Payloads["next"])
	before, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	for _, row := range invalid.Cases {
		t.Run(row.Name, func(t *testing.T) {
			got, err := a.Apply(context.Background(), c10Payload(t, row), c10Signature(t, row, key, other))
			if !errors.Is(err, c10Verdicts()[row.Expected]) || !reflect.DeepEqual(got, config.Applied{}) {
				t.Fatalf("result %+v: %v", got, err)
			}
			active, exists, err := a.Active(context.Background(), f.SensorID)
			if err != nil || !exists || !reflect.DeepEqual(active, want) {
				t.Fatal("rejection changed state", err)
			}
			after, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("rejection wrote a generation")
			}
		})
	}
}

func TestApplyConcurrentReconcilersAndReplay(t *testing.T) {
	f, limits, _ := c11Files(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), limits)
	v := c10Verifier(t, f, public, f.Bounds)
	a, b := c11Applier(t, s, v), c11Applier(t, s, v)
	var wg sync.WaitGroup
	results := make(chan config.Applied, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			applier := a
			if i%2 == 1 {
				applier = b
			}
			raw := []byte(f.Payloads["next"])
			result, err := applier.Apply(context.Background(), raw, ed25519.Sign(key, raw))
			if err != nil {
				t.Error(err)
				return
			}
			results <- result
		}(i)
	}
	wg.Wait()
	close(results)
	var want config.Applied
	for result := range results {
		if want.Revision == 0 {
			want = result
		}
		if !reflect.DeepEqual(result, want) {
			t.Fatal("concurrent replay differs")
		}
	}
	if want.Revision != 2 {
		t.Fatal("no committed result")
	}
	for _, applier := range []*sensor.Applier{a, b} {
		raw := []byte(f.Payloads["initial"])
		if _, err := applier.Apply(context.Background(), raw, ed25519.Sign(key, raw)); !errors.Is(err, config.ErrStale) {
			t.Fatal("stale replay accepted", err)
		}
		raw = []byte(strings.Replace(f.Payloads["next"], `"heartbeat_seconds":45`, `"heartbeat_seconds":60`, 1))
		if _, err := applier.Apply(context.Background(), raw, ed25519.Sign(key, raw)); !errors.Is(err, config.ErrConflict) {
			t.Fatal("conflicting revision accepted", err)
		}
	}
	records, err := s.Records(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatal("duplicate durable revision", err)
	}
	// Distinct signed documents for the same new revision cannot both win.
	outcomes := make(chan error, 2)
	for i, applier := range []*sensor.Applier{a, b} {
		raw := []byte(strings.Replace(f.Payloads["next"], `"revision":2`, `"revision":3`, 1))
		if i == 1 {
			raw = bytes.Replace(raw, []byte(`"heartbeat_seconds":45`), []byte(`"heartbeat_seconds":60`), 1)
		}
		go func(applier *sensor.Applier, raw []byte) {
			_, err := applier.Apply(context.Background(), raw, ed25519.Sign(key, raw))
			outcomes <- err
		}(applier, raw)
	}
	wins, conflicts := 0, 0
	for range 2 {
		err := <-outcomes
		if err == nil {
			wins++
		} else if errors.Is(err, config.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("conflicting writers were not serialized", wins, conflicts)
	}
	left, _, err := a.Active(context.Background(), f.SensorID)
	if err != nil {
		t.Fatal(err)
	}
	right, _, err := b.Active(context.Background(), f.SensorID)
	if err != nil || left.Revision != 3 || !reflect.DeepEqual(left, right) {
		t.Fatal("reconcilers disagree", err)
	}
}

func TestApplyPrerequisitesQuotaAndCancellation(t *testing.T) {
	f, limits, _ := c11Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, f, public, f.Bounds)
	s := openStore(t, storePath(t), limits)
	if _, err := sensor.NewApplier(context.Background(), nil, v); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, err := sensor.NewApplier(context.Background(), s, config.Verifier{}); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sensor.NewApplier(ctx, s, v); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var absent *sensor.Applier
	if _, err := absent.Apply(context.Background(), nil, nil); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, _, err := absent.Active(context.Background(), f.SensorID); !errors.Is(err, config.ErrInvalidInput) {
		t.Fatal(err)
	}
	v.MaxSensors = 1
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	raw := []byte(f.Payloads["next"])
	if _, err := a.Apply(ctx, raw, ed25519.Sign(key, raw)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(f.Payloads["initial"], f.SensorID, "sensor-02", 1))
	if _, err := a.Apply(context.Background(), raw, ed25519.Sign(key, raw)); !errors.Is(err, config.ErrQuota) {
		t.Fatal(err)
	}
	limits.MaxOperations = 1
	small := openStore(t, storePath(t), limits)
	a = c11Applier(t, small, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	raw = []byte(f.Payloads["next"])
	if got, err := a.Apply(context.Background(), raw, ed25519.Sign(key, raw)); !errors.Is(err, storage.ErrQuota) || got.Revision != 0 {
		t.Fatal("quota reported success", err)
	}
	small.Close()
	if _, _, err := a.Active(context.Background(), f.SensorID); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
}

func TestApplyRecoveryRejectsForgedHistory(t *testing.T) {
	f, limits, _ := c11Files(t)
	public, key := c10Key(t)
	_, other := c10Key(t)
	for _, kind := range []string{"wrong-signer", "invalid-time", "wrong-operation", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			s := openStore(t, storePath(t), limits)
			v := c10Verifier(t, f, public, f.Bounds)
			a := c11Applier(t, s, v)
			c11Apply(t, a, key, f.Payloads["next"])
			raw := []byte(strings.Replace(f.Payloads["next"], `"revision":2`, `"revision":3`, 1))
			if kind == "rollback" {
				raw = []byte(f.Payloads["initial"])
			}
			sig := ed25519.Sign(key, raw)
			at := v.Clock()
			if kind == "wrong-signer" {
				sig = ed25519.Sign(other, raw)
			}
			if kind == "invalid-time" {
				at = at.AddDate(1, 0, 0)
			}
			record := contracts.AppliedConfig{SchemaVersion: "1", Kind: contracts.ConfigApplied, Payload: raw, Signature: sig, AppliedAt: at.Format(time.RFC3339Nano)}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			// Direct writes emulate a structurally valid record from an untrusted caller.
			doc, err := config.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("config/%x/%d", sha256.Sum256([]byte(doc.SensorID)), doc.Revision)
			if kind == "wrong-operation" {
				id = "forged"
			}
			if _, err = s.Commit(context.Background(), id, encoded); err != nil {
				t.Fatal(err)
			}
			if _, err = sensor.NewApplier(context.Background(), s, v); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("forged history recovered", err)
			}
			if _, _, err = a.Active(context.Background(), f.SensorID); !errors.Is(err, storage.ErrRecovery) {
				t.Fatal("existing service hid corrupt history", err)
			}
		})
	}
}

func TestApplyPreservesMaximumExactPayload(t *testing.T) {
	f, limits, _ := c11Files(t)
	public, key := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, limits)
	a := c11Applier(t, s, c10Verifier(t, f, public, f.Bounds))
	raw := []byte(f.Payloads["initial"])
	// Whitespace is signed too; the envelope must not reduce C10's payload cap.
	raw = append(raw, bytes.Repeat([]byte(" "), contracts.MaxInputBytes-len(raw))...)
	got, err := a.Apply(context.Background(), raw, ed25519.Sign(key, raw))
	if err != nil || !bytes.Equal(got.Payload, raw) {
		t.Fatal("maximum signed bytes changed or rejected", err)
	}
	s.Close()
	s = openStore(t, path, limits)
	a = c11Applier(t, s, c10Verifier(t, f, public, f.Bounds))
	got, exists, err := a.Active(context.Background(), f.SensorID)
	if err != nil || !exists || !bytes.Equal(got.Payload, raw) {
		t.Fatal("maximum payload could not reopen", err)
	}
}

func TestApplyRechecksClockAndCancellationInsideWriterLock(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, limits, _ := c11Files(t)
			public, key := c10Key(t)
			v := c10Verifier(t, f, public, f.Bounds)
			initial := v.Clock()
			var offset atomic.Int64
			var signal atomic.Bool
			checked := make(chan struct{}, 1)
			v.Clock = func() time.Time {
				instant := initial.Add(time.Duration(offset.Load()))
				if signal.CompareAndSwap(true, false) {
					checked <- struct{}{}
				}
				return instant
			}
			s := openStore(t, storePath(t), limits)
			a := c11Applier(t, s, v)
			want := c11Apply(t, a, key, f.Payloads["initial"])
			locked, release := make(chan struct{}), make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.Update(context.Background(), func([]storage.Record) (string, []byte, error) {
					close(locked)
					<-release
					return "", nil, storage.ErrInvalidInput
				})
			}()
			<-locked
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			signal.Store(true)
			result := make(chan error, 1)
			raw := []byte(f.Payloads["next"])
			go func() { _, err := a.Apply(ctx, raw, ed25519.Sign(key, raw)); result <- err }()
			select {
			case <-checked:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("apply did not check its clock")
			}
			wantError := config.ErrExpired
			if mode == "expiry" {
				offset.Store(int64(366 * 24 * time.Hour))
			} else {
				cancel()
				wantError = context.Canceled
			}
			close(release)
			<-done
			select {
			case err := <-result:
				if !errors.Is(err, wantError) {
					t.Fatal("admitted while waiting", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("apply did not finish")
			}
			active, exists, err := a.Active(context.Background(), f.SensorID)
			if err != nil || !exists || !reflect.DeepEqual(active, want) {
				t.Fatal("waiting apply changed active state", err)
			}
		})
	}
}
