package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c14Fixture struct {
	c10Positive
	StorageLimits storage.Limits `json:"storage_limits"`
	Events        []string       `json:"events"`
	OtherEvent    string         `json:"other_event"`
}

func c14Files(t *testing.T) c14Fixture {
	t.Helper()
	var f c14Fixture
	raw, err := os.ReadFile("fixtures/miragemesh/C14/positive.json")
	if err != nil || json.Unmarshal(raw, &f) != nil || f.FixtureVersion != 1 || f.License != "Apache-2.0" || f.Provenance == "" || len(f.Events) != 4 {
		t.Fatal("invalid C14 positive fixture", err)
	}
	return f
}

func c14Spool(t *testing.T, s *storage.Store, a *sensor.Applier) *spool.Store {
	t.Helper()
	q, err := spool.New(s, a)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func c14Manifest(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSpoolDurableBoundedReplayAndRestart(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	var expected struct {
		FixtureVersion    int     `json:"fixture_version"`
		License           string  `json:"license"`
		Provenance        string  `json:"provenance"`
		AcceptedSequences []int64 `json:"accepted_sequences"`
		FullError         string  `json:"full_error"`
	}
	raw, err := os.ReadFile("fixtures/miragemesh/C14/expected-output.json")
	if err != nil || json.Unmarshal(raw, &expected) != nil || expected.FixtureVersion != 1 || expected.License != "Apache-2.0" || expected.Provenance == "" || len(expected.AcceptedSequences) != 2 {
		t.Fatal("invalid C14 expected fixture", err)
	}
	receipts := make([]storage.Receipt, 2)
	for i := range receipts {
		receipts[i], err = q.Enqueue(context.Background(), []byte(f.Events[i]))
		if err != nil {
			t.Fatal(err)
		}
	}
	before := c14Manifest(t, path)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	a = c11Applier(t, s, v)
	q = c14Spool(t, s, a)
	for i, want := range receipts {
		got, err := q.Enqueue(context.Background(), []byte(f.Events[i]))
		if err != nil || got != want {
			t.Fatalf("lost-ack replay: %+v %v", got, err)
		}
		record, err := s.Read(context.Background(), want.OperationID)
		if err != nil || record.Event.Sequence != expected.AcceptedSequences[i] || !bytes.Equal(record.Input, []byte(f.Events[i])) {
			t.Fatalf("recovered event: %+v %v", record, err)
		}
	}
	got, err := q.Enqueue(context.Background(), []byte(f.Events[2]))
	if !errors.Is(err, storage.ErrQuota) || err.Error() != expected.FullError || got != (storage.Receipt{}) {
		t.Fatalf("full spool: %+v %v", got, err)
	}
	if !bytes.Equal(before, c14Manifest(t, path)) {
		t.Fatal("replay or overflow changed authoritative bytes")
	}
}

func TestSpoolRejectsInvalidAndUnconfiguredEvents(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	q := c14Spool(t, s, a)
	before := c14Manifest(t, path)
	if got, err := q.Enqueue(context.Background(), []byte(f.Events[0])); !errors.Is(err, spool.ErrUnconfigured) || got != (storage.Receipt{}) {
		t.Fatalf("missing configuration: %+v %v", got, err)
	}
	if !bytes.Equal(before, c14Manifest(t, path)) {
		t.Fatal("missing configuration committed data")
	}
	c11Apply(t, a, key, f.Payloads["initial"])
	if _, err := q.Enqueue(context.Background(), []byte(f.Events[0])); err != nil {
		t.Fatal(err)
	}
	before = c14Manifest(t, path)
	var negative struct {
		FixtureVersion int                                          `json:"fixture_version"`
		License        string                                       `json:"license"`
		Provenance     string                                       `json:"provenance"`
		Cases          []struct{ Name, Input, Build, Error string } `json:"cases"`
	}
	raw, err := os.ReadFile("fixtures/miragemesh/C14/invalid.json")
	if err != nil || json.Unmarshal(raw, &negative) != nil || negative.FixtureVersion != 1 || negative.License != "Apache-2.0" || negative.Provenance == "" || len(negative.Cases) != 8 {
		t.Fatal("invalid C14 negative fixture", err)
	}
	verdicts := map[string]error{"invalid_event": sensor.ErrInvalidEvent, "out_of_order": sensor.ErrOutOfOrder, "conflict": storage.ErrConflict, "unconfigured": spool.ErrUnconfigured}
	for _, row := range negative.Cases {
		t.Run(row.Name, func(t *testing.T) {
			input := []byte(row.Input)
			if row.Build == "oversized" {
				input = bytes.Repeat([]byte(" "), contracts.MaxInputBytes+1)
			}
			want := verdicts[row.Error]
			if want == nil {
				t.Fatal("unknown expected verdict")
			}
			got, err := q.Enqueue(context.Background(), input)
			if !errors.Is(err, want) || got != (storage.Receipt{}) {
				t.Fatalf("rejection: %+v %v, want %v", got, err, want)
			}
			if !bytes.Equal(before, c14Manifest(t, path)) {
				t.Fatal("rejection changed manifest")
			}
		})
	}
	for _, pair := range []struct {
		s *storage.Store
		a *sensor.Applier
	}{{nil, a}, {s, nil}} {
		if _, err := spool.New(pair.s, pair.a); err == nil {
			t.Fatal("missing dependency accepted")
		}
	}
	other := openStore(t, storePath(t), f.StorageLimits)
	mismatch := c14Spool(t, other, a)
	if got, err := mismatch.Enqueue(context.Background(), []byte(f.Events[0])); !errors.Is(err, config.ErrInvalidInput) || got != (storage.Receipt{}) {
		t.Fatalf("mismatched config store: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Enqueue(ctx, []byte(f.Events[1])); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var absent *spool.Store
	if _, err := absent.Enqueue(context.Background(), []byte(f.Events[0])); err == nil {
		t.Fatal("nil spool accepted event")
	}
	s.Close()
	if _, err := q.Enqueue(context.Background(), []byte(f.Events[1])); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
}

func TestSpoolCapacityIsAtomicAndPerSensor(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	c11Apply(t, a, key, f.Payloads["other"])
	queues := []*spool.Store{c14Spool(t, s, a), c14Spool(t, s, a)}
	var wg sync.WaitGroup
	for i := 1; i <= 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := []byte(strings.ReplaceAll(strings.ReplaceAll(f.Events[0], `"sequence":1`, fmt.Sprintf(`"sequence":%d`, i)), `"event-01"`, fmt.Sprintf(`"event-%02d"`, i)))
			for attempt := 0; attempt < 30; attempt++ {
				_, err := queues[i%2].Enqueue(context.Background(), event)
				if err == nil || errors.Is(err, storage.ErrQuota) {
					return
				}
				if !errors.Is(err, sensor.ErrOutOfOrder) {
					t.Error(err)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	if _, err := queues[0].Enqueue(context.Background(), []byte(f.OtherEvent)); err != nil {
		t.Fatal("another sensor lost its own capacity", err)
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, r := range records {
		if r.Config == nil && r.Enrollment == nil {
			counts[r.Event.SensorID]++
		}
	}
	if counts["sensor-01"] != 2 || counts["sensor-02"] != 1 {
		t.Fatalf("per-sensor capacity: %v", counts)
	}
}

func TestSpoolUsesLatestAppliedBoundWithoutDropping(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	first, err := sensor.Accept(context.Background(), s, []byte(f.Events[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.Enqueue(context.Background(), []byte(f.Events[0])); err != nil || got != first {
		t.Fatal("spool changed existing sensor identity", got, err)
	}
	if _, err = q.Enqueue(context.Background(), []byte(f.Events[1])); err != nil {
		t.Fatal(err)
	}
	c11Apply(t, a, key, f.Payloads["lower"])
	if _, err = q.Enqueue(context.Background(), []byte(f.Events[2])); !errors.Is(err, storage.ErrQuota) {
		t.Fatal("lower bound ignored", err)
	}
	if got, err := q.Enqueue(context.Background(), []byte(f.Events[0])); err != nil || got != first {
		t.Fatal("lower bound erased replay", got, err)
	}
	for _, input := range f.Events[:2] {
		e, _ := contracts.DecodeEvent(context.Background(), []byte(input))
		records, err := s.Records(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range records {
			if r.Event.EventID == e.EventID && bytes.Equal(r.Input, []byte(input)) {
				found = true
			}
		}
		if !found {
			t.Fatal("lowering bound deleted data")
		}
	}
	c11Apply(t, a, key, f.Payloads["raise"])
	if _, err = q.Enqueue(context.Background(), []byte(f.Events[2])); err != nil {
		t.Fatal("new bound not consumed", err)
	}
	if _, err = q.Enqueue(context.Background(), []byte(f.Events[3])); !errors.Is(err, storage.ErrQuota) {
		t.Fatal(err)
	}
	// Existing C07 admission remains independent of the new spool consumer.
	if _, err = sensor.Accept(context.Background(), s, []byte(f.Events[3])); err != nil {
		t.Fatal("legacy acceptance changed", err)
	}
}

func TestSpoolStorageQuotaAndRecoveryFailures(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	limits := f.StorageLimits
	limits.MaxOperations = 2
	path := storePath(t)
	s := openStore(t, path, limits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	first, err := q.Enqueue(context.Background(), []byte(f.Events[0]))
	if err != nil {
		t.Fatal(err)
	}
	before := c14Manifest(t, path)
	if got, err := q.Enqueue(context.Background(), []byte(f.Events[1])); !errors.Is(err, storage.ErrQuota) || got != (storage.Receipt{}) {
		t.Fatal(got, err)
	}
	if !bytes.Equal(before, c14Manifest(t, path)) {
		t.Fatal("quota changed manifest")
	}
	if err := os.WriteFile(filepath.Join(path, "object-"+first.InputDigest+".json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := q.Enqueue(context.Background(), []byte(f.Events[1])); !errors.Is(err, storage.ErrRecovery) || got != (storage.Receipt{}) {
		t.Fatal("corrupt authority accepted", got, err)
	}
}

func TestSpoolRejectsForgedAppliedConfiguration(t *testing.T) {
	f := c14Files(t)
	public, key := c10Key(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, c10Verifier(t, &f.c10Positive, public, f.Bounds))
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	// A canonical storage envelope alone cannot grant a larger signed limit.
	forged := contracts.AppliedConfig{SchemaVersion: "1", Kind: contracts.ConfigApplied,
		Payload: []byte(f.Payloads["raise"]), Signature: ed25519.Sign(key, []byte(f.Payloads["initial"])), AppliedAt: f.Now}
	raw, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Commit(context.Background(), "forged", raw); err != nil {
		t.Fatal(err)
	}
	got, err := q.Enqueue(context.Background(), []byte(f.Events[0]))
	if !errors.Is(err, storage.ErrRecovery) || got != (storage.Receipt{}) {
		t.Fatalf("forged config accepted: %+v %v", got, err)
	}
}
