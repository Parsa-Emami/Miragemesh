package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"github.com/Parsa-Emami/Miragemesh/internal/update"
	f "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C25"
)

var updateAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
var updateLimits = storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536}

func updateOpen(t *testing.T, dir string, m f.Material, clock func() time.Time) (*storage.Store, *update.Verifier) {
	t.Helper()
	s, err := storage.Open(dir, updateLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	v, err := update.New(context.Background(), s, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 8, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func updateAccept(t *testing.T, v *update.Verifier, m f.Material, revision uint64, revoked []uint64, versions ...uint64) update.MetadataResult {
	t.Helper()
	p := f.Metadata(updateAt, revision, "sensor-25", revoked, versions...)
	r, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func updateRequest(version uint64) update.Request {
	return update.Request{SensorID: "sensor-25", Version: version, Artifact: bytes.NewReader(f.Artifact(version))}
}

func TestUpdateSignedMetadataAndArtifactSurviveRestart(t *testing.T) {
	m := f.Generate()
	dir := filepath.Join(t.TempDir(), "state")
	s, v := updateOpen(t, dir, m, func() time.Time { return updateAt })
	accepted := updateAccept(t, v, m, 1, nil, 2, 4)
	if accepted.Revision != 1 || accepted.Replayed {
		t.Fatal(accepted)
	}
	r, err := v.Verify(context.Background(), updateRequest(4))
	if err != nil || r.Version != 4 || r.HighWaterVersion != 4 || r.MetadataRevision != 1 || r.Replayed {
		t.Fatal(r, err)
	}
	again, err := v.Verify(context.Background(), updateRequest(4))
	if err != nil || !again.Replayed || again.Receipt != r.Receipt {
		t.Fatal(again, err)
	}
	var fixture struct {
		Event    string `json:"event"`
		Now      string `json:"now"`
		SensorID string `json:"sensor_id"`
	}
	rawFixture, err := os.ReadFile("fixtures/miragemesh/C25/positive.json")
	if err != nil || json.Unmarshal(rawFixture, &fixture) != nil || fixture.SensorID != "sensor-25" || fixture.Now != "2026-01-01T00:00:00Z" {
		t.Fatal("invalid positive fixture", err)
	}
	if _, err := sensor.Accept(context.Background(), s, []byte(fixture.Event)); err != nil {
		t.Fatal(err)
	}
	records, _ := s.Records(context.Background())
	log, err := events.Open(filepath.Join(t.TempDir(), "segments"), events.Limits{MaxSegments: 8, MaxRecordsPerSegment: 16, MaxBytesPerSegment: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if _, err := log.AppendRecords(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, v = updateOpen(t, dir, m, func() time.Time { return updateAt })
	snap, err := v.Snapshot(context.Background())
	if err != nil || len(snap.Sensors) != 1 || snap.Sensors[0].Version != 4 || snap.Sensors[0].HighWaterVersion != 4 || snap.Sensors[0].Status != "verified" {
		t.Fatal(snap, err)
	}
	if _, err := v.Verify(context.Background(), updateRequest(2)); !errors.Is(err, update.ErrRollback) {
		t.Fatal(err)
	}
}

func TestUpdateRejectsWrongSignerTamperingAndMissingEvidence(t *testing.T) {
	m := f.Generate()
	s, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	p := f.Metadata(updateAt, 1, "sensor-25", nil, 2, 4)
	sig := ed25519.Sign(m.Publisher, p)
	wrong := f.Generate()
	for _, signature := range [][]byte{nil, ed25519.Sign(wrong.Publisher, p), ed25519.Sign(m.Recovery, p)} {
		if _, err := v.Accept(context.Background(), p, signature); !errors.Is(err, update.ErrSignature) {
			t.Fatal(err)
		}
	}
	mutated := bytes.Replace(p, []byte(`"revision":1`), []byte(`"revision":2`), 1)
	if _, err := v.Accept(context.Background(), mutated, sig); !errors.Is(err, update.ErrSignature) {
		t.Fatal(err)
	}
	updateAccept(t, v, m, 1, nil, 2, 4)
	changed := append([]byte(nil), f.Artifact(4)...)
	changed[len(changed)-2] ^= 1
	for _, artifact := range [][]byte{nil, []byte("changed byte"), changed, append(f.Artifact(4), 0)} {
		req := updateRequest(4)
		req.Artifact = bytes.NewReader(artifact)
		if _, err := v.Verify(context.Background(), req); !errors.Is(err, update.ErrArtifact) {
			t.Fatal(err)
		}
	}
	if _, err := v.Verify(context.Background(), updateRequest(99)); !errors.Is(err, update.ErrEvidence) {
		t.Fatal(err)
	}
	records, _ := s.Records(context.Background())
	if len(records) != 1 {
		t.Fatal(len(records))
	}
}

func TestUpdateAuthorityRevisionExpiryAndRevocationAreDurable(t *testing.T) {
	m := f.Generate()
	at := updateAt
	dir := filepath.Join(t.TempDir(), "state")
	s, v := updateOpen(t, dir, m, func() time.Time { return at })
	updateAccept(t, v, m, 1, nil, 2, 3, 4)
	if _, err := v.Verify(context.Background(), updateRequest(3)); err != nil {
		t.Fatal(err)
	}
	updateAccept(t, v, m, 2, []uint64{3}, 2, 4)
	before, _ := s.Records(context.Background())
	if _, err := v.Verify(context.Background(), updateRequest(3)); !errors.Is(err, update.ErrRevoked) {
		t.Fatal(err)
	}
	p := f.Metadata(updateAt, 1, "sensor-25", nil, 2, 3, 4)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, update.ErrStale) {
		t.Fatal(err)
	}
	p = f.Metadata(updateAt, 2, "sensor-25", []uint64{3}, 2)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, update.ErrConflict) {
		t.Fatal(err)
	}
	p = f.Metadata(updateAt, 3, "sensor-25", nil, 2, 4)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, update.ErrRevoked) {
		t.Fatal(err)
	}
	p = f.Metadata(updateAt, 3, "sensor-25", []uint64{3}, 2, 4)
	raw := bytes.Replace(p, []byte(f.Digest(f.Artifact(4))), []byte(f.Digest([]byte("substitution"))), 1)
	if _, err := v.Accept(context.Background(), raw, ed25519.Sign(m.Publisher, raw)); !errors.Is(err, update.ErrConflict) {
		t.Fatal("release identity substitution accepted")
	}
	at = updateAt.Add(time.Hour)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, update.ErrExpired) {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), updateRequest(4)); !errors.Is(err, update.ErrExpired) {
		t.Fatal(err)
	}
	after, _ := s.Records(context.Background())
	if len(before) != len(after) {
		t.Fatal("rejection changed durable authority")
	}
	s.Close()
	_, v = updateOpen(t, dir, m, func() time.Time { return at })
	snap, err := v.Snapshot(context.Background())
	if err != nil || snap.Sensors[0].Revision != 2 || snap.Sensors[0].Status != "expired" {
		t.Fatal(snap, err)
	}
}

type updateAdvancingReader struct {
	data    *bytes.Reader
	advance func()
}

func (r *updateAdvancingReader) Read(p []byte) (int, error) { r.advance(); return r.data.Read(p) }

func TestUpdateRechecksExpiryAfterArtifactReadAndOnRecoveryRetry(t *testing.T) {
	m := f.Generate()
	at := updateAt
	s, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return at })
	updateAccept(t, v, m, 1, nil, 2, 4)
	request := updateRequest(4)
	request.Artifact = &updateAdvancingReader{bytes.NewReader(f.Artifact(4)), func() { at = updateAt.Add(time.Hour) }}
	if _, err := v.Verify(context.Background(), request); !errors.Is(err, update.ErrExpired) {
		t.Fatal(err)
	}
	at = updateAt
	v.Verify(context.Background(), updateRequest(4))
	g := f.Grant(updateAt, "expires", "sensor-25", 1, 4, 2)
	request = updateRequest(2)
	request.RecoveryPayload = g
	request.RecoverySignature = ed25519.Sign(m.Recovery, g)
	if _, err := v.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	at = updateAt.Add(10 * time.Minute)
	request.Artifact = bytes.NewReader(f.Artifact(2))
	before, _ := s.Records(context.Background())
	if _, err := v.Verify(context.Background(), request); !errors.Is(err, update.ErrRecovery) {
		t.Fatal("expired recovery replay reported trusted verification", err)
	}
	after, _ := s.Records(context.Background())
	if len(before) != len(after) {
		t.Fatal("expired retry changed state")
	}
}

func TestUpdateRejectsForgedHistoryAndEnforcesRealStorageQuota(t *testing.T) {
	m := f.Generate()
	dir := filepath.Join(t.TempDir(), "state")
	s, v := updateOpen(t, dir, m, func() time.Time { return updateAt })
	updateAccept(t, v, m, 1, nil, 4)
	records, _ := s.Records(context.Background())
	forged := *records[0].Update
	forged.Payload = f.Metadata(updateAt, 2, "sensor-25", nil, 4)
	raw, _ := json.Marshal(forged)
	id := "update/" + f.Digest([]byte("sensor-25")) + "/metadata/2"
	if _, err := s.Commit(context.Background(), id, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Snapshot(context.Background()); !errors.Is(err, storage.ErrRecovery) {
		t.Fatal(err)
	}
	s.Close()
	s, err := storage.Open(dir, updateLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := update.New(context.Background(), s, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 8, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: func() time.Time { return updateAt }}); !errors.Is(err, storage.ErrRecovery) {
		t.Fatal(err)
	}
	limited, err := storage.Open(filepath.Join(t.TempDir(), "quota"), storage.Limits{MaxOperations: 1, MaxBytes: 16384, MaxManifestBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	v, err = update.New(context.Background(), limited, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 1, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: func() time.Time { return updateAt }})
	if err != nil {
		t.Fatal(err)
	}
	updateAccept(t, v, m, 1, nil, 4)
	if _, err := v.Verify(context.Background(), updateRequest(4)); !errors.Is(err, storage.ErrQuota) {
		t.Fatal(err)
	}
	snapshot, err := v.Snapshot(context.Background())
	if err != nil || snapshot.Sensors[0].Version != 0 || snapshot.Sensors[0].Status != "no_candidate" {
		t.Fatal(snapshot, err)
	}
}

func TestUpdateValidatesCanonicalPolicyAndOwnsTrustedKeys(t *testing.T) {
	m := f.Generate()
	s, _ := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	pub := append(ed25519.PublicKey(nil), m.Publisher.Public().(ed25519.PublicKey)...)
	recovery := m.Recovery.Public().(ed25519.PublicKey)
	o := update.Options{PublisherKey: pub, RecoveryKey: recovery, Platform: "linux/amd64", MaxSensors: 1, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: func() time.Time { return updateAt }}
	v, err := update.New(context.Background(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	pub[0] ^= 1
	p := f.Metadata(updateAt, 1, "sensor-25", nil, 4)
	for _, raw := range [][]byte{append([]byte(" "), p...), bytes.Replace(p, []byte(`"revision":1`), []byte(`"revision":1,"revision":2`), 1), bytes.Replace(p, []byte(`"platform":"linux/amd64"`), []byte(`"platform":"linux/arm64"`), 1), bytes.Replace(p, []byte(`"revoked_versions":[]`), []byte(`"revoked_versions":[3,3]`), 1)} {
		if _, err := v.Accept(context.Background(), raw, ed25519.Sign(m.Publisher, raw)); !errors.Is(err, update.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	updateAccept(t, v, m, 1, nil, 4)
	p = f.Metadata(updateAt, 1, "other", nil, 4)
	if _, err := v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, storage.ErrQuota) {
		t.Fatal(err)
	}
	for _, change := range []func(*update.Options){func(o *update.Options) { o.RecoveryKey = o.PublisherKey }, func(o *update.Options) { o.PublisherKey = nil }, func(o *update.Options) { o.Platform = "https://example.invalid" }, func(o *update.Options) { o.MaxArtifactBytes = 67108865 }, func(o *update.Options) { o.MaxRecoveryTTL = 2 * time.Hour }, func(o *update.Options) { o.Clock = nil }} {
		invalid := o
		change(&invalid)
		if _, err := update.New(context.Background(), s, invalid); !errors.Is(err, update.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
}

func TestUpdateRollbackRequiresScopedOneTimeRecoveryAndKeepsHighWater(t *testing.T) {
	m := f.Generate()
	s, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	updateAccept(t, v, m, 1, []uint64{3}, 2, 4)
	if _, err := v.Verify(context.Background(), updateRequest(4)); err != nil {
		t.Fatal(err)
	}
	req := updateRequest(2)
	if _, err := v.Verify(context.Background(), req); !errors.Is(err, update.ErrRollback) {
		t.Fatal(err)
	}
	g := f.Grant(updateAt, "recover-25", "sensor-25", 1, 4, 2)
	req = updateRequest(2)
	req.RecoveryPayload = g
	req.RecoverySignature = ed25519.Sign(m.Recovery, g)
	r, err := v.Verify(context.Background(), req)
	if err != nil || r.Version != 2 || r.HighWaterVersion != 4 || !r.Recovery {
		t.Fatal(r, err)
	}
	req.Artifact = bytes.NewReader(f.Artifact(2))
	r2, err := v.Verify(context.Background(), req)
	if err != nil || !r2.Replayed || r2.Receipt != r.Receipt {
		t.Fatal(r2, err)
	}
	if _, err := v.Verify(context.Background(), updateRequest(4)); err != nil {
		t.Fatal(err)
	}
	req.Artifact = bytes.NewReader(f.Artifact(2))
	if _, err := v.Verify(context.Background(), req); !errors.Is(err, update.ErrRecovery) {
		t.Fatal(err)
	}
	records, _ := s.Records(context.Background())
	if len(records) != 4 {
		t.Fatal(len(records))
	}
}

func TestUpdateRejectsInvalidRecoveryScopeSignatureExpiryAndRevokedTarget(t *testing.T) {
	m := f.Generate()
	_, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	updateAccept(t, v, m, 1, []uint64{3}, 2, 4)
	v.Verify(context.Background(), updateRequest(4))
	for _, tc := range []struct {
		name, sensor       string
		revision, from, to uint64
		at                 time.Time
		publisher          bool
	}{
		{"sensor", "other", 1, 4, 2, updateAt, false}, {"revision", "sensor-25", 2, 4, 2, updateAt, false}, {"from", "sensor-25", 1, 9, 2, updateAt, false}, {"to", "sensor-25", 1, 4, 1, updateAt, false}, {"expired", "sensor-25", 1, 4, 2, updateAt.Add(-10 * time.Minute), false}, {"future", "sensor-25", 1, 4, 2, updateAt.Add(time.Second), false}, {"role", "sensor-25", 1, 4, 2, updateAt, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := f.Grant(tc.at, "grant-"+tc.name, tc.sensor, tc.revision, tc.from, tc.to)
			key := m.Recovery
			if tc.publisher {
				key = m.Publisher
			}
			req := updateRequest(2)
			req.RecoveryPayload = g
			req.RecoverySignature = ed25519.Sign(key, g)
			if _, err := v.Verify(context.Background(), req); !errors.Is(err, update.ErrRecovery) {
				t.Fatal(err)
			}
		})
	}
	g := f.Grant(updateAt, "revoked", "sensor-25", 1, 4, 3)
	req := updateRequest(3)
	req.RecoveryPayload = g
	req.RecoverySignature = ed25519.Sign(m.Recovery, g)
	if _, err := v.Verify(context.Background(), req); !errors.Is(err, update.ErrRevoked) {
		t.Fatal(err)
	}
}

func TestUpdateConcurrentAcceptanceAndVerificationDoNotDuplicate(t *testing.T) {
	m := f.Generate()
	s, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	p := f.Metadata(updateAt, 1, "sensor-25", nil, 4)
	sig := ed25519.Sign(m.Publisher, p)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Accept(context.Background(), p, sig); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), updateRequest(4)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	records, _ := s.Records(context.Background())
	if len(records) != 2 {
		t.Fatal(len(records))
	}
}

func TestUpdateBoundsCancellationFixturesAndNoEgress(t *testing.T) {
	for _, name := range []string{"positive", "negative", "expected-output"} {
		raw, err := os.ReadFile(filepath.Join("fixtures/miragemesh/C25", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil || v["schema_version"] != "1" {
			t.Fatal(name)
		}
	}
	m := f.Generate()
	s, v := updateOpen(t, filepath.Join(t.TempDir(), "state"), m, func() time.Time { return updateAt })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := f.Metadata(updateAt, 1, "sensor-25", nil, 4)
	if _, err := v.Accept(ctx, p, ed25519.Sign(m.Publisher, p)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), update.Request{}); !errors.Is(err, update.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, err := update.New(context.Background(), nil, update.Options{}); !errors.Is(err, update.ErrInvalidInput) {
		t.Fatal(err)
	}
	records, _ := s.Records(context.Background())
	if len(records) != 0 {
		t.Fatal(len(records))
	}
	entries, err := os.ReadDir("../internal/update")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join("../internal/update", entry.Name()))
		for _, name := range []string{`"net"`, `"net/http"`, `"os/exec"`} {
			if bytes.Contains(raw, []byte(name)) {
				t.Fatal("update verifier has egress capability", name)
			}
		}
	}
}
