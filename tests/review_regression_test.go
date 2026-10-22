package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func reviewEvent(t *testing.T, sensorID, eventID string) []byte {
	t.Helper()
	raw, err := json.Marshal(contracts.Event{SchemaVersion: "1", SensorID: sensorID, EventID: eventID, Sequence: 1, ObservedAt: "2026-10-22T00:00:00Z", Kind: "http.request", Metadata: contracts.HTTPMetadata{Path: "/"}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestReviewAcceptedPrettyEventMustProject(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(filepath.Join(t.TempDir(), "store"), storage.Limits{MaxOperations: 10, MaxBytes: 1 << 20, MaxManifestBytes: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var pretty interface{}
	json.Unmarshal(reviewEvent(t, "sensor-a", "event-a"), &pretty)
	raw, _ := json.MarshalIndent(pretty, "", "  ")
	if _, err := sensor.Accept(ctx, store, raw); err != nil {
		t.Fatal("accept", err)
	}
	records, err := store.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "segments")
	writer, err := events.Open(directory, events.Limits{MaxSegments: 10, MaxRecordsPerSegment: 10, MaxBytesPerSegment: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	result, err := writer.AppendRecords(ctx, records)
	t.Logf("durably accepted pretty JSON: projection=%+v error=%v", result, err)
	if err != nil {
		t.Fatal("C04/C07 accepted event cannot be projected", err)
	}
	sum := sha256.Sum256(raw)
	index, _ := writer.Index()
	entry, ok := index.Lookup("sensor-a", "event-a")
	if !ok || entry.Digest != hex.EncodeToString(sum[:]) || entry.Bytes != int64(len(raw)) {
		t.Fatal("lost exact payload identity", entry)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(directory, events.Limits{MaxSegments: 10, MaxRecordsPerSegment: 10, MaxBytesPerSegment: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rebuilt, _ := reopened.Index()
	got, _ := rebuilt.Lookup("sensor-a", "event-a")
	if got != entry {
		t.Fatal("rebuild changed event identity", got, entry)
	}
	again, err := reopened.AppendRecords(ctx, records)
	if err != nil || again.Appended != 0 || again.AlreadyProjected != 1 {
		t.Fatal("replay", again, err)
	}
	encoded, err := os.ReadFile(filepath.Join(directory, "segment-00000000000000000001.jsonl"))
	if err != nil || bytes.Count(encoded, []byte{'\n'}) != 1 {
		t.Fatal("not one framed record", err)
	}
}
func TestReviewDistinctIdentityTuplesMustNotCollide(t *testing.T) {
	writer, err := events.Open(filepath.Join(t.TempDir(), "segments"), events.Limits{MaxSegments: 10, MaxRecordsPerSegment: 10, MaxBytesPerSegment: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, identity := range [][2]string{{"a", "b\x00c"}, {"a\x00b", "c"}} {
		raw := reviewEvent(t, identity[0], identity[1])
		if _, failure := contracts.DecodeEvent(context.Background(), raw); failure != nil {
			t.Fatal("invalid fixture", failure)
		}
		_, err := writer.Append(context.Background(), raw)
		t.Logf("identity=%q error=%v", identity, err)
		if err != nil {
			t.Fatal("two valid independent identities collided", err)
		}
	}
}

type reviewProvider struct{ stopped string }

func (p *reviewProvider) Inspect(context.Context, string) (decoy.Runtime, error) {
	return decoy.Runtime{ID: "unrelated-container", State: decoy.StateRunning}, nil
}
func (p *reviewProvider) Stop(_ context.Context, id string) error { p.stopped = id; return nil }
func (p *reviewProvider) Start(context.Context, string, decoy.Policy) (decoy.Container, error) {
	return decoy.Container{}, errors.New("stop probe after reconciliation")
}
func (p *reviewProvider) Exec(context.Context, string, []string) (decoy.ExecResult, error) {
	return decoy.ExecResult{}, nil
}
func TestReviewReconcileMustPreserveUnownedContainer(t *testing.T) {
	provider := &reviewProvider{}
	policy := decoy.Policy{Image: "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Command: []string{"/usr/local/bin/decoy"}, Mounts: []decoy.Mount{{Source: "/tmp/artifact", Target: decoy.ArtifactTarget, Role: decoy.MountArtifact, ReadOnly: true}, {Source: "/tmp/state", Target: decoy.StateTarget, Role: decoy.MountState}}, MemoryBytes: 67108864, PidsLimit: 32, User: "1000:1000", Egress: decoy.EgressDenied}
	supervisor, err := decoy.NewSupervisor(provider, policy, "miragemesh-decoy")
	if err != nil {
		t.Fatal(err)
	}
	_, err = supervisor.Start(context.Background())
	t.Logf("start error=%v stopped=%q", err, provider.stopped)
	if provider.stopped != "" {
		t.Fatal("removed container without ownership evidence", provider.stopped)
	}
}

func TestAlertsKeepOpaqueIdentityPairsDistinct(t *testing.T) {
	sources := []alerts.Source{}
	for n, pair := range [][2]string{{"a", "b\x00c"}, {"a\x00b", "c"}} {
		raw := reviewEvent(t, pair[0], pair[1])
		sum := sha256.Sum256(raw)
		sources = append(sources, alerts.Source{Raw: raw, Ref: events.Entry{SensorID: pair[0], EventID: pair[1], Sequence: 1, Segment: "segment-00000000000000000001", Record: int64(n + 1), Digest: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))}})
	}
	out, err := alerts.Evaluate(context.Background(), sources, nil, alerts.Policy{RateLimit: 2, Window: time.Second}, true)
	if err != nil || len(out.Interactions) != 2 {
		t.Fatalf("independent identities: %+v %v", out, err)
	}
}

func TestMultilineFrameQuotaAndIncompleteRecovery(t *testing.T) {
	raw := append([]byte{'\n'}, reviewEvent(t, "sensor-a", "event-large")...)
	raw = append(raw, bytes.Repeat([]byte{' '}, contracts.MaxInputBytes-len(raw))...)
	directory := filepath.Join(t.TempDir(), "segments")
	limits := events.Limits{MaxSegments: 4, MaxRecordsPerSegment: 2, MaxBytesPerSegment: contracts.MaxInputBytes + 1}
	writer, err := events.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Append(context.Background(), raw); !errors.Is(err, events.ErrQuota) {
		t.Fatalf("encoded quota: %v", err)
	}
	segments, _ := writer.Segments()
	if len(segments) != 0 {
		t.Fatal("quota rejection created a segment")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	limits.MaxBytesPerSegment = 32768
	writer, err = events.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Append(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "segment-00000000000000000001.jsonl")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Model a process dying after part of a second encoded frame was written.
	tail := committed[:9000]
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(tail); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	index, err := reopened.Index()
	if err != nil {
		t.Fatal(err)
	}
	if index.Records != 1 || index.Complete || len(index.Incomplete) != 1 || index.Incomplete[0].Incomplete.Bytes != int64(len(tail)) {
		t.Fatalf("torn frame status: %+v", index)
	}
	preserved, err := os.ReadFile(filepath.Join(directory, "segment-00000000000000000001.incomplete.jsonl"))
	if err != nil || !bytes.Equal(preserved, append(append([]byte{}, committed...), tail...)) {
		t.Fatal("recovery changed encoded evidence", err)
	}
}

func TestSegmentPreservesValidTrailingWhitespace(t *testing.T) {
	// This C04-valid case used to be listed incorrectly as a negative C17 fixture.
	raw := append(reviewEvent(t, "sensor-a", "event-whitespace"), '\n', '\n')
	if _, failure := contracts.DecodeEvent(context.Background(), raw); failure != nil {
		t.Fatal(failure)
	}
	directory := filepath.Join(t.TempDir(), "segments")
	limits := events.Limits{MaxSegments: 2, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 16384}
	writer, err := events.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := writer.Append(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw[:len(raw)-1])
	if ref.Digest != hex.EncodeToString(sum[:]) || ref.Bytes != int64(len(raw)-1) {
		t.Fatal("normalization removed more than the one framing LF", ref)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	index, err := reopened.Index()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := index.Lookup("sensor-a", "event-whitespace")
	if !ok || entry.Digest != ref.Digest {
		t.Fatal("rebuild lost trailing whitespace", entry)
	}
}
