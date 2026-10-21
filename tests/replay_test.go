package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c16Batch struct {
	BatchID       string `json:"batch_id"`
	FirstSequence int64  `json:"first_sequence"`
	LastSequence  int64  `json:"last_sequence"`
	EventIndexes  []int  `json:"event_indexes"`
}

type c16Fixture struct {
	c10Positive
	StorageLimits storage.Limits      `json:"storage_limits"`
	QuotaLimits   storage.Limits      `json:"quota_limits"`
	Events        []string            `json:"events"`
	Batches       map[string]c16Batch `json:"batches"`
}

type c16Expected struct {
	FixtureVersion   int      `json:"fixture_version"`
	License          string   `json:"license"`
	Provenance       string   `json:"provenance"`
	BatchID          string   `json:"batch_id"`
	Acknowledged     []int64  `json:"acknowledged_sequences"`
	AckOperationIDs  []string `json:"ack_operation_ids"`
	ResumeSequences  []int64  `json:"resume_sequences_after_ack"`
	EventBatchLimit  int      `json:"event_batch_limit"`
	SpoolLimitEvents int      `json:"spool_limit_events"`
}

type c16InvalidCase struct {
	Name              string `json:"name"`
	BatchID           string `json:"batch_id"`
	FirstSequence     int64  `json:"first_sequence"`
	LastSequence      int64  `json:"last_sequence"`
	EventIndexes      []int  `json:"event_indexes"`
	PriorEventIndexes []int  `json:"prior_event_indexes"`
	RawEvent          string `json:"raw_event"`
	RawEventBuild     string `json:"raw_event_build"`
	ExpectedError     string `json:"expected_error"`
	ExpectedIs        string `json:"expected_is"`
}

type c16Invalid struct {
	FixtureVersion int              `json:"fixture_version"`
	License        string           `json:"license"`
	Provenance     string           `json:"provenance"`
	SensorID       string           `json:"sensor_id"`
	Cases          []c16InvalidCase `json:"cases"`
}

type c16RecordCounts struct {
	config     int
	event      int
	ack        int
	gap        int
	enrollment int
}

func c16Files(t *testing.T) (c16Fixture, c16Expected, c16Invalid) {
	t.Helper()
	var positive c16Fixture
	var expected c16Expected
	var invalid c16Invalid
	for name, target := range map[string]any{"positive": &positive, "expected-output": &expected, "invalid": &invalid} {
		raw, err := os.ReadFile("fixtures/miragemesh/C16/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C16 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || expected.FixtureVersion != 1 || invalid.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || expected.License != "Apache-2.0" || invalid.License != "Apache-2.0" ||
		positive.Provenance == "" || expected.Provenance == "" || invalid.Provenance == "" ||
		len(positive.Events) != 8 || len(positive.Batches) != 3 ||
		positive.QuotaLimits.MaxOperations != 2 ||
		positive.StorageLimits.MaxOperations < 16 ||
		expected.BatchID != positive.Batches["first"].BatchID ||
		len(expected.Acknowledged) != 2 || len(expected.AckOperationIDs) != 2 ||
		len(expected.ResumeSequences) != 2 || expected.EventBatchLimit != 2 || expected.SpoolLimitEvents != 2 ||
		len(invalid.Cases) == 0 || invalid.SensorID != positive.SensorID {
		t.Fatal("invalid C16 fixture metadata")
	}
	return positive, expected, invalid
}

func c16Ingestor(t *testing.T, s *storage.Store, a *sensor.Applier) *collector.Ingestor {
	t.Helper()
	ing, err := collector.New(s, a)
	if err != nil {
		t.Fatal(err)
	}
	return ing
}

func (f c16Fixture) batch(t *testing.T, name string) collector.Batch {
	t.Helper()
	shape, ok := f.Batches[name]
	if !ok {
		t.Fatalf("missing C16 batch %q", name)
	}
	batch := collector.Batch{ID: shape.BatchID, FirstSequence: shape.FirstSequence, LastSequence: shape.LastSequence}
	for _, index := range shape.EventIndexes {
		if index < 0 || index >= len(f.Events) {
			t.Fatalf("invalid event index %d", index)
		}
		batch.Events = append(batch.Events, []byte(f.Events[index]))
	}
	return batch
}

func c16Counts(t *testing.T, s *storage.Store) c16RecordCounts {
	t.Helper()
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var counts c16RecordCounts
	for _, record := range records {
		switch {
		case record.Config != nil:
			counts.config++
		case record.Enrollment != nil:
			counts.enrollment++
		case record.Gap != nil:
			counts.gap++
		case record.Ack != nil:
			counts.ack++
		case record.Event.SchemaVersion != "":
			counts.event++
		default:
			t.Fatalf("unclassified record %+v", record.Receipt)
		}
	}
	return counts
}

func c16Ack(t *testing.T, s *storage.Store, operationID string) contracts.SpoolAckRecord {
	t.Helper()
	record, err := s.Read(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Ack == nil {
		t.Fatalf("%s is not an acknowledgement", operationID)
	}
	return *record.Ack
}

func c16OversizedEvent() []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"1","sensor_id":"sensor-01","event_id":"event-large","sequence":1,"observed_at":"2026-01-01T00:00:00Z","kind":"http.request","metadata":{"path":"%s"}}`, strings.Repeat("a", contracts.MaxInputBytes)))
}

func TestCollectorDurableBatchAcknowledgementSurvivesRestart(t *testing.T) {
	f, expected, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	receipts := make([]storage.Receipt, 2)
	for i := range receipts {
		var err error
		receipts[i], err = q.Enqueue(context.Background(), []byte(f.Events[i]))
		if err != nil {
			t.Fatal(err)
		}
	}
	ing := c16Ingestor(t, s, a)
	result, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if result.BatchID != expected.BatchID || result.FirstSequence != 1 || result.LastSequence != 2 || len(result.Events) != 2 {
		t.Fatalf("unexpected acknowledgement: %+v", result)
	}
	for i, event := range result.Events {
		if event.Sequence != expected.Acknowledged[i] || event.EventReceipt != receipts[i] ||
			event.AckReceipt.OperationID != expected.AckOperationIDs[i] {
			t.Fatalf("acknowledgement %d: %+v", i, event)
		}
		ack := c16Ack(t, s, expected.AckOperationIDs[i])
		if ack.SensorID != f.SensorID || ack.Sequence != expected.Acknowledged[i] ||
			ack.EventID != event.EventID || ack.InputDigest != event.EventReceipt.InputDigest {
			t.Fatalf("durable ack %d: %+v", i, ack)
		}
		encoded, err := json.Marshal(ack)
		if err != nil {
			t.Fatal(err)
		}
		record, err := s.Read(context.Background(), expected.AckOperationIDs[i])
		if err != nil || !bytes.Equal(record.Input, encoded) {
			t.Fatalf("ack bytes %d: %+v %v", i, record.Receipt, err)
		}
	}
	if counts := c16Counts(t, s); counts.config != 1 || counts.event != 2 || counts.ack != 2 {
		t.Fatalf("initial records: %+v", counts)
	}

	before := c14Manifest(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	a = c11Applier(t, s, v)
	ing = c16Ingestor(t, s, a)
	replay, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Events) != len(result.Events) {
		t.Fatalf("replayed events: %+v", replay.Events)
	}
	for i := range result.Events {
		if replay.Events[i] != result.Events[i] {
			t.Fatalf("replayed receipt %d changed: %+v != %+v", i, replay.Events[i], result.Events[i])
		}
	}
	if !bytes.Equal(before, c14Manifest(t, path)) {
		t.Fatal("lost-ack replay changed the manifest")
	}
	if counts := c16Counts(t, s); counts.config != 1 || counts.event != 2 || counts.ack != 2 {
		t.Fatalf("replayed records: %+v", counts)
	}
}

func TestCollectorLostAcknowledgementReplayIsIdempotent(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	ing := c16Ingestor(t, s, a)
	first, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the caller losing the acknowledgement and restarting before it
	// can act on the result. The durable records are the only evidence retained.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	a = c11Applier(t, s, v)
	ing = c16Ingestor(t, s, a)
	second, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || len(second.Events) != 2 {
		t.Fatalf("unexpected event acknowledgements: %+v %+v", first, second)
	}
	for i := range first.Events {
		if second.Events[i] != first.Events[i] {
			t.Fatalf("lost-ack replay changed receipt %d", i)
		}
	}
	if counts := c16Counts(t, s); counts.event != 2 || counts.ack != 2 {
		t.Fatalf("lost-ack replay duplicated records: %+v", counts)
	}
}

func TestCollectorAcknowledgementReclaimsSpoolCapacity(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	q := c14Spool(t, s, a)
	for i := 0; i < 2; i++ {
		if _, err := q.Enqueue(context.Background(), []byte(f.Events[i])); err != nil {
			t.Fatal(err)
		}
	}
	ing := c16Ingestor(t, s, a)
	if _, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first")); err != nil {
		t.Fatal(err)
	}
	for i := 2; i < 4; i++ {
		if _, err := q.Enqueue(context.Background(), []byte(f.Events[i])); err != nil {
			t.Fatalf("capacity was not reclaimed by acknowledgement: %v", err)
		}
	}
	loss, err := q.Losses(context.Background(), f.SensorID)
	if err != nil || loss.Count != 0 {
		t.Fatalf("unexpected loss after acknowledgement: %+v %v", loss, err)
	}
	if _, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "second")); err != nil {
		t.Fatal(err)
	}
	if counts := c16Counts(t, s); counts.event != 4 || counts.ack != 4 || counts.gap != 0 {
		t.Fatalf("records after reclamation: %+v", counts)
	}
}

func TestCollectorRejectsForgedAndOrphanedAcknowledgements(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	cases := []struct {
		name   string
		setup  func(*storage.Store, *spool.Store) error
		ingest collector.Batch
	}{
		{
			name: "forged_digest",
			setup: func(s *storage.Store, q *spool.Store) error {
				if _, err := q.Enqueue(context.Background(), []byte(f.Events[0])); err != nil {
					return err
				}
				if _, err := q.Enqueue(context.Background(), []byte(f.Events[1])); err != nil {
					return err
				}
				fake := contracts.SpoolAckRecord{SchemaVersion: contracts.SchemaVersion, Kind: contracts.SpoolAck, SensorID: f.SensorID, EventID: "event-01", Sequence: 1, InputDigest: strings.Repeat("0", 64)}
				raw, _ := json.Marshal(fake)
				_, err := s.Commit(context.Background(), sensor.AckOperationID(f.SensorID, 1), raw)
				return err
			},
			ingest: f.batch(t, "first"),
		},
		{
			name: "orphaned_ack",
			setup: func(s *storage.Store, q *spool.Store) error {
				fake := contracts.SpoolAckRecord{SchemaVersion: contracts.SchemaVersion, Kind: contracts.SpoolAck, SensorID: f.SensorID, EventID: "event-01", Sequence: 1, InputDigest: strings.Repeat("a", 64)}
				raw, _ := json.Marshal(fake)
				_, err := s.Commit(context.Background(), sensor.AckOperationID(f.SensorID, 1), raw)
				return err
			},
			ingest: collector.Batch{ID: "batch-orphan", FirstSequence: 1, LastSequence: 1, Events: [][]byte{[]byte(f.Events[0])}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := storePath(t)
			s := openStore(t, path, f.StorageLimits)
			a := c11Applier(t, s, v)
			c11Apply(t, a, key, f.Payloads["initial"])
			q := c14Spool(t, s, a)
			if err := tc.setup(s, q); err != nil {
				t.Fatal(err)
			}
			before := c14Manifest(t, path)
			ing := c16Ingestor(t, s, a)
			if _, err := ing.Ingest(context.Background(), f.SensorID, tc.ingest); !errors.Is(err, storage.ErrRecovery) {
				t.Fatalf("forged state: %v", err)
			}
			if !bytes.Equal(before, c14Manifest(t, path)) {
				t.Fatal("forged state changed the manifest")
			}
			_, err := q.Enqueue(context.Background(), []byte(f.Events[2]))
			if !errors.Is(err, storage.ErrRecovery) {
				t.Fatalf("forged state reclaimed capacity: %v", err)
			}
		})
	}
}

func TestCollectorRejectsInvalidBatchesBeforeCommit(t *testing.T) {
	f, _, invalid := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	verdicts := map[string]error{
		"invalid_batch":   collector.ErrInvalidBatch,
		"batch_too_large": collector.ErrBatchTooLarge,
		"invalid_event":   sensor.ErrInvalidEvent,
		"sensor_mismatch": collector.ErrSensorMismatch,
		"out_of_order":    sensor.ErrOutOfOrder,
		"conflict":        storage.ErrConflict,
	}
	for _, tc := range invalid.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			path := storePath(t)
			s := openStore(t, path, f.StorageLimits)
			a := c11Applier(t, s, v)
			c11Apply(t, a, key, f.Payloads["initial"])
			for _, index := range tc.PriorEventIndexes {
				if _, err := sensor.Accept(context.Background(), s, []byte(f.Events[index])); err != nil {
					t.Fatal(err)
				}
			}
			batch := collector.Batch{ID: tc.BatchID, FirstSequence: tc.FirstSequence, LastSequence: tc.LastSequence}
			switch {
			case tc.RawEventBuild == "max+1":
				batch.Events = append(batch.Events, c16OversizedEvent())
			case tc.RawEvent != "":
				batch.Events = append(batch.Events, []byte(tc.RawEvent))
			default:
				for _, index := range tc.EventIndexes {
					batch.Events = append(batch.Events, []byte(f.Events[index]))
				}
			}
			want, ok := verdicts[tc.ExpectedIs]
			if !ok {
				t.Fatalf("unknown verdict %q", tc.ExpectedIs)
			}
			before := c14Manifest(t, path)
			counts := c16Counts(t, s)
			ing := c16Ingestor(t, s, a)
			got, err := ing.Ingest(context.Background(), invalid.SensorID, batch)
			if !errors.Is(err, want) || got.SensorID != "" || got.BatchID != "" || len(got.Events) != 0 {
				t.Fatalf("rejection: %+v %v, want %v", got, err, want)
			}
			if !strings.Contains(err.Error(), tc.ExpectedError) {
				t.Fatalf("error %q does not mention %q", err, tc.ExpectedError)
			}
			if !bytes.Equal(before, c14Manifest(t, path)) || counts != c16Counts(t, s) {
				t.Fatal("invalid batch changed durable state")
			}
		})
	}
}

func TestCollectorRequiresConfigurationAndStorageQuota(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	a := c11Applier(t, s, v)
	if _, err := collector.New(nil, nil); !errors.Is(err, collector.ErrInvalidInput) {
		t.Fatal("missing dependencies accepted")
	}
	if _, err := collector.New(s, nil); !errors.Is(err, collector.ErrInvalidInput) {
		t.Fatal("missing applier accepted")
	}
	other := openStore(t, storePath(t), f.StorageLimits)
	if _, err := collector.New(other, a); !errors.Is(err, collector.ErrInvalidInput) {
		t.Fatal("mismatched applier accepted")
	}
	ing := c16Ingestor(t, s, a)
	before := c14Manifest(t, path)
	if _, err := ing.Ingest(context.Background(), f.SensorID, f.batch(t, "first")); !errors.Is(err, sensor.ErrUnconfigured) {
		t.Fatalf("unconfigured ingest: %v", err)
	}
	if !bytes.Equal(before, c14Manifest(t, path)) {
		t.Fatal("unconfigured ingest changed the manifest")
	}
	var absent *collector.Ingestor
	if _, err := absent.Ingest(context.Background(), f.SensorID, f.batch(t, "first")); !errors.Is(err, collector.ErrInvalidInput) {
		t.Fatal("nil ingestor accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ing.Ingest(ctx, f.SensorID, f.batch(t, "first")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled ingest accepted")
	}

	limitedPath := storePath(t)
	limited := openStore(t, limitedPath, f.QuotaLimits)
	limitedApplier := c11Applier(t, limited, v)
	c11Apply(t, limitedApplier, key, f.Payloads["initial"])
	q := c14Spool(t, limited, limitedApplier)
	if _, err := q.Enqueue(context.Background(), []byte(f.Events[0])); err != nil {
		t.Fatal(err)
	}
	before = c14Manifest(t, limitedPath)
	single := collector.Batch{ID: "batch-quota", FirstSequence: 1, LastSequence: 1, Events: [][]byte{[]byte(f.Events[0])}}
	if _, err := c16Ingestor(t, limited, limitedApplier).Ingest(context.Background(), f.SensorID, single); !errors.Is(err, storage.ErrQuota) {
		t.Fatalf("acknowledgement quota: %v", err)
	}
	if !bytes.Equal(before, c14Manifest(t, limitedPath)) || c16Counts(t, limited).ack != 0 {
		t.Fatal("failed acknowledgement changed the manifest")
	}
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openStore(t, limitedPath, f.StorageLimits)
	reopenedApplier := c11Applier(t, reopened, v)
	result, err := c16Ingestor(t, reopened, reopenedApplier).Ingest(context.Background(), f.SensorID, single)
	if err != nil || len(result.Events) != 1 {
		t.Fatalf("quota retry: %+v %v", result, err)
	}
	if counts := c16Counts(t, reopened); counts.event != 1 || counts.ack != 1 {
		t.Fatalf("quota retry records: %+v", counts)
	}
}

func TestCollectorConcurrentReplayCreatesOneObservation(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	s := openStore(t, storePath(t), f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	ing := c16Ingestor(t, s, a)
	batch := f.batch(t, "first")
	const workers = 8
	results := make(chan collector.Acknowledgement, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := ing.Ingest(context.Background(), f.SensorID, batch)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first *collector.Acknowledgement
	for result := range results {
		if first == nil {
			copy := result
			first = &copy
			continue
		}
		for i := range first.Events {
			if result.Events[i] != first.Events[i] {
				t.Fatalf("concurrent replay changed receipt %d", i)
			}
		}
	}
	if first == nil {
		t.Fatal("no concurrent result")
	}
	if counts := c16Counts(t, s); counts.config != 1 || counts.event != 2 || counts.ack != 2 {
		t.Fatalf("concurrent replay records: %+v", counts)
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			key := fmt.Sprintf("%s/%d", record.Event.SensorID, record.Event.Sequence)
			if seen[key] {
				t.Fatalf("duplicate event observation %s", key)
			}
			seen[key] = true
		}
	}
}

func TestCollectorTreatsPathsAsOpaqueAndHasNoEgress(t *testing.T) {
	f, _, _ := c16Files(t)
	public, key := c10Key(t)
	v := c10Verifier(t, &f.c10Positive, public, f.Bounds)
	root := t.TempDir()
	storeDir := filepath.Join(root, "store")
	s := openStore(t, storeDir, f.StorageLimits)
	a := c11Applier(t, s, v)
	c11Apply(t, a, key, f.Payloads["initial"])
	sentinel := filepath.Join(root, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape-link")
	if err := os.Symlink(sentinel, link); err != nil {
		t.Fatal(err)
	}
	first := []byte(strings.Replace(f.Events[0], "/replay/1", "../../etc/passwd", 1))
	second := []byte(strings.Replace(f.Events[1], "/replay/2", link, 1))
	batch := collector.Batch{ID: "batch-paths", FirstSequence: 1, LastSequence: 2, Events: [][]byte{first, second}}
	if _, err := c16Ingestor(t, s, a).Ingest(context.Background(), f.SensorID, batch); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(sentinel); err != nil || !bytes.Equal(contents, []byte("unchanged")) {
		t.Fatalf("collector touched the sentinel: %q %v", contents, err)
	}
	for i, want := range []string{"../../etc/passwd", link} {
		event, failure := contracts.DecodeEvent(context.Background(), [][]byte{first, second}[i])
		if failure != nil {
			t.Fatal(failure)
		}
		record, err := s.Read(context.Background(), "sensor/"+c16SensorHash(f.SensorID)+"/"+strconv.FormatInt(int64(i+1), 10))
		if err != nil || record.Event.Metadata.Path != want || record.Event.Metadata.Path != event.Metadata.Path {
			t.Fatalf("path was not stored opaquely: %+v %v", record.Event.Metadata, err)
		}
	}
	allowed := map[string]bool{
		"context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true,
		"errors": true, "fmt": true, "unicode/utf8": true,
		"github.com/Parsa-Emami/Miragemesh/internal/config":    true,
		"github.com/Parsa-Emami/Miragemesh/internal/contracts": true,
		"github.com/Parsa-Emami/Miragemesh/internal/sensor":    true,
		"github.com/Parsa-Emami/Miragemesh/internal/storage":   true,
	}
	files, err := filepath.Glob("../internal/collector/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("collector sources: %v", err)
	}
	for _, file := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if !allowed[importPath] {
				t.Fatalf("%s imports %q; collector must remain offline", file, importPath)
			}
		}
	}
}

func c16SensorHash(sensorID string) string {
	sum := sha256.Sum256([]byte(sensorID))
	return hex.EncodeToString(sum[:])
}
