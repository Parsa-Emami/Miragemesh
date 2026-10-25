package acceptance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidentview"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/sensorview"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	c24fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

const (
	WorkflowVersion = "1"
	maxEnvelope     = 262144
)

var ErrInvalidOptions = errors.New("acceptance: invalid workflow options")

type Options struct {
	Directory  string
	FixtureDir string
	Now        func() time.Time
}

type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type SensorState struct {
	SensorID          string `json:"sensor_id"`
	LastEventAt       string `json:"last_event_at,omitempty"`
	Offline           bool   `json:"offline"`
	ConfigStatus      string `json:"config_status"`
	DroppedEventCount uint64 `json:"dropped_event_count"`
}

type SegmentState struct {
	ID      string `json:"id"`
	Records int64  `json:"records"`
	Sealed  bool   `json:"sealed"`
}

type Counts struct {
	Config     int `json:"config"`
	Event      int `json:"event"`
	Ack        int `json:"ack"`
	Gap        int `json:"gap"`
	Enrollment int `json:"enrollment"`
	Rotation   int `json:"rotation"`
	Incident   int `json:"incident"`
}

type WorkflowResult struct {
	EnrolledSensor        string            `json:"enrolled_sensor"`
	AppliedRevision       int64             `json:"applied_revision"`
	AcceptedSequences     []int64           `json:"accepted_sequences"`
	AcknowledgedSequences []int64           `json:"acknowledged_sequences"`
	DroppedSequence       int64             `json:"dropped_sequence"`
	Loss                  spool.LossSummary `json:"loss"`
	Counts                Counts            `json:"counts"`
	Segments              []SegmentState    `json:"segments"`
	SegmentDigests        map[string]string `json:"segment_digests"`
	IncidentCount         int               `json:"incident_count"`
	IncidentID            string            `json:"incident_id"`
	TriageEntries         int               `json:"triage_entries"`
	RetentionEligible     int               `json:"retention_eligible"`
	CoverageComplete      bool              `json:"coverage_complete"`
	Sensor                SensorState       `json:"sensor"`
	ManifestDigest        string            `json:"manifest_digest"`
	Restarted             bool              `json:"restarted"`
	Restored              bool              `json:"restored"`
	RestoreEquivalent     bool              `json:"restore_equivalent"`
}

type NegativeResult struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Passed   bool   `json:"passed"`
}

type Runtime struct {
	StateDir              string         `json:"state_dir"`
	SegmentsDir           string         `json:"segments_dir"`
	PublicKeyFile         string         `json:"public_key_file"`
	IssuerFile            string         `json:"issuer_file"`
	SensorID              string         `json:"sensor_id"`
	StorageLimits         storage.Limits `json:"storage_limits"`
	SegmentLimits         events.Limits  `json:"segment_limits"`
	ConfigMaxSensors      int            `json:"config_max_sensors"`
	Bounds                Bounds         `json:"bounds"`
	Incident              IncidentSpec   `json:"incident"`
	Rotation              RotationSpec   `json:"rotation"`
	ConfigPublicKeySHA256 string         `json:"config_public_key_sha256"`
}

type Outcome struct {
	SchemaVersion string           `json:"schema_version"`
	SensorID      string           `json:"sensor_id"`
	Steps         []Step           `json:"steps"`
	Result        WorkflowResult   `json:"result"`
	Negative      []NegativeResult `json:"negative,omitempty"`
	Runtime       Runtime          `json:"runtime"`
}

type batchEnvelope struct {
	BatchID       string   `json:"batch_id"`
	FirstSequence int64    `json:"first_sequence"`
	LastSequence  int64    `json:"last_sequence"`
	Events        []string `json:"events"`
}

type ackEvent struct {
	EventID  string `json:"event_id"`
	Sequence int64  `json:"sequence"`
}

type ackResponse struct {
	OK            bool       `json:"ok"`
	Error         string     `json:"error,omitempty"`
	FirstSequence int64      `json:"first_sequence"`
	LastSequence  int64      `json:"last_sequence"`
	Events        []ackEvent `json:"events"`
}

// Run executes the positive reference workflow against a new local directory.
// It writes runtime.json and outcome.json for the supported local app.
func Run(ctx context.Context, options Options) (Outcome, error) {
	if ctx == nil || options.Directory == "" || options.FixtureDir == "" {
		return Outcome{}, ErrInvalidOptions
	}
	now := time.Now().UTC().Truncate(time.Second)
	if options.Now != nil {
		now = options.Now().UTC().Truncate(time.Second)
	}
	if now.IsZero() {
		return Outcome{}, ErrInvalidOptions
	}
	fixtures, err := Load(options.FixtureDir)
	if err != nil {
		return Outcome{}, err
	}
	root, err := filepath.Abs(options.Directory)
	if err != nil {
		return Outcome{}, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return Outcome{}, err
	}
	stateDir := filepath.Join(root, "state")
	segmentsDir := filepath.Join(root, "segments")
	if _, err := os.Stat(stateDir); err == nil {
		return Outcome{}, errors.New("acceptance: state directory already exists")
	}
	if _, err := os.Stat(segmentsDir); err == nil {
		return Outcome{}, errors.New("acceptance: segment directory already exists")
	}

	outcome := Outcome{SchemaVersion: WorkflowVersion, SensorID: fixtures.Positive.SensorID}
	fail := func(err error) (Outcome, error) { return outcome, err }
	step := func(name, detail string) {
		outcome.Steps = append(outcome.Steps, Step{Name: name, Status: "passed", Detail: detail})
	}

	store, err := storage.Open(stateDir, fixtures.Positive.StorageLimits)
	if err != nil {
		return fail(err)
	}
	writer, err := events.Open(segmentsDir, fixtures.Positive.SegmentLimits)
	if err != nil {
		store.Close()
		return fail(err)
	}
	closed := false
	closeAll := func() {
		if closed {
			return
		}
		closed = true
		if writer != nil {
			writer.Close()
		}
		if store != nil {
			store.Close()
		}
	}
	defer closeAll()

	// 1. Enroll the sensor through the real C08 token service.
	enrollmentTTL := time.Duration(fixtures.Positive.EnrollmentTTLSecond) * time.Second
	enroller, err := enrollment.New(store, enrollmentTTL, time.Now)
	if err != nil {
		return fail(err)
	}
	token, err := enroller.Issue(ctx, fixtures.Positive.SensorID, enrollmentTTL)
	if err != nil {
		return fail(err)
	}
	if _, err := enroller.Consume(ctx, token.Token, fixtures.Positive.SensorID); err != nil {
		return fail(err)
	}
	if _, err := enroller.Consume(ctx, token.Token, fixtures.Positive.SensorID); !errors.Is(err, enrollment.ErrReplay) {
		return fail(fmt.Errorf("acceptance: enrollment replay: %v", err))
	}
	step("enroll", "sensor-01 enrolled with one durable token consumption; the token replay was rejected")

	// 2. Register one real client identity in the C24 ledger and build the
	// C09 guard used by the TLS ingest harness.
	material := c24fixture.Generate(now, fixtures.Positive.SensorID)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail(err)
	}
	verifier := config.Verifier{
		PublicKey: public, Clock: time.Now, MaxSensors: fixtures.Positive.ConfigMaxSensors,
		Bounds: fixtures.Positive.Bounds.configBounds(),
	}
	applier, err := sensor.NewApplier(ctx, store, verifier)
	if err != nil {
		return fail(err)
	}
	payload, signature, err := desiredState(fixtures, now, private)
	if err != nil {
		return fail(err)
	}
	applied, err := applier.Apply(ctx, payload, signature)
	if err != nil {
		return fail(err)
	}
	if applied.Revision != fixtures.Positive.Config.Revision {
		return fail(fmt.Errorf("acceptance: applied revision %d", applied.Revision))
	}
	publicKeyFile := filepath.Join(root, "sensor-config.pub")
	if err := writePrivate(publicKeyFile, []byte(public)); err != nil {
		return fail(err)
	}
	issuerFile := filepath.Join(root, "issuer.pem")
	if err := writePrivate(issuerFile, []byte(material.Authority)); err != nil {
		return fail(err)
	}
	for name, content := range map[string]string{
		"server.pem": material.Server, "server-key.pem": material.ServerKey,
		"client.pem": material.Initial, "client-key.pem": material.InitialKey,
	} {
		if err := writePrivate(filepath.Join(root, name), []byte(content)); err != nil {
			return fail(err)
		}
	}
	rotator, err := pki.NewRotator(ctx, store, pki.RotationOptions{
		IssuerCertificatePEM: material.Authority, MaxSensors: fixtures.Positive.Rotation.MaxSensors,
		MaxLifetime:    time.Duration(fixtures.Positive.Rotation.MaxLifetimeSeconds) * time.Second,
		MaxOverlap:     time.Duration(fixtures.Positive.Rotation.MaxOverlapSeconds) * time.Second,
		MaxRecoveryTTL: time.Duration(fixtures.Positive.Rotation.MaxRecoveryTTLSeconds) * time.Second,
		Clock:          time.Now,
	})
	if err != nil {
		return fail(err)
	}
	if _, err := rotator.Register(ctx, pki.RegisterCertificate{
		SensorID: fixtures.Positive.SensorID, CertificatePEM: material.Initial, IdempotencyKey: "c30-reference-register-key",
	}); err != nil {
		return fail(err)
	}
	guard, err := pki.New(pki.Options{
		Rotation: rotator, Anchors: []string{material.Authority},
		ServerCertificatePEM: material.Server, ServerKeyPEM: material.ServerKey,
		RevocationListPEM: material.CRL, Scopes: map[string][]string{},
		MaxAnchors: 1, MaxScopes: 1, MaxScopesPerIdentity: 1, Clock: time.Now,
	})
	if err != nil {
		return fail(err)
	}
	server, err := startIngest(guard, store, applier)
	if err != nil {
		return fail(err)
	}
	defer server.Close()
	clientConfig, err := clientTLS(material, now)
	if err != nil {
		return fail(err)
	}
	step("apply-config", "signed desired-state revision 1 is active with its exact payload bytes")

	// 3. Accept event-01 through a real mutually authenticated batch.
	first, err := fixtures.envelope("first", now)
	if err != nil {
		return fail(err)
	}
	if _, err := server.Deliver(ctx, clientConfig, first); err != nil {
		return fail(fmt.Errorf("acceptance: first batch: %w", err))
	}
	step("event-01", "event-01 was authenticated, batch-ingested and durably acknowledged")

	// 4. Go offline: retain bounded events, then report one explicit loss.
	queue, err := spool.New(store, applier)
	if err != nil {
		return fail(err)
	}
	for _, index := range fixtures.Positive.OfflineEventIndexes {
		raw, err := fixtures.eventBytes(index, now)
		if err != nil {
			return fail(err)
		}
		if _, err := queue.Enqueue(ctx, raw); err != nil {
			return fail(err)
		}
	}
	step("disconnect", "the bounded offline spool retained event-02 and event-03")

	overflow, err := fixtures.eventBytes(fixtures.Positive.OverflowEventIndex, now)
	if err != nil {
		return fail(err)
	}
	manifestBefore, err := manifestDigest(stateDir)
	if err != nil {
		return fail(err)
	}
	if _, err := queue.Enqueue(ctx, overflow); !errors.Is(err, spool.ErrDropped) {
		return fail(fmt.Errorf("acceptance: overflow: %v", err))
	}
	manifestAfterDrop, err := manifestDigest(stateDir)
	if err != nil {
		return fail(err)
	}
	if manifestBefore == manifestAfterDrop {
		return fail(errors.New("acceptance: overflow did not record a durable gap"))
	}
	if _, err := queue.Enqueue(ctx, overflow); !errors.Is(err, spool.ErrDropped) {
		return fail(errors.New("acceptance: an exact overflow retry changed its outcome"))
	}
	if after, err := manifestDigest(stateDir); err != nil || after != manifestAfterDrop {
		return fail(errors.New("acceptance: an exact overflow retry published a second gap"))
	}
	loss, err := queue.Losses(ctx, fixtures.Positive.SensorID)
	if err != nil {
		return fail(err)
	}
	if loss.Count != 1 || len(loss.Gaps) != 1 || loss.Gaps[0] != (spool.GapRange{From: 4, Through: 4}) {
		return fail(fmt.Errorf("acceptance: loss summary %+v", loss))
	}
	step("spool", "event-04 overflowed the signed spool bound and is recorded as explicit durable loss")

	// 5. Reconnect, repeat the acknowledgement, then continue after the gap.
	reconnect, err := fixtures.envelope("reconnect", now)
	if err != nil {
		return fail(err)
	}
	reconnectAck, err := server.Deliver(ctx, clientConfig, reconnect)
	if err != nil {
		return fail(fmt.Errorf("acceptance: reconnect batch: %w", err))
	}
	duplicate, err := fixtures.envelope("duplicate", now)
	if err != nil {
		return fail(err)
	}
	duplicateAck, err := server.Deliver(ctx, clientConfig, duplicate)
	if err != nil {
		return fail(fmt.Errorf("acceptance: duplicate batch: %w", err))
	}
	if !sameAck(reconnectAck, duplicateAck) {
		return fail(errors.New("acceptance: the repeated acknowledgement changed its receipts"))
	}
	resumedIndex := -1
	for i := range fixtures.Positive.Events {
		if i != fixtures.Positive.OverflowEventIndex && i > 0 && i != fixtures.Positive.OfflineEventIndexes[0] && i != fixtures.Positive.OfflineEventIndexes[1] {
			resumedIndex = i
		}
	}
	if resumedIndex < 0 {
		return fail(ErrFixture)
	}
	resumedRaw, err := fixtures.eventBytes(resumedIndex, now)
	if err != nil {
		return fail(err)
	}
	if _, err := queue.Enqueue(ctx, resumedRaw); err != nil {
		return fail(fmt.Errorf("acceptance: resumed enqueue: %w", err))
	}
	resumed, err := fixtures.envelope("resumed", now)
	if err != nil {
		return fail(err)
	}
	if _, err := server.Deliver(ctx, clientConfig, resumed); err != nil {
		return fail(fmt.Errorf("acceptance: resumed batch: %w", err))
	}
	records, err := store.Records(ctx)
	if err != nil {
		return fail(err)
	}
	counts := countRecords(records)
	accepted, acknowledged := eventSequences(records)
	if !equalSequences(accepted, []int64{1, 2, 3, 5}) || !equalSequences(acknowledged, []int64{1, 2, 3, 5}) {
		return fail(fmt.Errorf("acceptance: delivered sequences events=%v acks=%v", accepted, acknowledged))
	}
	if counts.Event != 4 || counts.Ack != 4 || counts.Gap != 1 || counts.Config != 1 {
		return fail(fmt.Errorf("acceptance: durable counts %+v", counts))
	}
	step("reconnect", "the repeated batch acknowledgement was idempotent and delivery resumed after the explicit gap")

	// 6. Project immutable segments and derive the incident view.
	projection, err := writer.AppendRecords(ctx, records)
	if err != nil {
		return fail(err)
	}
	if projection.Appended != 4 || projection.Skipped == 0 {
		return fail(fmt.Errorf("acceptance: segment projection %+v", projection))
	}
	segmentStates, err := segmentStates(writer)
	if err != nil {
		return fail(err)
	}
	if len(segmentStates) != 2 || segmentStates[0].Records != 2 || !segmentStates[0].Sealed {
		return fail(fmt.Errorf("acceptance: segment state %+v", segmentStates))
	}
	view, err := incidentview.NewView(ctx, store, writer, alerts.Policy{
		RateLimit: fixtures.Positive.Incident.RateLimit,
		Window:    time.Duration(fixtures.Positive.Incident.WindowSeconds) * time.Second,
	})
	if err != nil {
		return fail(err)
	}
	snapshot, err := view.Snapshot(ctx)
	if err != nil {
		return fail(err)
	}
	if len(snapshot.Incidents) < fixtures.Expected.IncidentsMin || !snapshot.Coverage.Complete {
		return fail(fmt.Errorf("acceptance: incident snapshot incidents=%d coverage=%v", len(snapshot.Incidents), snapshot.Coverage))
	}
	incidentID := snapshot.Incidents[0].ID
	body, err := json.Marshal(map[string]string{"status": fixtures.Positive.Triage.Status, "reason": fixtures.Positive.Triage.Reason})
	if err != nil {
		return fail(err)
	}
	if _, err := view.Triage(ctx, incidentID, fixtures.Positive.Triage.IdempotencyKey, body); err != nil {
		return fail(err)
	}
	replayed, err := view.Triage(ctx, incidentID, fixtures.Positive.Triage.IdempotencyKey, body)
	if err != nil || !replayed.Replayed {
		return fail(fmt.Errorf("acceptance: triage replay %+v %v", replayed, err))
	}
	afterTriage, err := view.Snapshot(ctx)
	if err != nil {
		return fail(err)
	}
	triageEntries := historyLength(afterTriage, incidentID)
	if triageEntries != fixtures.Expected.TriageEntries {
		return fail(fmt.Errorf("acceptance: triage history %d", triageEntries))
	}
	retention, err := writer.PlanRetention(ctx, events.RetentionRequest{
		Before: now.Add(time.Duration(fixtures.Positive.Retention.CutoffOffsetSeconds) * time.Second),
		Reason: fixtures.Positive.Retention.Reason, IdempotencyKey: "c30-retention-preview-key",
	})
	if err != nil {
		return fail(err)
	}
	if len(retention.Segments) != fixtures.Expected.Retention.Eligible || retention.Applied {
		return fail(fmt.Errorf("acceptance: retention preview %+v", retention))
	}
	sensorSnapshot, err := sensorview.BuildSnapshot(ctx, store, applier, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	sensorState, err := selectSensor(sensorSnapshot, fixtures.Positive.SensorID)
	if err != nil {
		return fail(err)
	}
	if sensorState.ConfigStatus != fixtures.Expected.Sensor.ConfigStatus || sensorState.DroppedEventCount != fixtures.Expected.Sensor.DroppedEventCount || sensorState.Offline != fixtures.Expected.Sensor.Offline {
		return fail(fmt.Errorf("acceptance: sensor snapshot %+v", sensorState))
	}
	step("triage-retention", "triage is durable and idempotent; the non-destructive retention preview is explicit and coverage is complete")

	// 7. Restart the real store and segment writer, then restore from a copy.
	// Re-read the durable ledger after triage so the restart comparison covers
	// every accepted operation, including the triage record it just wrote.
	records, err = store.Records(ctx)
	if err != nil {
		return fail(err)
	}
	countsBefore := countRecords(records)
	acceptedBefore, acknowledgedBefore := eventSequences(records)
	if !equalSequences(acceptedBefore, accepted) || !equalSequences(acknowledgedBefore, acknowledged) {
		return fail(errors.New("acceptance: triage changed the delivered event ledger"))
	}
	segmentsBefore := segmentStates
	digestsBefore, err := segmentDigests(segmentsDir)
	if err != nil {
		return fail(err)
	}
	manifestBeforeRestart, err := manifestDigest(stateDir)
	if err != nil {
		return fail(err)
	}
	server.Close()
	if err := writer.Close(); err != nil {
		return fail(err)
	}
	if err := store.Close(); err != nil {
		return fail(err)
	}
	closed = true

	restoreRoot := filepath.Join(root, "restore")
	if err := copyTree(stateDir, filepath.Join(restoreRoot, "state")); err != nil {
		return fail(err)
	}
	if err := copyTree(segmentsDir, filepath.Join(restoreRoot, "segments")); err != nil {
		return fail(err)
	}

	store, err = storage.Open(stateDir, fixtures.Positive.StorageLimits)
	if err != nil {
		return fail(err)
	}
	writer, err = events.Open(segmentsDir, fixtures.Positive.SegmentLimits)
	if err != nil {
		return fail(err)
	}
	closed = false
	applier, err = sensor.NewApplier(ctx, store, verifier)
	if err != nil {
		return fail(err)
	}
	view, err = incidentview.NewView(ctx, store, writer, alerts.Policy{
		RateLimit: fixtures.Positive.Incident.RateLimit,
		Window:    time.Duration(fixtures.Positive.Incident.WindowSeconds) * time.Second,
	})
	if err != nil {
		return fail(err)
	}
	restartFacts, err := inspect(ctx, store, writer, applier, view, fixtures.Positive.SensorID, incidentID, stateDir, segmentsDir)
	if err != nil {
		return fail(err)
	}
	if !equalSequences(restartFacts.accepted, acceptedBefore) || !equalSequences(restartFacts.acknowledged, acknowledgedBefore) ||
		restartFacts.counts != countsBefore || !equalSegments(restartFacts.segments, segmentsBefore) ||
		!equalDigests(restartFacts.digests, digestsBefore) || restartFacts.manifestDigest != manifestBeforeRestart ||
		restartFacts.triageEntries != triageEntries || !restartFacts.coverage || !sameLoss(restartFacts.loss, loss) {

		return fail(fmt.Errorf("acceptance: restart changed the accepted state: accepted=%v/%v acknowledged=%v/%v counts=%+v/%+v segments=%+v/%+v digests=%v manifest=%s/%s triage=%d/%d coverage=%v loss=%+v/%+v",
			restartFacts.accepted, acceptedBefore, restartFacts.acknowledged, acknowledgedBefore,
			restartFacts.counts, countsBefore, restartFacts.segments, segmentsBefore,
			equalDigests(restartFacts.digests, digestsBefore), restartFacts.manifestDigest, manifestBeforeRestart,
			restartFacts.triageEntries, triageEntries, restartFacts.coverage, restartFacts.loss, loss))
	}
	if _, err := writer.PlanRetention(ctx, events.RetentionRequest{
		Before: now.Add(time.Duration(fixtures.Positive.Retention.CutoffOffsetSeconds) * time.Second),
		Reason: fixtures.Positive.Retention.Reason, IdempotencyKey: "c30-retention-preview-key",
	}); err != nil {
		return fail(err)
	}
	if err := store.Close(); err != nil {
		return fail(err)
	}
	if err := writer.Close(); err != nil {
		return fail(err)
	}
	closed = true

	restoreStore, err := storage.Open(filepath.Join(restoreRoot, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return fail(err)
	}
	defer restoreStore.Close()
	restoreWriter, err := events.Open(filepath.Join(restoreRoot, "segments"), fixtures.Positive.SegmentLimits)
	if err != nil {
		return fail(err)
	}
	defer restoreWriter.Close()
	restoreApplier, err := sensor.NewApplier(ctx, restoreStore, verifier)
	if err != nil {
		return fail(err)
	}
	restoreView, err := incidentview.NewView(ctx, restoreStore, restoreWriter, alerts.Policy{
		RateLimit: fixtures.Positive.Incident.RateLimit,
		Window:    time.Duration(fixtures.Positive.Incident.WindowSeconds) * time.Second,
	})
	if err != nil {
		return fail(err)
	}
	restoreFacts, err := inspect(ctx, restoreStore, restoreWriter, restoreApplier, restoreView, fixtures.Positive.SensorID, incidentID, filepath.Join(restoreRoot, "state"), filepath.Join(restoreRoot, "segments"))
	if err != nil {
		return fail(err)
	}
	restoreEquivalent := equalSequences(restoreFacts.accepted, acceptedBefore) &&
		equalSequences(restoreFacts.acknowledged, acknowledgedBefore) &&
		restoreFacts.counts == countsBefore && equalSegments(restoreFacts.segments, segmentsBefore) &&
		equalDigests(restoreFacts.digests, digestsBefore) && restoreFacts.manifestDigest == manifestBeforeRestart &&
		restoreFacts.triageEntries == triageEntries && restoreFacts.coverage && sameLoss(restoreFacts.loss, loss)
	if !restoreEquivalent {
		return fail(errors.New("acceptance: restored copy changed the accepted state"))
	}
	step("restart-restore", "the accepted state, exact segment bytes, index, triage and loss accounting survived restart and a restored copy")

	outcome.Result = WorkflowResult{
		EnrolledSensor: fixtures.Positive.SensorID, AppliedRevision: applied.Revision,
		AcceptedSequences: acceptedBefore, AcknowledgedSequences: acknowledgedBefore,
		DroppedSequence: fixtures.Positive.Events[fixtures.Positive.OverflowEventIndex].Sequence,
		Loss:            loss, Counts: countsBefore, Segments: segmentsBefore, SegmentDigests: digestsBefore,
		IncidentCount: len(snapshot.Incidents), IncidentID: incidentID, TriageEntries: triageEntries,
		RetentionEligible: len(retention.Segments), CoverageComplete: snapshot.Coverage.Complete,
		Sensor: sensorState, ManifestDigest: manifestBeforeRestart,
		Restarted: true, Restored: true, RestoreEquivalent: true,
	}
	outcome.Runtime = Runtime{
		StateDir: stateDir, SegmentsDir: segmentsDir, PublicKeyFile: publicKeyFile, IssuerFile: issuerFile,
		SensorID: fixtures.Positive.SensorID, StorageLimits: fixtures.Positive.StorageLimits,
		SegmentLimits: fixtures.Positive.SegmentLimits, ConfigMaxSensors: fixtures.Positive.ConfigMaxSensors,
		Bounds: fixtures.Positive.Bounds, Incident: fixtures.Positive.Incident, Rotation: fixtures.Positive.Rotation,
		ConfigPublicKeySHA256: digestHex(public),
	}
	if err := writeJSON(filepath.Join(root, "runtime.json"), outcome.Runtime); err != nil {
		return fail(err)
	}
	if err := writeJSON(filepath.Join(root, "outcome.json"), outcome); err != nil {
		return fail(err)
	}
	return outcome, nil
}

type workflowFacts struct {
	accepted, acknowledged []int64
	counts                 Counts
	loss                   spool.LossSummary
	segments               []SegmentState
	digests                map[string]string
	triageEntries          int
	coverage               bool
	sensor                 SensorState
	manifestDigest         string
}

func inspect(ctx context.Context, store *storage.Store, writer *events.Writer, applier *sensor.Applier, view *incidentview.View, sensorID, incidentID, stateDir, segmentsDir string) (workflowFacts, error) {
	var facts workflowFacts
	records, err := store.Records(ctx)
	if err != nil {
		return facts, err
	}
	facts.counts = countRecords(records)
	facts.accepted, facts.acknowledged = eventSequences(records)
	facts.segments, err = segmentStates(writer)
	if err != nil {
		return facts, err
	}
	facts.digests, err = segmentDigests(segmentsDir)
	if err != nil {
		return facts, err
	}
	facts.manifestDigest, err = manifestDigest(stateDir)
	if err != nil {
		return facts, err
	}
	loss, err := spool.New(store, applier)
	if err != nil {
		return facts, err
	}
	facts.loss, err = loss.Losses(ctx, sensorID)
	if err != nil {
		return facts, err
	}
	snapshot, err := view.Snapshot(ctx)
	if err != nil {
		return facts, err
	}
	facts.coverage = snapshot.Coverage.Complete
	facts.triageEntries = historyLength(snapshot, incidentID)
	sensors, err := sensorview.BuildSnapshot(ctx, store, applier, time.Now().UTC())
	if err != nil {
		return facts, err
	}
	facts.sensor, err = selectSensor(sensors, sensorID)
	return facts, err
}

func desiredState(fixtures Fixtures, now time.Time, private ed25519.PrivateKey) ([]byte, []byte, error) {
	issued := now.Add(time.Duration(fixtures.Positive.Config.IssuedOffsetSeconds) * time.Second)
	expires := issued.Add(time.Duration(fixtures.Positive.Config.LifetimeSeconds) * time.Second)
	document := struct {
		SchemaVersion string          `json:"schema_version"`
		SensorID      string          `json:"sensor_id"`
		Revision      int64           `json:"revision"`
		IssuedAt      string          `json:"issued_at"`
		ExpiresAt     string          `json:"expires_at"`
		Settings      config.Settings `json:"settings"`
	}{
		SchemaVersion: contracts.SchemaVersion, SensorID: fixtures.Positive.SensorID,
		Revision: fixtures.Positive.Config.Revision, IssuedAt: issued.Format(time.RFC3339Nano),
		ExpiresAt: expires.Format(time.RFC3339Nano), Settings: fixtures.Positive.Settings,
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	signature, err := config.Sign(payload, private)
	if err != nil {
		return nil, nil, err
	}
	return payload, signature, nil
}

func clientTLS(material c24fixture.Material, now time.Time) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair([]byte(material.Initial), []byte(material.InitialKey))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(material.Authority)) {
		return nil, errors.New("acceptance: authority is not a certificate")
	}
	return &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func writePrivate(path string, content []byte) error {
	return os.WriteFile(path, content, 0600)
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func manifestDigest(stateDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "manifest.json"))
	if err != nil {
		return "", err
	}
	return digestHex(raw), nil
}

func countRecords(records []storage.Record) Counts {
	var counts Counts
	for _, record := range records {
		switch {
		case record.Config != nil:
			counts.Config++
		case record.Enrollment != nil:
			counts.Enrollment++
		case record.Gap != nil:
			counts.Gap++
		case record.Ack != nil:
			counts.Ack++
		case record.Rotation != nil:
			counts.Rotation++
		case record.Incident != nil:
			counts.Incident++
		case record.Event.SchemaVersion != "":
			counts.Event++
		}
	}
	return counts
}

func eventSequences(records []storage.Record) (accepted, acknowledged []int64) {
	for _, record := range records {
		if record.Event.SchemaVersion != "" {
			accepted = append(accepted, record.Event.Sequence)
		}
		if record.Ack != nil {
			acknowledged = append(acknowledged, record.Ack.Sequence)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i] < accepted[j] })
	sort.Slice(acknowledged, func(i, j int) bool { return acknowledged[i] < acknowledged[j] })
	return accepted, acknowledged
}

func segmentStates(writer *events.Writer) ([]SegmentState, error) {
	segments, err := writer.Segments()
	if err != nil {
		return nil, err
	}
	out := make([]SegmentState, 0, len(segments))
	for _, segment := range segments {
		out = append(out, SegmentState{ID: segment.ID, Records: segment.Records, Sealed: segment.Sealed})
	}
	return out, nil
}

func segmentDigests(directory string) (map[string]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	digests := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		digests[entry.Name()] = digestHex(raw)
	}
	return digests, nil
}

func historyLength(snapshot incidentview.ViewSnapshot, id string) int {
	for _, incident := range snapshot.Incidents {
		if incident.ID == id {
			return len(incident.History)
		}
	}
	return 0
}

func selectSensor(snapshot sensorview.Snapshot, sensorID string) (SensorState, error) {
	for _, sensor := range snapshot.Sensors {
		if sensor.SensorID == sensorID {
			state := SensorState{SensorID: sensor.SensorID, Offline: sensor.Offline, ConfigStatus: sensor.ConfigStatus, DroppedEventCount: sensor.DroppedEventCount}
			if sensor.LastEventAt != nil {
				state.LastEventAt = *sensor.LastEventAt
			}
			return state, nil
		}
	}
	return SensorState{}, errors.New("acceptance: sensor is missing from the snapshot")
}

func equalSequences(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalSegments(left, right []SegmentState) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalDigests(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, digest := range left {
		if right[name] != digest {
			return false
		}
	}
	return true
}

func sameLoss(left, right spool.LossSummary) bool {
	if left.SensorID != right.SensorID || left.Count != right.Count || len(left.Gaps) != len(right.Gaps) {
		return false
	}
	for i := range left.Gaps {
		if left.Gaps[i] != right.Gaps[i] {
			return false
		}
	}
	return true
}

func sameAck(left, right ackResponse) bool {
	if !left.OK || !right.OK || left.FirstSequence != right.FirstSequence || left.LastSequence != right.LastSequence || len(left.Events) != len(right.Events) {
		return false
	}
	for i := range left.Events {
		if left.Events[i] != right.Events[i] {
			return false
		}
	}
	return true
}

func copyTree(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("acceptance: restore source is not a directory")
	}
	if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(source, entry.Name())
		dst := filepath.Join(destination, entry.Name())
		child, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := copyTree(src, dst); err != nil {
				return err
			}
			continue
		}
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, raw, child.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// ingestServer is a test-only harness around the real C09 guard and C16
// collector. It is not a product listener and does not add an ingest protocol.
type ingestServer struct {
	listener net.Listener
	guard    *pki.Guard
	ingestor *collector.Ingestor
	mu       sync.Mutex
	errs     []error
	closed   bool
}

func startIngest(guard *pki.Guard, store *storage.Store, applier *sensor.Applier) (*ingestServer, error) {
	if guard == nil || store == nil || applier == nil {
		return nil, ErrInvalidOptions
	}
	ingestor, err := collector.New(store, applier)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &ingestServer{listener: listener, guard: guard, ingestor: ingestor}
	go server.accept()
	return server, nil
}

func (s *ingestServer) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *ingestServer) handle(conn net.Conn) {
	defer conn.Close()
	tlsConn := tls.Server(conn, s.guard.TLSConfig())
	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		s.record(err)
		return
	}
	if _, err := s.guard.Authenticate(tlsConn); err != nil {
		s.record(err)
		return
	}
	length := make([]byte, 4)
	if _, err := io.ReadFull(tlsConn, length); err != nil {
		s.record(err)
		return
	}
	size := binary.BigEndian.Uint32(length)
	if size == 0 || size > maxEnvelope {
		s.record(errors.New("acceptance: invalid batch envelope size"))
		return
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(tlsConn, raw); err != nil {
		s.record(err)
		return
	}
	var envelope batchEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.BatchID == "" || len(envelope.Events) == 0 {
		s.record(errors.New("acceptance: malformed batch envelope"))
		return
	}
	batch := collector.Batch{ID: envelope.BatchID, FirstSequence: envelope.FirstSequence, LastSequence: envelope.LastSequence}
	sensorID := ""
	for _, frame := range envelope.Events {
		decoded, failure := contracts.DecodeEvent(context.Background(), []byte(frame))
		if failure != nil {
			s.record(failure)
			return
		}
		if sensorID == "" {
			sensorID = decoded.SensorID
		}
		if decoded.SensorID != sensorID {
			s.record(collector.ErrSensorMismatch)
			return
		}
		batch.Events = append(batch.Events, []byte(frame))
	}
	if err := s.guard.Allows(tlsConn.ConnectionState(), sensorID); err != nil {
		s.record(err)
		return
	}
	acknowledgement, err := s.ingestor.Ingest(context.Background(), sensorID, batch)
	if err != nil {
		s.record(err)
		s.respond(tlsConn, ackResponse{OK: false, Error: err.Error()})
		return
	}
	response := ackResponse{OK: true, FirstSequence: acknowledgement.FirstSequence, LastSequence: acknowledgement.LastSequence}
	for _, event := range acknowledgement.Events {
		response.Events = append(response.Events, ackEvent{EventID: event.EventID, Sequence: event.Sequence})
	}
	s.respond(tlsConn, response)
}

func (s *ingestServer) respond(conn *tls.Conn, response ackResponse) {
	raw, err := json.Marshal(response)
	if err != nil {
		return
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(raw)))
	_, _ = conn.Write(append(length, raw...))
}

func (s *ingestServer) Deliver(ctx context.Context, clientConfig *tls.Config, envelope batchEnvelope) (ackResponse, error) {
	if ctx == nil || clientConfig == nil {
		return ackResponse{}, ErrInvalidOptions
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", s.listener.Addr().String(), clientConfig)
	if err != nil {
		return ackResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return ackResponse{}, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return ackResponse{}, err
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(raw)))
	if _, err := conn.Write(append(length, raw...)); err != nil {
		return ackResponse{}, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return ackResponse{}, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxEnvelope {
		return ackResponse{}, errors.New("acceptance: invalid acknowledgement size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return ackResponse{}, err
	}
	var response ackResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return ackResponse{}, err
	}
	if !response.OK {
		return response, errors.New("acceptance: remote rejection: " + response.Error)
	}
	return response, nil
}

func (s *ingestServer) record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, err)
}

func (s *ingestServer) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]error, len(s.errs))
	copy(out, s.errs)
	return out
}

func (s *ingestServer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.listener.Close()
}

// WriteRuntime is kept small so the Node launcher can map the generated state
// without guessing limits or policy from fixture files.
func WriteRuntime(path string, runtime Runtime) error { return writeJSON(path, runtime) }

// WriteOutcome lets the seed runner persist the positive and negative results
// together without exposing the internal file layout.
func WriteOutcome(path string, outcome Outcome) error { return writeJSON(path, outcome) }
