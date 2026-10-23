package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// segmentProjectionOptions is the operator configuration of the one-shot
// projection workflow. Every limit is required; tests choose their own policy
// values and those values are not product defaults.
type segmentProjectionOptions struct {
	StorageDir          string
	SegmentsDir         string
	StorageLimits       storage.Limits
	SegmentLimits       events.Limits
	AlertsRequested     bool
	AlertsRateLimit     int
	AlertsWindowSeconds int
}

// segmentProjectionIncomplete describes one preserved non-event tail.
type segmentProjectionIncomplete struct {
	Segment string `json:"segment"`
	Offset  int64  `json:"offset"`
	Bytes   int64  `json:"bytes"`
	Digest  string `json:"digest"`
}

// segmentProjectionOrdinalGap is an exclusive gap between present segment
// ordinals. It is a storage fact, not an event sequence gap.
type segmentProjectionOrdinalGap struct {
	After  uint64 `json:"after"`
	Before uint64 `json:"before"`
}

// segmentProjectionOutcome is the typed runtime result of projecting the C05
// snapshot into immutable segments. C18 rebuilds the deduplication index from
// the committed segments, so repetition is deduplicated. The projection still
// shares no commit with C16.
type segmentProjectionOutcome struct {
	Scope                   string                        `json:"scope"`
	Status                  string                        `json:"status"`
	Appended                int                           `json:"appended"`
	Skipped                 int                           `json:"skipped"`
	Retained                int                           `json:"retained"`
	RetentionGaps           []events.RetentionGap         `json:"retention_gaps,omitempty"`
	AlreadyProjected        int                           `json:"already_projected"`
	Segments                int                           `json:"segments"`
	SegmentsKnown           bool                          `json:"segments_known"`
	IncompleteSegments      int                           `json:"incomplete_segments"`
	Incomplete              []segmentProjectionIncomplete `json:"incomplete,omitempty"`
	IndexKnown              bool                          `json:"index_known"`
	IndexRecords            int64                         `json:"index_records"`
	IndexSensors            int                           `json:"index_sensors"`
	IndexComplete           bool                          `json:"index_complete"`
	IndexDuplicates         int64                         `json:"index_duplicates"`
	IndexMissingOrdinals    []segmentProjectionOrdinalGap `json:"index_missing_ordinals,omitempty"`
	IndexIncompleteSegments int                           `json:"index_incomplete_segments"`
	Deduplicated            bool                          `json:"deduplicated"`
	AtomicWithC16           bool                          `json:"atomic_with_c16"`
	Error                   string                        `json:"error,omitempty"`
	ErrorKind               string                        `json:"error_kind,omitempty"`
	Alerts                  *alerts.Outcome               `json:"alerts,omitempty"`
}

// projectSegments opens the existing C05 store, reads its owned snapshot and
// appends only validated event records to the segment store. It returns the
// partial projection on failure and never writes a C05 receipt or ACK.
func projectSegments(ctx context.Context, options segmentProjectionOptions) (outcome segmentProjectionOutcome, err error) {
	outcome = segmentProjectionOutcome{
		Scope:         "event-segments",
		Status:        "failed",
		Deduplicated:  true,
		AtomicWithC16: false,
	}
	if ctx == nil || options.StorageDir == "" || options.SegmentsDir == "" {
		return outcome, events.ErrInvalidInput
	}
	if options.AlertsRequested {
		if options.AlertsRateLimit <= 0 || options.AlertsWindowSeconds <= 0 || int64(options.AlertsWindowSeconds) > int64(^uint64(0)>>1)/int64(time.Second) {
			return outcome, alerts.ErrInvalidPolicy
		}
	} else if options.AlertsRateLimit != 0 || options.AlertsWindowSeconds != 0 {
		return outcome, alerts.ErrInvalidPolicy
	}
	if segmentPathsConflict(options.StorageDir, options.SegmentsDir) {
		return outcome, events.ErrInvalidInput
	}
	if err := requireExistingC05Store(options.StorageDir); err != nil {
		return outcome, err
	}
	if err := ctx.Err(); err != nil {
		return outcome, err
	}

	store, openErr := storage.Open(options.StorageDir, options.StorageLimits)
	if openErr != nil {
		return outcome, openErr
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	records, readErr := store.Records(ctx)
	if readErr != nil {
		return outcome, readErr
	}

	writer, openErr := events.Open(options.SegmentsDir, options.SegmentLimits)
	if openErr != nil {
		return outcome, openErr
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	projection, appendErr := writer.AppendRecords(ctx, records)
	outcome.Appended = projection.Appended
	outcome.Skipped = projection.Skipped
	outcome.AlreadyProjected = projection.AlreadyProjected
	outcome.Retained = projection.Retained
	outcome.IndexKnown = projection.IndexKnown
	if projection.IndexKnown {
		outcome.RetentionGaps = projection.Rebuilt.Retention
		outcome.IndexRecords = projection.Rebuilt.Records
		outcome.IndexSensors = projection.Rebuilt.Sensors
		outcome.IndexComplete = projection.Rebuilt.Complete
		outcome.IndexDuplicates = projection.Rebuilt.Duplicates
		outcome.IndexIncompleteSegments = len(projection.Rebuilt.Incomplete)
		for _, gap := range projection.Rebuilt.Missing {
			outcome.IndexMissingOrdinals = append(outcome.IndexMissingOrdinals, segmentProjectionOrdinalGap{
				After:  gap.After,
				Before: gap.Before,
			})
		}
	}
	snapshotErr := captureSegmentState(writer, &outcome)
	if appendErr != nil {
		return outcome, appendErr
	}
	if snapshotErr != nil {
		return outcome, snapshotErr
	}
	if options.AlertsRequested {
		index, indexErr := writer.Index()
		if indexErr != nil {
			return outcome, indexErr
		}
		derived, deriveErr := deriveAlerts(ctx, records, index, alerts.Policy{
			RateLimit: options.AlertsRateLimit,
			Window:    time.Duration(options.AlertsWindowSeconds) * time.Second,
		})
		if deriveErr != nil {
			return outcome, deriveErr
		}
		outcome.Alerts = &derived
	}
	outcome.Status = "projected"
	return outcome, nil
}

func deriveAlerts(ctx context.Context, records []storage.Record, index events.Index, policy alerts.Policy) (alerts.Outcome, error) {
	sources := make([]alerts.Source, 0, len(records))
	bySensor := make(map[string]*alerts.SensorHealth)
	coverageComplete := index.Complete
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return alerts.Outcome{}, err
		}
		if record.Event.SchemaVersion != "" {
			raw := record.Input
			if len(raw) > 0 && raw[len(raw)-1] == '\n' {
				raw = raw[:len(raw)-1]
			}
			var event struct {
				SensorID string `json:"sensor_id"`
				EventID  string `json:"event_id"`
				Sequence int64  `json:"sequence"`
			}
			if err := json.Unmarshal(raw, &event); err != nil {
				return alerts.Outcome{}, events.ErrInvalidEvent
			}
			entry, exists := index.Lookup(event.SensorID, event.EventID)
			if !exists {
				if retired, ok := index.Retained(event.SensorID, event.EventID); ok && (retired.Sequence != event.Sequence || retired.Digest != segmentDigest(raw)) {
					return alerts.Outcome{}, events.ErrIndexConflict
				}
				coverageComplete = false
				continue
			}
			if entry.Sequence != event.Sequence || entry.Digest != segmentDigest(raw) {
				return alerts.Outcome{}, events.ErrIndexConflict
			}
			sources = append(sources, alerts.Source{Raw: append([]byte(nil), raw...), Ref: entry})
			continue
		}
		if record.Gap == nil {
			continue
		}
		gap, err := contracts.DecodeSpoolGap(ctx, record.Input)
		if err != nil || gap != *record.Gap || record.Receipt.OperationID != sensor.GapOperationID(gap.SensorID, gap.Sequence) {
			return alerts.Outcome{}, storage.ErrRecovery
		}
		signal := bySensor[gap.SensorID]
		if signal == nil {
			signal = &alerts.SensorHealth{SensorID: gap.SensorID}
			bySensor[gap.SensorID] = signal
		}
		signal.DroppedEvents++
		signal.GapSequences = append(signal.GapSequences, gap.Sequence)
	}
	health := make([]alerts.SensorHealth, 0, len(bySensor))
	for _, signal := range bySensor {
		health = append(health, *signal)
	}
	return alerts.Evaluate(ctx, sources, health, policy, coverageComplete)
}

func segmentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// captureSegmentState records the durable state that exists after a partial
// append. A poisoned or closed writer cannot expose a trustworthy snapshot;
// SegmentsKnown then remains false instead of implying that no segment exists.
func captureSegmentState(writer *events.Writer, outcome *segmentProjectionOutcome) error {
	segments, err := writer.Segments()
	if err != nil {
		return err
	}
	outcome.SegmentsKnown = true
	outcome.Segments = len(segments)
	outcome.IncompleteSegments = 0
	outcome.Incomplete = nil
	for _, segment := range segments {
		if segment.Incomplete == nil {
			continue
		}
		outcome.IncompleteSegments++
		outcome.Incomplete = append(outcome.Incomplete, segmentProjectionIncomplete{
			Segment: segment.ID,
			Offset:  segment.Incomplete.Offset,
			Bytes:   segment.Incomplete.Bytes,
			Digest:  segment.Incomplete.Digest,
		})
	}
	return nil
}

func requireExistingC05Store(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return storage.ErrInvalidInput
		}
		return storage.ErrIO
	}
	if !info.IsDir() {
		return storage.ErrInvalidInput
	}
	info, err = os.Stat(filepath.Join(directory, "manifest.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return storage.ErrRecovery
		}
		return storage.ErrIO
	}
	if !info.Mode().IsRegular() {
		return storage.ErrRecovery
	}
	return nil
}

func segmentPathsConflict(first, second string) bool {
	firstAbsolute, firstErr := filepath.Abs(first)
	secondAbsolute, secondErr := filepath.Abs(second)
	if firstErr != nil || secondErr != nil {
		return true
	}
	return pathContains(firstAbsolute, secondAbsolute) || pathContains(secondAbsolute, firstAbsolute)
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return true
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func runSegmentProjection(ctx context.Context, options segmentProjectionOptions) int {
	outcome, err := projectSegments(ctx, options)
	if err != nil {
		outcome.Status = "failed"
		outcome.Error = err.Error()
		outcome.ErrorKind = segmentProjectionErrorKind(err)
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(outcome); encodeErr != nil {
		fmt.Fprintln(os.Stderr, "Unable to write segment projection result")
		return 1
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, events.ErrInvalidInput) || errors.Is(err, storage.ErrInvalidInput) || errors.Is(err, alerts.ErrInvalidInput) || errors.Is(err, alerts.ErrInvalidPolicy) {
		return 2
	}
	return 1
}

func segmentProjectionErrorKind(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, storage.ErrInvalidInput), errors.Is(err, events.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, events.ErrIndexConflict), errors.Is(err, events.ErrRetentionConflict):
		return "conflict"
	case errors.Is(err, events.ErrInvalidEvent):
		return "invalid_event"
	case errors.Is(err, alerts.ErrInvalidSource):
		return "invalid_event"
	case errors.Is(err, alerts.ErrSourceConflict):
		return "conflict"
	case errors.Is(err, alerts.ErrInvalidPolicy), errors.Is(err, alerts.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, storage.ErrLocked), errors.Is(err, events.ErrLocked):
		return "locked"
	case errors.Is(err, storage.ErrQuota), errors.Is(err, events.ErrQuota):
		return "quota"
	case errors.Is(err, storage.ErrRecovery), errors.Is(err, events.ErrRecovery):
		return "recovery"
	case errors.Is(err, storage.ErrIO), errors.Is(err, events.ErrIO):
		return "io"
	case errors.Is(err, storage.ErrClosed), errors.Is(err, events.ErrClosed):
		return "closed"
	default:
		return "unknown"
	}
}
