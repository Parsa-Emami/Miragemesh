package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// segmentProjectionOptions is the operator configuration of the one-shot
// projection workflow. Every limit is required; tests choose their own policy
// values and those values are not product defaults.
type segmentProjectionOptions struct {
	StorageDir    string
	SegmentsDir   string
	StorageLimits storage.Limits
	SegmentLimits events.Limits
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
	outcome.IndexKnown = projection.IndexKnown
	if projection.IndexKnown {
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
	outcome.Status = "projected"
	return outcome, nil
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
	if errors.Is(err, events.ErrInvalidInput) || errors.Is(err, storage.ErrInvalidInput) {
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
	case errors.Is(err, events.ErrIndexConflict):
		return "conflict"
	case errors.Is(err, events.ErrInvalidEvent):
		return "invalid_event"
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
