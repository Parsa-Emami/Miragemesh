package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

var ErrRetained = errors.New("event source intentionally expired")
var ErrRetentionConflict = errors.New("retention idempotency conflict")

const retentionName = "retention.json"
const retentionStage = ".retention.tmp"
const retentionMaxBytes = 4 * 1024 * 1024
const retentionMaxOperations = 1024

type RetentionRequest struct {
	Before         time.Time
	Reason         string
	IdempotencyKey string
}

type RetainedEvent struct {
	SensorID   string `json:"sensor_id"`
	EventID    string `json:"event_id"`
	Sequence   int64  `json:"sequence"`
	Record     int64  `json:"record"`
	Digest     string `json:"digest"`
	Bytes      int64  `json:"bytes"`
	ObservedAt string `json:"observed_at"`
}

type RetentionGap struct {
	Segment   string          `json:"segment"`
	Ordinal   uint64          `json:"ordinal"`
	Records   int64           `json:"records"`
	Bytes     int64           `json:"bytes"`
	Digest    string          `json:"digest"`
	Before    string          `json:"before"`
	ExpiredAt string          `json:"expired_at"`
	Reason    string          `json:"reason"`
	Events    []RetainedEvent `json:"events"`
}

type RetentionResult struct {
	Applied  bool           `json:"applied"`
	Replayed bool           `json:"replayed"`
	Segments []RetentionGap `json:"segments"`
}

type retentionOperation struct {
	KeyDigest     string         `json:"key_digest"`
	RequestDigest string         `json:"request_digest"`
	Before        string         `json:"before"`
	ExpiredAt     string         `json:"expired_at"`
	Reason        string         `json:"reason"`
	Segments      []RetentionGap `json:"segments"`
	Checksum      string         `json:"checksum"`
}

type retentionState struct {
	Version    int                  `json:"version"`
	Operations []retentionOperation `json:"operations"`
}

func retentionChecksum(op retentionOperation) string {
	op.Checksum = ""
	raw, _ := json.Marshal(op)
	return digest(raw)
}

func retentionRequestDigest(before, reason string) string {
	raw, _ := json.Marshal([2]string{before, reason})
	return digest(raw)
}

func retentionText(s string, min, max int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) >= min && utf8.RuneCountInString(s) <= max && strings.TrimSpace(s) != ""
}

func validRetentionDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func cloneRetention(gaps []RetentionGap) []RetentionGap {
	result := make([]RetentionGap, len(gaps))
	for i, gap := range gaps {
		result[i] = gap
		result[i].Events = append([]RetainedEvent(nil), gap.Events...)
	}
	return result
}

func (w *Writer) loadRetention(names []string) error {
	w.retention = retentionState{Version: 1, Operations: []retentionOperation{}}
	w.retired = make(map[[2]string]RetainedEvent)
	for _, name := range names {
		if name != retentionName {
			continue
		}
		raw, err := w.readFile(name, retentionMaxBytes)
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &w.retention) != nil {
			return ErrRecovery
		}
		canonical, err := json.Marshal(w.retention)
		if err != nil || !bytes.Equal(canonical, raw) || w.retention.Version != 1 || w.retention.Operations == nil || len(w.retention.Operations) == 0 || len(w.retention.Operations) > retentionMaxOperations {
			return ErrRecovery
		}
		keys, segments := make(map[string]bool), make(map[uint64]bool)
		for _, op := range w.retention.Operations {
			before, be := time.Parse(time.RFC3339Nano, op.Before)
			expired, ee := time.Parse(time.RFC3339Nano, op.ExpiredAt)
			if be != nil || ee != nil || before.Year() < 1 || expired.Year() < 1 || !before.Before(expired) || !retentionText(op.Reason, 1, 1024) || !validRetentionDigest(op.KeyDigest) || keys[op.KeyDigest] || op.Segments == nil || op.Checksum != retentionChecksum(op) || op.RequestDigest != retentionRequestDigest(op.Before, op.Reason) {
				return ErrRecovery
			}
			keys[op.KeyDigest] = true
			for _, gap := range op.Segments {
				if gap.Ordinal == 0 || gap.Segment != segmentID(gap.Ordinal) || segments[gap.Ordinal] || gap.Records < 1 || gap.Bytes < 1 || !validRetentionDigest(gap.Digest) || gap.Records != int64(len(gap.Events)) || gap.Before != op.Before || gap.ExpiredAt != op.ExpiredAt || gap.Reason != op.Reason {
					return ErrRecovery
				}
				segments[gap.Ordinal] = true
				for i, event := range gap.Events {
					observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
					if err != nil || !observed.Before(before) || !retentionText(event.SensorID, 1, 128) || !retentionText(event.EventID, 1, 128) || event.Sequence < 1 || event.Record != int64(i+1) || event.Bytes < 1 || event.Bytes > contracts.MaxInputBytes || !validRetentionDigest(event.Digest) {
						return ErrRecovery
					}
					key := eventKey(event.SensorID, event.EventID)
					if old, ok := w.retired[key]; ok && (old.Digest != event.Digest || old.Sequence != event.Sequence) {
						return ErrRecovery
					}
					w.retired[key] = event
				}
			}
		}
	}
	for _, name := range names {
		if name == retentionStage {
			if w.ops.remove(name) != nil || w.syncDirectory() != nil {
				return ErrIO
			}
		}
	}
	return nil
}

func (w *Writer) retentionEvents(ctx context.Context, data []byte) ([]RetainedEvent, error) {
	result := []RetainedEvent{}
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			return nil, ErrRecovery
		}
		payload, err := decodeFrame(data[:end])
		if err != nil {
			return nil, err
		}
		event, failure := contracts.DecodeEvent(ctx, payload)
		if failure != nil {
			return nil, ErrRecovery
		}
		if _, err := time.Parse(time.RFC3339Nano, event.ObservedAt); err != nil {
			return nil, ErrRecovery
		}
		result = append(result, RetainedEvent{SensorID: event.SensorID, EventID: event.EventID, Sequence: event.Sequence, Record: int64(len(result) + 1), Digest: digest(payload), Bytes: int64(len(payload)), ObservedAt: event.ObservedAt})
		data = data[end+1:]
	}
	return result, nil
}

func (w *Writer) finishRetention(entries []parsedEntry) error {
	if len(w.retention.Operations) == 0 {
		return nil
	}
	present := make(map[uint64]parsedEntry, len(entries))
	for _, entry := range entries {
		present[entry.number] = entry
	}
	var pending []string
	for _, op := range w.retention.Operations {
		for _, gap := range op.Segments {
			entry, ok := present[gap.Ordinal]
			if !ok {
				continue
			}
			if entry.kind != kindSealed {
				return ErrRecovery
			}
			data, err := w.readFile(entry.name, w.limits.MaxBytesPerSegment)
			if err != nil {
				return err
			}
			if int64(len(data)) != gap.Bytes || digest(data) != gap.Digest {
				return ErrRecovery
			}
			events, err := w.retentionEvents(context.Background(), data)
			if err != nil || len(events) != len(gap.Events) {
				return ErrRecovery
			}
			for i, event := range events {
				if event != gap.Events[i] {
					return ErrRecovery
				}
			}
			pending = append(pending, entry.name)
		}
	}
	f, err := w.openFile(retentionName, os.O_RDONLY)
	if err != nil {
		return err
	}
	err = w.ops.sync(f)
	closeErr := f.Close()
	if err != nil || closeErr != nil || w.syncDirectory() != nil {
		return ErrIO
	}
	for _, name := range pending {
		if w.ops.remove(name) != nil {
			return ErrIO
		}
	}
	if w.syncDirectory() != nil {
		return ErrIO
	}
	return nil
}

func (w *Writer) retentionPlan(ctx context.Context, request RetentionRequest) (retentionOperation, bool, error) {
	if err := w.available(ctx); err != nil {
		return retentionOperation{}, false, err
	}
	if request.Before.IsZero() || request.Before.Year() < 1 || request.Before.Year() > 9999 || !request.Before.Before(time.Now()) || !retentionText(request.Reason, 1, 1024) || !retentionText(request.IdempotencyKey, 16, 128) {
		return retentionOperation{}, false, ErrInvalidInput
	}
	before := request.Before.UTC().Format(time.RFC3339Nano)
	op := retentionOperation{KeyDigest: digest([]byte(request.IdempotencyKey)), RequestDigest: retentionRequestDigest(before, request.Reason), Before: before, ExpiredAt: time.Now().UTC().Format(time.RFC3339Nano), Reason: request.Reason, Segments: []RetentionGap{}}
	for _, previous := range w.retention.Operations {
		if previous.KeyDigest == op.KeyDigest {
			if previous.RequestDigest != op.RequestDigest {
				return retentionOperation{}, false, ErrRetentionConflict
			}
			return previous, true, nil
		}
	}
	for _, seg := range w.segments {
		if seg.kind != kindSealed || seg.incomplete != nil {
			continue
		}
		data, err := w.readFile(seg.name, w.limits.MaxBytesPerSegment)
		if err != nil {
			return retentionOperation{}, false, err
		}
		entries, err := w.retentionEvents(ctx, data)
		if err != nil {
			return retentionOperation{}, false, err
		}
		if int64(len(entries)) != seg.records || int64(len(data)) != seg.bytes {
			return retentionOperation{}, false, ErrRecovery
		}
		eligible := true
		for _, event := range entries {
			existing, ok := w.indexEntry(event.SensorID, event.EventID)
			if !ok || existing.Digest != event.Digest || existing.Sequence != event.Sequence {
				return retentionOperation{}, false, ErrIndexConflict
			}
			observed, _ := time.Parse(time.RFC3339Nano, event.ObservedAt)
			if !observed.Before(request.Before) {
				eligible = false
			}
		}
		if eligible {
			op.Segments = append(op.Segments, RetentionGap{Segment: seg.id, Ordinal: seg.number, Records: seg.records, Bytes: int64(len(data)), Digest: digest(data), Before: op.Before, ExpiredAt: op.ExpiredAt, Reason: op.Reason, Events: entries})
		}
	}
	op.Checksum = retentionChecksum(op)
	return op, false, nil
}

func (w *Writer) PlanRetention(ctx context.Context, request RetentionRequest) (RetentionResult, error) {
	if w == nil {
		return RetentionResult{}, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op, replayed, err := w.retentionPlan(ctx, request)
	if err != nil {
		return RetentionResult{}, err
	}
	return RetentionResult{Applied: replayed, Replayed: replayed, Segments: cloneRetention(op.Segments)}, nil
}

func (w *Writer) Expire(ctx context.Context, request RetentionRequest) (RetentionResult, error) {
	if w == nil {
		return RetentionResult{}, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op, replayed, err := w.retentionPlan(ctx, request)
	if err != nil {
		return RetentionResult{}, err
	}
	if replayed {
		return RetentionResult{Applied: true, Replayed: true, Segments: cloneRetention(op.Segments)}, nil
	}
	if len(w.retention.Operations) >= retentionMaxOperations {
		return RetentionResult{}, ErrQuota
	}
	next := retentionState{Version: 1, Operations: append(append([]retentionOperation(nil), w.retention.Operations...), op)}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > retentionMaxBytes {
		return RetentionResult{}, ErrQuota
	}
	if err := ctx.Err(); err != nil {
		return RetentionResult{}, err
	}
	w.poisoned = true
	f, err := w.ops.create(retentionStage)
	if err != nil {
		return RetentionResult{}, ErrIO
	}
	n, writeErr := w.ops.write(f, raw)
	if writeErr != nil || n != len(raw) {
		f.Close()
		return RetentionResult{}, ErrIO
	}
	if w.ops.sync(f) != nil {
		f.Close()
		return RetentionResult{}, ErrIO
	}
	if f.Close() != nil || w.ops.rename(retentionStage, retentionName) != nil || w.syncDirectory() != nil {
		return RetentionResult{}, ErrIO
	}
	w.retention = next
	names, err := w.names()
	if err != nil {
		return RetentionResult{}, err
	}
	entries, err := w.entries(names)
	if err != nil {
		return RetentionResult{}, err
	}
	if err := w.finishRetention(entries); err != nil {
		return RetentionResult{}, err
	}
	for _, gap := range op.Segments {
		for _, event := range gap.Events {
			w.retired[eventKey(event.SensorID, event.EventID)] = event
		}
	}
	w.indexEntries = nil
	w.byEvent = make(map[[2]string]int)
	w.duplicates = 0
	remaining := make([]*segment, 0, len(w.segments))
	expired := make(map[uint64]bool, len(op.Segments))
	for _, gap := range op.Segments {
		expired[gap.Ordinal] = true
	}
	for _, seg := range w.segments {
		if expired[seg.number] {
			continue
		}
		_, records, err := w.load(parsedEntry{number: seg.number, kind: seg.kind, name: seg.name})
		if err != nil {
			return RetentionResult{}, err
		}
		if err := w.indexRecords(records); err != nil {
			return RetentionResult{}, err
		}
		remaining = append(remaining, seg)
	}
	w.segments = remaining
	w.poisoned = false
	return RetentionResult{Applied: true, Segments: cloneRetention(op.Segments)}, nil
}
