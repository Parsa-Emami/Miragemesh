// Package events provides an append-only, bounded JSONL event segment log.
//
// It owns segment files only. Collector acceptance receipts, spool records,
// acknowledgements, configuration and enrollment remain owned by storage.
package events

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrLocked       = errors.New("event segments locked")
	ErrQuota        = errors.New("quota exceeded")
	ErrRecovery     = errors.New("recovery required")
	ErrInvalidInput = errors.New("invalid input")
	ErrInvalidEvent = errors.New("invalid event")
	ErrIO           = errors.New("event segment I/O failed")
	ErrClosed       = errors.New("event segments closed")
)

// Limits are mandatory. Values in tests are policy for those tests only and
// are not product defaults or capacity claims.
type Limits struct {
	MaxSegments          int   `json:"max_segments"`
	MaxRecordsPerSegment int64 `json:"max_records_per_segment"`
	MaxBytesPerSegment   int64 `json:"max_bytes_per_segment"`
}

func (l Limits) validate() error {
	if l.MaxSegments <= 0 || l.MaxSegments > math.MaxInt-5 ||
		l.MaxRecordsPerSegment <= 0 ||
		l.MaxBytesPerSegment < contracts.MaxInputBytes+1 ||
		l.MaxBytesPerSegment == math.MaxInt64 {
		return ErrInvalidInput
	}
	return nil
}

// Ref identifies one durably appended event record.
type Ref struct {
	Segment  string
	Record   int64
	SensorID string
	EventID  string
	Sequence int64
	Digest   string
	Bytes    int64
}

// Incomplete describes a preserved, non-newline-terminated tail. It is status,
// never an event record.
type Incomplete struct {
	Offset int64
	Bytes  int64
	Digest string
}

// Segment is the durable state of one segment file. ID is stable across the
// active-to-sealed transition.
type Segment struct {
	ID         string
	Records    int64
	Bytes      int64
	Sealed     bool
	Incomplete *Incomplete
}

// Projection reports how many storage records became events, how many were
// already indexed, and how many non-event storage records were intentionally
// skipped. Rebuilt is the index snapshot captured before any append.
type Projection struct {
	Appended         int
	Skipped          int
	AlreadyProjected int
	Retained         int
	IndexKnown       bool
	Rebuilt          Index
}

type segmentKind uint8

const (
	kindActive segmentKind = iota + 1
	kindSealed
	kindIncomplete
)

const (
	segmentPrefix = "segment-"
	lockName      = ".lock"
)

type segment struct {
	id         string
	number     uint64
	name       string
	kind       segmentKind
	records    int64
	bytes      int64
	incomplete *Incomplete
	file       *os.File
}

// fileOps are filesystem operations kept replaceable for syscall-failure tests.
type fileOps struct {
	remove func(string) error
	write  func(*os.File, []byte) (int, error)
	sync   func(*os.File) error
	rename func(string, string) error
	create func(string) (*os.File, error)
}

// Writer owns one locked segment directory.
type Writer struct {
	mu        sync.Mutex
	root      *os.Root
	lock      *os.File
	limits    Limits
	ops       fileOps
	segments  []*segment
	active    *segment
	next      uint64
	exhausted bool
	closed    bool
	poisoned  bool

	indexEntries []Entry
	byEvent      map[[2]string]int
	duplicates   int64
	retention    retentionState
	retired      map[[2]string]RetainedEvent
}

type parsedEntry struct {
	number uint64
	kind   segmentKind
	name   string
}

func segmentID(number uint64) string {
	return fmt.Sprintf("segment-%020d", number)
}

func segmentName(number uint64, kind segmentKind) string {
	switch kind {
	case kindActive:
		return segmentID(number) + ".jsonl"
	case kindSealed:
		return segmentID(number) + ".sealed.jsonl"
	case kindIncomplete:
		return segmentID(number) + ".incomplete.jsonl"
	default:
		return ""
	}
}

func parseSegmentName(name string) (uint64, segmentKind, bool) {
	if !strings.HasPrefix(name, segmentPrefix) {
		return 0, 0, false
	}
	rest := strings.TrimPrefix(name, segmentPrefix)
	if len(rest) < 21 || rest[20] != '.' {
		return 0, 0, false
	}
	digits := rest[:20]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, 0, false
		}
	}
	number, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || number == 0 {
		return 0, 0, false
	}
	var kind segmentKind
	switch rest[20:] {
	case ".jsonl":
		kind = kindActive
	case ".sealed.jsonl":
		kind = kindSealed
	case ".incomplete.jsonl":
		kind = kindIncomplete
	default:
		return 0, 0, false
	}
	return number, kind, true
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func private(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode() == mode && (info.IsDir() || stat.Nlink == 1)
}

func (w *Writer) openFile(name string, flags int) (*os.File, error) {
	f, err := w.root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrIO
	}
	info, err := f.Stat()
	if err != nil || !private(info, 0600) {
		f.Close()
		return nil, ErrRecovery
	}
	return f, nil
}

func (w *Writer) readFile(name string, limit int64) ([]byte, error) {
	f, err := w.openFile(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, ErrIO
	}
	if int64(len(data)) > limit {
		return nil, ErrRecovery
	}
	return data, nil
}

func (w *Writer) syncDirectory() error {
	f, err := w.root.Open(".")
	if err != nil {
		return ErrIO
	}
	if w.ops.sync(f) != nil {
		f.Close()
		return ErrIO
	}
	if f.Close() != nil {
		return ErrIO
	}
	return nil
}

func (w *Writer) names() ([]string, error) {
	f, err := w.root.Open(".")
	if err != nil {
		return nil, ErrIO
	}
	defer f.Close()
	names, err := f.Readdirnames(w.limits.MaxSegments + 4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrIO
	}
	if len(names) > w.limits.MaxSegments+3 {
		return nil, ErrRecovery
	}
	return names, nil
}

func (w *Writer) entries(names []string) ([]parsedEntry, error) {
	seen := make(map[uint64]bool)
	result := make([]parsedEntry, 0, len(names))
	for _, name := range names {
		info, err := w.root.Lstat(name)
		if err != nil {
			return nil, ErrRecovery
		}
		if name == lockName {
			if !private(info, 0600) || info.Size() != 0 {
				return nil, ErrRecovery
			}
			continue
		}
		if name == retentionName || name == retentionStage {
			if !private(info, 0600) || info.Size() < 0 || info.Size() > retentionMaxBytes {
				return nil, ErrRecovery
			}
			continue
		}
		number, kind, ok := parseSegmentName(name)
		if !ok || seen[number] {
			return nil, ErrRecovery
		}
		if !private(info, 0600) || info.Size() < 0 || info.Size() > w.limits.MaxBytesPerSegment {
			return nil, ErrRecovery
		}
		seen[number] = true
		result = append(result, parsedEntry{number: number, kind: kind, name: name})
	}
	if len(result) > w.limits.MaxSegments {
		return nil, ErrRecovery
	}
	sort.Slice(result, func(i, j int) bool { return result[i].number < result[j].number })
	return result, nil
}

func (w *Writer) load(entry parsedEntry) (*segment, []Entry, error) {
	data, err := w.readFile(entry.name, w.limits.MaxBytesPerSegment)
	if err != nil {
		return nil, nil, err
	}
	seg := &segment{
		id:     segmentID(entry.number),
		number: entry.number,
		name:   entry.name,
		kind:   entry.kind,
		bytes:  int64(len(data)),
	}
	var entries []Entry
	offset := 0
	for offset < len(data) {
		index := bytes.IndexByte(data[offset:], '\n')
		if index < 0 {
			break
		}
		payload, decodeErr := decodeFrame(data[offset : offset+index])
		if decodeErr != nil {
			return nil, nil, ErrRecovery
		}
		event, failure := contracts.DecodeEvent(context.Background(), payload)
		if failure != nil {
			return nil, nil, ErrRecovery
		}
		seg.records++
		entries = append(entries, Entry{
			SensorID: event.SensorID,
			EventID:  event.EventID,
			Sequence: event.Sequence,
			Segment:  seg.id,
			Record:   seg.records,
			Digest:   digest(payload),
			Bytes:    int64(len(payload)),
		})
		offset += index + 1
	}
	tail := data[offset:]
	switch entry.kind {
	case kindActive:
		if len(tail) > 0 {
			if len(tail) > frameLimit(tail) {
				return nil, nil, ErrRecovery
			}
			seg.incomplete = &Incomplete{Offset: int64(offset), Bytes: int64(len(tail)), Digest: digest(tail)}
		}
	case kindSealed:
		if len(tail) != 0 || seg.records == 0 {
			return nil, nil, ErrRecovery
		}
	case kindIncomplete:
		if len(tail) == 0 || len(tail) > frameLimit(tail) {
			return nil, nil, ErrRecovery
		}
		seg.incomplete = &Incomplete{Offset: int64(offset), Bytes: int64(len(tail)), Digest: digest(tail)}
	default:
		return nil, nil, ErrRecovery
	}
	if seg.records > w.limits.MaxRecordsPerSegment {
		return nil, nil, ErrRecovery
	}
	return seg, entries, nil
}

// Open locks and recovers a segment directory. An active file with a torn tail
// is preserved as an incomplete file; complete records before the tail remain
// readable. Every other malformed or unsafe inventory fails with ErrRecovery.
func Open(directory string, limits Limits) (*Writer, error) {
	return openWithOps(directory, limits, nil)
}

func openWithOps(directory string, limits Limits, configure func(*Writer)) (*Writer, error) {
	if directory == "" || limits.validate() != nil {
		return nil, ErrInvalidInput
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, ErrInvalidInput
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Dir(absolute) {
		return nil, ErrRecovery
	}
	if err = os.Mkdir(absolute, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrIO
	}
	info, err := os.Lstat(absolute)
	if err != nil || !private(info, os.ModeDir|0700) {
		return nil, ErrRecovery
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, ErrIO
	}
	w := &Writer{
		root:    root,
		limits:  limits,
		byEvent: make(map[[2]string]int),
	}
	w.ops = fileOps{
		remove: root.Remove,
		write:  func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		sync:   func(f *os.File) error { return f.Sync() },
		rename: root.Rename,
		create: func(name string) (*os.File, error) {
			return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		},
	}
	if configure != nil {
		configure(w)
	}
	success := false
	defer func() {
		if !success {
			_ = w.Close()
		}
	}()

	w.lock, err = w.openFile(lockName, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(w.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, ErrIO
	}
	names, err := w.names()
	if err != nil {
		return nil, err
	}
	entries, err := w.entries(names)
	if err != nil {
		return nil, err
	}

	if err := w.loadRetention(names); err != nil {
		return nil, err
	}
	if err := w.finishRetention(entries); err != nil {
		return nil, err
	}
	if len(w.retention.Operations) > 0 {
		names, err = w.names()
		if err != nil {
			return nil, err
		}
		entries, err = w.entries(names)
		if err != nil {
			return nil, err
		}
	}
	var active *segment
	for _, entry := range entries {
		seg, records, err := w.load(entry)
		if err != nil {
			return nil, err
		}
		if err := w.indexRecords(records); err != nil {
			return nil, err
		}
		if entry.kind == kindActive {
			if active != nil {
				return nil, ErrRecovery
			}
			active = seg
		}
		w.segments = append(w.segments, seg)
	}
	if active != nil {
		for _, seg := range w.segments {
			if seg != active && seg.number > active.number {
				return nil, ErrRecovery
			}
		}
		if active.incomplete != nil {
			nextName := segmentName(active.number, kindIncomplete)
			if w.ops.rename(active.name, nextName) != nil {
				return nil, ErrIO
			}
			if w.syncDirectory() != nil {
				return nil, ErrIO
			}
			active.name = nextName
			active.kind = kindIncomplete
			active = nil
		}
	}
	if active != nil {
		f, err := w.openFile(active.name, os.O_RDWR|os.O_APPEND)
		if err != nil {
			return nil, err
		}
		stat, err := f.Stat()
		if err != nil || stat.Size() != active.bytes {
			f.Close()
			return nil, ErrRecovery
		}
		active.file = f
		w.active = active
	}

	var maximum uint64
	for _, seg := range w.segments {
		if seg.number > maximum {
			maximum = seg.number
		}
	}
	for _, op := range w.retention.Operations {
		for _, gap := range op.Segments {
			if gap.Ordinal > maximum {
				maximum = gap.Ordinal
			}
		}
	}
	w.next = 1
	if maximum > 0 {
		if maximum == math.MaxUint64 {
			w.exhausted = true
		} else {
			w.next = maximum + 1
		}
	}
	success = true
	return w, nil
}

func (w *Writer) available(ctx context.Context) error {
	if w.closed {
		return ErrClosed
	}
	if w.poisoned {
		return ErrRecovery
	}
	if ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// A JSON string is a base64-encoded exact payload; legacy object frames stay unchanged.
// https://pkg.go.dev/encoding/json#Marshal documents the []byte representation.
func frameLimit(frame []byte) int {
	if len(frame) > 0 && frame[0] == '"' {
		return 2 + 4*((contracts.MaxInputBytes+2)/3)
	}
	return contracts.MaxInputBytes
}

func decodeFrame(frame []byte) ([]byte, error) {
	if len(frame) == 0 || len(frame) > frameLimit(frame) {
		return nil, ErrRecovery
	}
	payload := frame
	if frame[0] == '"' {
		payload = nil // Do not let byte-slice decoding overwrite the frame being checked.
		if json.Unmarshal(frame, &payload) != nil {
			return nil, ErrRecovery
		}
		canonical, _ := json.Marshal(payload)
		if !bytes.Equal(canonical, frame) || bytes.IndexByte(payload, '\n') < 0 {
			return nil, ErrRecovery
		}
	}
	if len(payload) == 0 || len(payload) > contracts.MaxInputBytes {
		return nil, ErrRecovery
	}
	return payload, nil
}

func normalizeEvent(ctx context.Context, raw []byte) ([]byte, contracts.Event, error) {
	if ctx == nil {
		return nil, contracts.Event{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, contracts.Event{}, err
	}
	payload := raw
	if len(payload) > 0 && payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
	}
	if len(payload) == 0 || len(payload) > contracts.MaxInputBytes {
		return nil, contracts.Event{}, ErrInvalidEvent
	}
	event, failure := contracts.DecodeEvent(ctx, payload)
	if failure != nil {
		if err := ctx.Err(); err != nil {
			return nil, contracts.Event{}, err
		}
		return nil, contracts.Event{}, ErrInvalidEvent
	}
	if err := ctx.Err(); err != nil {
		return nil, contracts.Event{}, err
	}
	return append([]byte(nil), payload...), event, nil
}

// Append validates the whole event before creating or changing a file. It
// returns only after the record and its framing newline are synced. A record
// that conflicts with the rebuilt index is rejected before bytes change.
func (w *Writer) Append(ctx context.Context, raw []byte) (Ref, error) {
	if w == nil {
		return Ref{}, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.available(ctx); err != nil {
		return Ref{}, err
	}
	payload, event, err := normalizeEvent(ctx, raw)
	if err != nil {
		return Ref{}, err
	}
	return w.appendNormalizedLocked(payload, event)
}

// appendNormalizedLocked is the single append path for direct appends and
// projections. The caller holds w.mu and has already validated the payload.
func (w *Writer) appendNormalizedLocked(payload []byte, event contracts.Event) (Ref, error) {
	candidate := Entry{
		SensorID: event.SensorID,
		EventID:  event.EventID,
		Sequence: event.Sequence,
		Digest:   digest(payload),
		Bytes:    int64(len(payload)),
	}
	if err := w.checkIndexEntry(candidate); err != nil {
		return Ref{}, err
	}
	if _, retired := w.retired[eventKey(event.SensorID, event.EventID)]; retired {
		if _, live := w.indexEntry(event.SensorID, event.EventID); !live {
			return Ref{}, ErrRetained
		}
	}
	frame := payload
	if bytes.IndexByte(payload, '\n') >= 0 {
		frame, _ = json.Marshal(payload)
	}
	line := make([]byte, len(frame)+1)
	copy(line, frame)
	line[len(frame)] = '\n'
	if int64(len(line)) > w.limits.MaxBytesPerSegment {
		return Ref{}, ErrQuota
	}
	if w.active == nil {
		if err := w.createNextLocked(); err != nil {
			return Ref{}, err
		}
	}
	if w.active.records >= w.limits.MaxRecordsPerSegment ||
		int64(len(line)) > w.limits.MaxBytesPerSegment-w.active.bytes {
		if err := w.sealLocked(); err != nil {
			return Ref{}, err
		}
		if err := w.createNextLocked(); err != nil {
			return Ref{}, err
		}
	}
	seg := w.active
	n, err := w.ops.write(seg.file, line)
	if err != nil || n != len(line) {
		w.poisoned = true
		return Ref{}, ErrIO
	}
	if err := w.ops.sync(seg.file); err != nil {
		w.poisoned = true
		return Ref{}, ErrIO
	}
	seg.records++
	seg.bytes += int64(len(line))
	ref := Ref{
		Segment:  seg.id,
		Record:   seg.records,
		SensorID: event.SensorID,
		EventID:  event.EventID,
		Sequence: event.Sequence,
		Digest:   candidate.Digest,
		Bytes:    candidate.Bytes,
	}
	candidate.Segment = ref.Segment
	candidate.Record = ref.Record
	w.recordIndexEntry(candidate)
	return ref, nil
}

func (w *Writer) sealLocked() error {
	seg := w.active
	if seg == nil || seg.records == 0 {
		w.poisoned = true
		return ErrRecovery
	}
	if err := w.ops.sync(seg.file); err != nil {
		w.poisoned = true
		return ErrIO
	}
	if err := seg.file.Close(); err != nil {
		w.poisoned = true
		return ErrIO
	}
	seg.file = nil
	sealedName := segmentName(seg.number, kindSealed)
	if err := w.ops.rename(seg.name, sealedName); err != nil {
		w.poisoned = true
		return ErrIO
	}
	if err := w.syncDirectory(); err != nil {
		w.poisoned = true
		return ErrIO
	}
	seg.name = sealedName
	seg.kind = kindSealed
	w.active = nil
	return nil
}

func (w *Writer) createNextLocked() error {
	if w.exhausted || len(w.segments) >= w.limits.MaxSegments {
		return ErrQuota
	}
	number := w.next
	if number == 0 {
		number = 1
	}
	name := segmentName(number, kindActive)
	f, err := w.ops.create(name)
	if err != nil {
		w.poisoned = true
		return ErrIO
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		w.poisoned = true
		return ErrIO
	}
	info, err := f.Stat()
	if err != nil || !private(info, 0600) {
		f.Close()
		w.poisoned = true
		return ErrRecovery
	}
	if err := w.syncDirectory(); err != nil {
		f.Close()
		w.poisoned = true
		return ErrIO
	}
	seg := &segment{id: segmentID(number), number: number, name: name, kind: kindActive, file: f}
	w.segments = append(w.segments, seg)
	w.active = seg
	if number == math.MaxUint64 {
		w.exhausted = true
	} else {
		w.next = number + 1
	}
	return nil
}

// AppendRecords projects storage records into the event log. Configuration,
// enrollment, gap and acknowledgement records are deliberately skipped; a
// blank record that is none of those is ambiguous and fails recovery. The index
// rebuilt at Open is the deduplication checkpoint: an event that is already
// committed is counted as already projected instead of being written again.
func (w *Writer) AppendRecords(ctx context.Context, records []storage.Record) (Projection, error) {
	if w == nil || ctx == nil {
		return Projection{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Projection{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.available(ctx); err != nil {
		return Projection{}, err
	}
	projection := Projection{IndexKnown: true, Rebuilt: w.snapshotIndex()}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return projection, err
		}
		nonEvent := record.Gap != nil || record.Ack != nil || record.Enrollment != nil || record.Config != nil || record.Incident != nil
		if record.Event.SchemaVersion == "" {
			if nonEvent {
				projection.Skipped++
				continue
			}
			return projection, ErrRecovery
		}
		if nonEvent {
			return projection, ErrRecovery
		}
		payload, event, err := normalizeEvent(ctx, record.Input)
		if err != nil {
			return projection, err
		}
		if existing, ok := w.indexEntry(event.SensorID, event.EventID); ok {
			if existing.Digest != digest(payload) || existing.Sequence != event.Sequence {
				return projection, ErrIndexConflict
			}
			projection.AlreadyProjected++
			continue
		}
		if old, ok := w.retired[eventKey(event.SensorID, event.EventID)]; ok {
			if old.Digest != digest(payload) || old.Sequence != event.Sequence {
				return projection, ErrIndexConflict
			}
			projection.Retained++
			continue
		}
		if _, err := w.appendNormalizedLocked(payload, event); err != nil {
			return projection, err
		}
		projection.Appended++
	}
	return projection, nil
}

// Segments returns a stable snapshot sorted by ordinal. An ordinal gap is a
// retention fact, not an event sequence gap, and is allowed.
func (w *Writer) Segments() ([]Segment, error) {
	if w == nil {
		return nil, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	if w.poisoned {
		return nil, ErrRecovery
	}
	result := make([]Segment, 0, len(w.segments))
	for _, seg := range w.segments {
		item := Segment{
			ID:      seg.id,
			Records: seg.records,
			Bytes:   seg.bytes,
			Sealed:  seg.kind != kindActive,
		}
		if seg.incomplete != nil {
			incomplete := *seg.incomplete
			item.Incomplete = &incomplete
		}
		result = append(result, item)
	}
	return result, nil
}

// Close releases the active file, lock and root. It is safe to call twice.
func (w *Writer) Close() error {
	if w == nil {
		return ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	failure := false
	if w.active != nil && w.active.file != nil {
		if w.active.file.Close() != nil {
			failure = true
		}
		w.active.file = nil
	}
	if w.lock != nil {
		if syscall.Flock(int(w.lock.Fd()), syscall.LOCK_UN) != nil {
			failure = true
		}
		if w.lock.Close() != nil {
			failure = true
		}
		w.lock = nil
	}
	if w.root != nil {
		if w.root.Close() != nil {
			failure = true
		}
		w.root = nil
	}
	if failure {
		return ErrIO
	}
	return nil
}
