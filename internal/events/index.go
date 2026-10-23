package events

import "errors"

// ErrIndexConflict reports two committed records with the same sensor/event
// identity but different content or sequence. It is never trusted as success.
var ErrIndexConflict = errors.New("event index conflict")

// Entry locates one unique committed event record in the immutable segments.
type Entry struct {
	SensorID string
	EventID  string
	Sequence int64
	Segment  string
	Record   int64
	Digest   string
	Bytes    int64
}

// OrdinalRange is an exclusive gap between two present segment ordinals. A
// segment ordinal is a storage fact and is not an event sequence gap.
type OrdinalRange struct {
	After  uint64
	Before uint64
}

// Index is a read-only snapshot that Open rebuilds from the complete records of
// the committed segments. It is derived state: no durable index file exists and
// a lost in-memory snapshot is rebuilt by reopening the writer.
//
// Presence of an entry proves that one complete record was durably written.
// Absence never proves that an event was not ingested: C15 gap records, C23
// retention and a missing segment can all remove a record from this view.
type Index struct {
	Records      int64
	Sensors      int
	SegmentIDs   []string
	FirstOrdinal uint64
	LastOrdinal  uint64
	Missing      []OrdinalRange
	Incomplete   []Segment
	Duplicates   int64
	Retention    []RetentionGap
	retired      map[[2]string]RetainedEvent
	Complete     bool

	entries []Entry
	byEvent map[[2]string]int
}

func eventKey(sensorID, eventID string) [2]string {
	return [2]string{sensorID, eventID}
}

// Entries returns an owned copy of the indexed records in storage order:
// segment ordinal, then one-based record number.
func (i Index) Entries() []Entry {
	return append([]Entry(nil), i.entries...)
}

// Lookup returns the indexed record for one sensor/event identity. A missing
// entry is not evidence that the event was never ingested.
func (i Index) Lookup(sensorID, eventID string) (Entry, bool) {
	position, ok := i.byEvent[eventKey(sensorID, eventID)]
	if !ok || position < 0 || position >= len(i.entries) {
		return Entry{}, false
	}
	return i.entries[position], true
}

// Index returns the index that was rebuilt when the writer was opened and kept
// current by successful appends. Callers cannot mutate the writer's index.
func (w *Writer) Index() (Index, error) {
	if w == nil {
		return Index{}, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Index{}, ErrClosed
	}
	if w.poisoned {
		return Index{}, ErrRecovery
	}
	return w.snapshotIndex(), nil
}

func (w *Writer) indexEntry(sensorID, eventID string) (Entry, bool) {
	position, ok := w.byEvent[eventKey(sensorID, eventID)]
	if !ok || position < 0 || position >= len(w.indexEntries) {
		return Entry{}, false
	}
	return w.indexEntries[position], true
}

// checkIndexEntry fails closed before bytes change when the candidate would
// make the index ambiguous. An exact repeat is tolerated for compatibility
// with stores that were projected twice before C18.
func (w *Writer) checkIndexEntry(candidate Entry) error {
	if old, ok := w.retired[eventKey(candidate.SensorID, candidate.EventID)]; ok && (old.Digest != candidate.Digest || old.Sequence != candidate.Sequence) {
		return ErrIndexConflict
	}
	existing, ok := w.indexEntry(candidate.SensorID, candidate.EventID)
	if !ok {
		return nil
	}
	if existing.Digest != candidate.Digest || existing.Sequence != candidate.Sequence {
		return ErrIndexConflict
	}
	return nil
}

// recordIndexEntry keeps the first copy of a unique identity. A repeated
// identical record is counted instead of indexed twice; checkIndexEntry has
// already rejected any conflicting record before the bytes were written.
func (w *Writer) recordIndexEntry(entry Entry) {
	key := eventKey(entry.SensorID, entry.EventID)
	if position, ok := w.byEvent[key]; ok {
		existing := w.indexEntries[position]
		if existing.Digest == entry.Digest && existing.Sequence == entry.Sequence {
			w.duplicates++
		}
		return
	}
	position := len(w.indexEntries)
	w.indexEntries = append(w.indexEntries, entry)
	w.byEvent[key] = position
}

// snapshotIndex owns every slice and rebuilds its lookup maps, so returning it
// cannot expose the writer's mutable index.
func (w *Writer) snapshotIndex() Index {
	snapshot := Index{
		Records:    int64(len(w.indexEntries)),
		Duplicates: w.duplicates,
		Missing:    []OrdinalRange{},
		Incomplete: []Segment{},
		entries:    append([]Entry(nil), w.indexEntries...),
	}
	sensors := make(map[string]bool, len(snapshot.entries))
	for _, entry := range snapshot.entries {
		sensors[entry.SensorID] = true
	}
	snapshot.Sensors = len(sensors)
	for position, seg := range w.segments {
		snapshot.SegmentIDs = append(snapshot.SegmentIDs, seg.id)
		if position == 0 {
			snapshot.FirstOrdinal = seg.number
		}
		snapshot.LastOrdinal = seg.number
		if seg.incomplete != nil {
			snapshot.Incomplete = append(snapshot.Incomplete, Segment{
				ID:         seg.id,
				Records:    seg.records,
				Bytes:      seg.bytes,
				Sealed:     seg.kind != kindActive,
				Incomplete: &Incomplete{Offset: seg.incomplete.Offset, Bytes: seg.incomplete.Bytes, Digest: seg.incomplete.Digest},
			})
		}
		if position > 0 {
			previous := w.segments[position-1].number
			if seg.number > previous+1 {
				snapshot.Missing = append(snapshot.Missing, OrdinalRange{After: previous, Before: seg.number})
			}
		}
	}
	for _, op := range w.retention.Operations {
		snapshot.Retention = append(snapshot.Retention, cloneRetention(op.Segments)...)
	}
	snapshot.retired = make(map[[2]string]RetainedEvent, len(w.retired))
	for k, v := range w.retired {
		snapshot.retired[k] = v
	}
	snapshot.Complete = len(snapshot.Missing) == 0 && len(snapshot.Incomplete) == 0 && len(snapshot.Retention) == 0
	snapshot.byEvent = make(map[[2]string]int, len(snapshot.entries))
	for position, entry := range snapshot.entries {
		snapshot.byEvent[eventKey(entry.SensorID, entry.EventID)] = position
	}
	return snapshot
}

// indexRecords adds the complete records of one segment during Open. It is the
// only rebuild path; there is no durable index that could be trusted instead.
func (w *Writer) indexRecords(entries []Entry) error {
	for _, entry := range entries {
		if err := w.checkIndexEntry(entry); err != nil {
			return err
		}
		w.recordIndexEntry(entry)
	}
	return nil
}

func (i Index) Retained(sensorID, eventID string) (RetainedEvent, bool) {
	event, ok := i.retired[eventKey(sensorID, eventID)]
	return event, ok
}
