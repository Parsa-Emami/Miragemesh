package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

const hourFormat = "2006010215"

var (
	errInvalidEvent = errors.New("invalid monitoring event")
	errEventAge     = errors.New("event outside admission window")
	errEventFuture  = errors.New("event timestamp too far in the future")
	errConflict     = errors.New("event identity conflict")
	errCapacity     = errors.New("hourly event capacity reached")
	errUnavailable  = errors.New("monitoring state unavailable")
	errNotFound     = errors.New("incident not found")
)

type journalPolicy struct {
	retentionHours int
	eventsPerHour  int
	maxEventAge    time.Duration
	alertThreshold int
}

type journal struct {
	mu         sync.Mutex
	dir        *privateDirectory
	policy     journalPolicy
	now        func() time.Time
	buckets    map[string]*bucket
	byID       map[string]*eventEntry
	bySensor   map[string][]*eventEntry
	bySeq      map[sequenceKey]*eventEntry
	heartbeats map[string]sensorHeartbeat
	hour       string
	failed     bool
}

type sequenceKey struct {
	sensor   string
	sequence int64
}

type bucket struct {
	name   string
	events *events.Writer
	audit  *storage.Store
	triage *incidents.Service
	items  []*eventEntry
	counts map[string]int
	gap    bool
}

type eventEntry struct {
	ref    events.Entry
	bucket *bucket
	id     string
	cursor string
}

type receipt struct {
	EventID  string `json:"event_id"`
	Sequence int64  `json:"sequence"`
	SHA256   string `json:"sha256"`
}

type incidentRow struct {
	ID               string `json:"id"`
	SensorID         string `json:"sensor_id"`
	EventID          string `json:"event_id"`
	Sequence         int64  `json:"sequence"`
	Hour             string `json:"received_hour"`
	RateSignal       bool   `json:"rate_signal"`
	CoverageComplete bool   `json:"coverage_complete"`
}

type triageRow struct {
	Status string    `json:"status"`
	Reason string    `json:"reason"`
	Actor  string    `json:"actor"`
	At     time.Time `json:"triaged_at"`
}

type incidentDetail struct {
	Event   contracts.Event `json:"event"`
	SHA256  string          `json:"sha256"`
	History []triageRow     `json:"history"`
}

type incidentPage struct {
	Items []incidentRow `json:"items"`
	Next  string        `json:"next_cursor,omitempty"`
}

type sensorSummary struct {
	ID            string     `json:"id"`
	LastHour      string     `json:"last_received_hour,omitempty"`
	Recent        int        `json:"events_this_hour"`
	Signal        bool       `json:"rate_signal"`
	Online        bool       `json:"online"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	Pending       int        `json:"spool_pending"`
	Held          int        `json:"spool_held"`
}

type sensorHeartbeat struct {
	SensorID string `json:"sensor_id"`
	Pending  int    `json:"pending"`
	Held     int    `json:"held"`
	at       time.Time
}

func openJournal(path string, policy journalPolicy, now func() time.Time) (*journal, error) {
	dir, err := openPrivateDirectory(path)
	if err != nil {
		return nil, err
	}
	j := &journal{
		dir: dir, policy: policy, now: now,
		buckets: make(map[string]*bucket), byID: make(map[string]*eventEntry),
		bySensor: make(map[string][]*eventEntry), bySeq: make(map[sequenceKey]*eventEntry),
		heartbeats: make(map[string]sensorHeartbeat),
		hour:       now().UTC().Format(hourFormat),
	}
	if err := j.reopen(); err != nil {
		j.close()
		return nil, err
	}
	return j, nil
}

func (j *journal) reopen() error {
	items, err := fs.ReadDir(j.dir.root.FS(), ".")
	if err != nil {
		return err
	}
	for _, item := range items {
		name := item.Name()
		if name == ".lock" {
			continue
		}
		expired := strings.HasPrefix(name, ".expired-")
		hour := strings.TrimPrefix(name, ".expired-")
		if _, err := time.Parse(hourFormat, hour); err != nil || !item.IsDir() || hour > j.hour {
			return errors.New("unexpected monitoring state entry or clock rollback")
		}
		info, err := item.Info()
		if err != nil || !owned(info, fs.ModeDir|0700) {
			return errors.New("unsafe monitoring state partition")
		}
		if expired || hour < j.cutoff(j.now()) {
			if err := j.removePartition(name); err != nil {
				return err
			}
			continue
		}
		b, err := j.openBucket(name)
		if err != nil {
			return err
		}
		index, err := b.events.Index()
		if err != nil {
			return err
		}
		if index.Records > int64(j.policy.eventsPerHour) || index.Duplicates > 0 {
			return errors.New("existing partition exceeds policy or contains duplicate records")
		}
		b.gap = !index.Complete
		for _, ref := range index.Entries() {
			if err := j.index(b, ref); err != nil {
				return err
			}
		}
	}
	return nil
}

func (j *journal) openBucket(hour string) (*bucket, error) {
	if err := j.dir.root.Mkdir(hour, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	writer, err := events.Open(filepath.Join(j.dir.path, hour, "events"), events.Limits{
		MaxSegments: j.policy.eventsPerHour + 2, MaxRecordsPerSegment: 512, MaxBytesPerSegment: 1 << 20,
	})
	if err != nil {
		return nil, err
	}
	b := &bucket{name: hour, events: writer, counts: make(map[string]int)}
	j.buckets[hour] = b
	return b, errors.Join(j.dir.syncAt(hour), j.dir.sync())
}

func (j *journal) index(b *bucket, ref events.Entry) error {
	identity, err := json.Marshal([2]string{ref.SensorID, ref.EventID})
	if err != nil {
		return err
	}
	id := digest(identity)
	seq := sequenceKey{ref.SensorID, ref.Sequence}
	if j.byID[id] != nil || j.bySeq[seq] != nil {
		return errConflict
	}
	item := &eventEntry{ref: ref, bucket: b, id: id, cursor: fmt.Sprintf("%s:%s:%020d", b.name, ref.Segment, ref.Record)}
	j.byID[id], j.bySeq[seq] = item, item
	j.bySensor[ref.SensorID] = append(j.bySensor[ref.SensorID], item)
	b.items = append(b.items, item)
	b.counts[ref.SensorID]++
	return nil
}

func (j *journal) cutoff(now time.Time) string {
	return now.UTC().Add(-time.Duration(j.policy.retentionHours-1) * time.Hour).Format(hourFormat)
}

func (j *journal) removePartition(name string) error {
	if !strings.HasPrefix(name, ".expired-") {
		expired := ".expired-" + name
		if err := j.dir.root.Rename(name, expired); err != nil {
			return err
		}
		if err := j.dir.sync(); err != nil {
			return err
		}
		name = expired
	}
	if err := j.dir.root.RemoveAll(name); err != nil {
		return err
	}
	return j.dir.sync()
}

func (j *journal) maintain() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.rotate(j.now())
}

func (j *journal) rotate(now time.Time) error {
	hour := now.UTC().Format(hourFormat)
	if j.failed || hour < j.hour {
		return errUnavailable
	}
	if hour == j.hour {
		return nil
	}
	cutoff := j.cutoff(now)
	for name, b := range j.buckets {
		if name >= cutoff {
			continue
		}
		if err := b.close(); err != nil {
			j.failed = true
			return err
		}
		if err := j.removePartition(name); err != nil {
			j.failed = true
			return err
		}
		for _, item := range b.items {
			delete(j.byID, item.id)
			delete(j.bySeq, sequenceKey{item.ref.SensorID, item.ref.Sequence})
		}
		delete(j.buckets, name)
	}
	for id, items := range j.bySensor {
		first := sort.Search(len(items), func(i int) bool { return items[i].bucket.name >= cutoff })
		if first == len(items) {
			delete(j.bySensor, id)
		} else if first > 0 {
			j.bySensor[id] = append([]*eventEntry(nil), items[first:]...)
		}
	}
	j.hour = hour
	return nil
}

func (j *journal) append(ctx context.Context, event contracts.Event, raw []byte) (receipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	if err := j.rotate(now); err != nil {
		return receipt{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return receipt{}, false, err
	}
	result := receipt{EventID: event.EventID, Sequence: event.Sequence, SHA256: digest(raw)}
	identity, _ := json.Marshal([2]string{event.SensorID, event.EventID})
	previous := j.byID[digest(identity)]
	if previous != nil {
		if previous.ref.Digest != result.SHA256 || previous.ref.Sequence != event.Sequence {
			return receipt{}, false, errConflict
		}
		return result, true, nil
	}
	if j.bySeq[sequenceKey{event.SensorID, event.Sequence}] != nil {
		return receipt{}, false, errConflict
	}
	at, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if err != nil || at.Before(now.Add(-j.policy.maxEventAge)) {
		return receipt{}, false, errEventAge
	}
	if at.After(now.Add(2 * time.Minute)) {
		return receipt{}, false, errEventFuture
	}
	b := j.buckets[j.hour]
	if b == nil {
		b, err = j.openBucket(j.hour)
		if err != nil {
			j.failed = true
			return receipt{}, false, err
		}
	}
	if len(b.items) >= j.policy.eventsPerHour {
		return receipt{}, false, errCapacity
	}
	ref, err := b.events.Append(ctx, raw)
	if err != nil {
		if errors.Is(err, events.ErrIO) || errors.Is(err, events.ErrRecovery) {
			j.failed = true
		}
		return receipt{}, false, err
	}
	if err := j.index(b, events.Entry{
		SensorID: ref.SensorID, EventID: ref.EventID, Sequence: ref.Sequence,
		Segment: ref.Segment, Record: ref.Record, Digest: ref.Digest, Bytes: ref.Bytes,
	}); err != nil {
		j.failed = true
		return receipt{}, false, err
	}
	return result, false, nil
}

func (j *journal) page(sensors []string, before string, limit int) (incidentPage, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.rotate(j.now()); err != nil {
		return incidentPage{}, err
	}
	items := make([]*eventEntry, 0, len(sensors)*(limit+1))
	for _, id := range sensors {
		rows := j.bySensor[id]
		end := len(rows)
		if before != "" {
			end = sort.Search(end, func(i int) bool { return rows[i].cursor >= before })
		}
		items = append(items, rows[max(0, end-limit-1):end]...)
	}
	sort.Slice(items, func(a, b int) bool { return items[a].cursor > items[b].cursor })
	page := incidentPage{Items: make([]incidentRow, 0, min(limit, len(items)))}
	for _, item := range items[:min(limit, len(items))] {
		hour, _ := time.Parse(hourFormat, item.bucket.name)
		page.Items = append(page.Items, incidentRow{
			ID: item.id, SensorID: item.ref.SensorID, EventID: item.ref.EventID, Sequence: item.ref.Sequence,
			Hour: hour.Format(time.RFC3339), RateSignal: item.bucket.counts[item.ref.SensorID] >= j.policy.alertThreshold,
			CoverageComplete: !item.bucket.gap,
		})
	}
	if len(items) > limit {
		page.Next = items[limit-1].cursor
	}
	return page, nil
}

func (j *journal) sensorStatus(sensors []string) ([]sensorSummary, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	if err := j.rotate(now); err != nil {
		return nil, err
	}
	result := make([]sensorSummary, 0, len(sensors))
	for _, id := range sensors {
		row := sensorSummary{ID: id}
		if heartbeat, ok := j.heartbeats[id]; ok {
			row.LastHeartbeat = &heartbeat.at
			row.Online = now.Sub(heartbeat.at) < 45*time.Second && !now.Before(heartbeat.at)
			row.Pending, row.Held = heartbeat.Pending, heartbeat.Held
		}
		if items := j.bySensor[id]; len(items) > 0 {
			at, _ := time.Parse(hourFormat, items[len(items)-1].bucket.name)
			row.LastHour = at.Format(time.RFC3339)
		}
		if b := j.buckets[j.hour]; b != nil {
			row.Recent = b.counts[id]
			row.Signal = row.Recent >= j.policy.alertThreshold
		}
		result = append(result, row)
	}
	return result, nil
}

func (j *journal) heartbeat(report sensorHeartbeat) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	if err := j.rotate(now); err != nil {
		return err
	}
	report.at = now.UTC()
	j.heartbeats[report.SensorID] = report
	return nil
}

func (j *journal) detail(ctx context.Context, sensors []string, id string) (incidentDetail, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.rotate(j.now()); err != nil {
		return incidentDetail{}, err
	}
	item := j.byID[id]
	if item == nil || !allowed(sensors, item.ref.SensorID) {
		return incidentDetail{}, errNotFound
	}
	raw, err := item.bucket.events.Read(ctx, item.ref)
	if err != nil {
		return incidentDetail{}, err
	}
	event, failure := contracts.DecodeEvent(ctx, raw)
	if failure != nil {
		return incidentDetail{}, errUnavailable
	}
	detail := incidentDetail{Event: event, SHA256: item.ref.Digest, History: []triageRow{}}
	if _, err := j.dir.root.Stat(filepath.Join(item.bucket.name, "triage")); errors.Is(err, fs.ErrNotExist) {
		return detail, nil
	} else if err != nil {
		return incidentDetail{}, err
	}
	if err := j.openAudit(ctx, item.bucket); err != nil {
		return incidentDetail{}, err
	}
	history, err := item.bucket.triage.History(ctx, id)
	if err != nil {
		return incidentDetail{}, err
	}
	for _, entry := range history {
		detail.History = append(detail.History, triageRow{entry.Status, entry.Reason, entry.Actor, entry.TriagedAt})
	}
	return detail, nil
}

func (j *journal) triage(ctx context.Context, operator operator, id, key string, raw []byte) (triageRow, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.rotate(j.now()); err != nil {
		return triageRow{}, err
	}
	item := j.byID[id]
	if item == nil || !allowed(operator.Sensors, item.ref.SensorID) {
		return triageRow{}, errNotFound
	}
	if err := j.openAudit(ctx, item.bucket); err != nil {
		return triageRow{}, err
	}
	result, err := item.bucket.triage.TriageAs(ctx, id, operator.ID, key, raw)
	if err != nil {
		return triageRow{}, err
	}
	row := result.Entry
	return triageRow{row.Status, row.Reason, row.Actor, row.TriagedAt}, nil
}

func (j *journal) openAudit(ctx context.Context, b *bucket) error {
	if b.triage != nil {
		return nil
	}
	audit, err := storage.Open(filepath.Join(j.dir.path, b.name, "triage"), storage.Limits{
		MaxOperations: 512, MaxBytes: 1 << 20, MaxManifestBytes: 1 << 20,
	})
	if err != nil {
		return err
	}
	if err := j.dir.syncAt(b.name); err != nil {
		audit.Close()
		return err
	}
	svc, err := incidents.New(ctx, audit)
	if err != nil {
		audit.Close()
		return err
	}
	b.audit, b.triage = audit, svc
	return nil
}

func (b *bucket) close() error {
	var err error
	if b.audit != nil {
		err = b.audit.Close()
	}
	return errors.Join(err, b.events.Close())
}

func (j *journal) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failed = true
	var err error
	for _, b := range j.buckets {
		err = errors.Join(err, b.close())
	}
	return errors.Join(err, j.dir.close())
}

func decodeObservation(ctx context.Context, raw []byte) (contracts.Event, []byte, error) {
	raw = bytes.TrimRight(raw, "\n")
	event, failure := contracts.DecodeEvent(ctx, raw)
	if failure != nil || event.Sequence < 1 || len(event.Metadata.Path) > 512 ||
		!strings.HasPrefix(event.Metadata.Path, "/") || strings.ContainsAny(event.Metadata.Path, "?#") ||
		strings.ContainsFunc(event.Metadata.Path, func(r rune) bool { return r < 32 || r == 127 }) {
		return contracts.Event{}, nil, errInvalidEvent
	}
	return event, raw, nil
}
