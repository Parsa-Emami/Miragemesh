package monitor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

type sensorSpool struct {
	mu        sync.Mutex
	dir       *privateDirectory
	id        string
	limit     int
	sequence  int64
	pending   []string
	held      int
	wake      chan struct{}
	failed    bool
	lastError string
}

type spoolStatus struct {
	Pending       int    `json:"pending"`
	Held          int    `json:"held"`
	Limit         int    `json:"limit"`
	DeliveryError string `json:"delivery_error,omitempty"`
	Available     bool   `json:"available"`
}

func openSpool(path, id string, limit int) (*sensorSpool, error) {
	dir, err := openPrivateDirectory(path)
	if err != nil {
		return nil, err
	}
	q := &sensorSpool{dir: dir, id: id, limit: limit, wake: make(chan struct{}, 1)}
	if err := q.recover(); err != nil {
		dir.close()
		return nil, err
	}
	return q, nil
}

func (q *sensorSpool) recover() error {
	if err := q.dir.root.Remove(".stage"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	items, err := fs.ReadDir(q.dir.root.FS(), ".")
	if err != nil {
		return err
	}
	id, err := q.dir.read("sensor-id", 512)
	if errors.Is(err, fs.ErrNotExist) && len(items) == 1 {
		if err := q.dir.replace("sensor-id", []byte(q.id)); err != nil {
			return err
		}
	} else if err != nil || string(id) != q.id {
		return errors.New("spool sensor identity does not match configuration")
	}
	state, err := q.dir.read("sequence", 20)
	if err == nil {
		n, err := strconv.ParseInt(string(state), 10, 64)
		if err != nil || n < 1 || n > contracts.MaxSequence || strconv.FormatInt(n, 10) != string(state) {
			return errors.New("invalid spool sequence")
		}
		q.sequence = n
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	seen := make(map[int64]bool)
	for _, item := range items {
		name := item.Name()
		switch name {
		case ".lock", "sequence", "sensor-id":
			continue
		}
		kind, sequence, ok := spoolFilename(name)
		if !ok || sequence > q.sequence || seen[sequence] || len(q.pending)+q.held >= q.limit {
			return errors.New("invalid spool record or spool exceeds configured limit")
		}
		raw, err := q.dir.read(name, contracts.MaxInputBytes)
		if err != nil {
			return err
		}
		event, _, err := decodeObservation(context.Background(), raw)
		if err != nil || event.SensorID != q.id || event.Sequence != sequence {
			return errors.New("invalid observation in sensor spool")
		}
		seen[sequence] = true
		if kind == "pending" {
			q.pending = append(q.pending, name)
		} else {
			q.held++
		}
	}
	return q.dir.sync()
}

func spoolFilename(name string) (string, int64, bool) {
	kind, rest, ok := strings.Cut(name, "-")
	number, suffix := strings.CutSuffix(rest, ".json")
	sequence, err := strconv.ParseInt(number, 10, 64)
	return kind, sequence, ok && suffix && (kind == "pending" || kind == "held") &&
		err == nil && sequence >= 1 && sequence <= contracts.MaxSequence && fmt.Sprintf("%016d", sequence) == number
}

func (q *sensorSpool) enqueue(ctx context.Context, path string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed {
		return errUnavailable
	}
	if len(q.pending)+q.held >= q.limit || q.sequence == contracts.MaxSequence {
		return errCapacity
	}
	event := contracts.Event{
		SchemaVersion: contracts.SchemaVersion, SensorID: q.id, EventID: "obs-" + rand.Text(),
		Sequence: q.sequence + 1, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Kind: "http.request", Metadata: contracts.HTTPMetadata{Path: path},
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, _, err := decodeObservation(ctx, raw); err != nil {
		return err
	}
	name := fmt.Sprintf("pending-%016d.json", event.Sequence)
	if err := q.dir.replace("sequence", []byte(strconv.FormatInt(event.Sequence, 10))); err != nil {
		q.failed = true
		return err
	}
	q.sequence = event.Sequence
	if err := q.dir.replace(name, raw); err != nil {
		q.failed = true
		return err
	}
	q.pending = append(q.pending, name)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *sensorSpool) peek() (string, []byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed {
		return "", nil, errUnavailable
	}
	if len(q.pending) == 0 {
		return "", nil, nil
	}
	name := q.pending[0]
	raw, err := q.dir.read(name, contracts.MaxInputBytes)
	return name, raw, err
}

func (q *sensorSpool) confirm(name string, hold bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed || len(q.pending) == 0 || q.pending[0] != name {
		return errUnavailable
	}
	var err error
	if hold {
		err = q.dir.root.Rename(name, "held-"+strings.TrimPrefix(name, "pending-"))
	} else {
		err = q.dir.root.Remove(name)
	}
	if err == nil {
		err = q.dir.sync()
	}
	if err != nil {
		q.failed = true
		return err
	}
	q.pending = q.pending[1:]
	if hold {
		q.held++
	}
	q.lastError = ""
	return nil
}

func (q *sensorSpool) deliveryError(code string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lastError = code
}

func (q *sensorSpool) status() spoolStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	return spoolStatus{len(q.pending), q.held, q.limit, q.lastError, !q.failed}
}
