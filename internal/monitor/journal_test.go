package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

func TestJournalExpiresOldPartitionsWhileAcceptingNewEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "journal")
	now := time.Date(2026, 11, 7, 0, 12, 0, 0, time.UTC)
	firstHour := now.Format(hourFormat)
	policy := journalPolicy{retentionHours: 24, eventsPerHour: 2, maxEventAge: time.Hour, alertThreshold: 2}
	clock := func() time.Time { return now }
	j, err := openJournal(path, policy, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if j != nil {
			_ = j.close()
		}
	}()
	observation := func(n int64) (contracts.Event, []byte) {
		t.Helper()
		event := contracts.Event{SchemaVersion: "1", SensorID: "edge-01", EventID: fmt.Sprintf("event-%d", n),
			Sequence: n, Kind: "http.request", ObservedAt: now.Format(time.RFC3339Nano), Metadata: contracts.HTTPMetadata{Path: "/decoy"}}
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return event, raw
	}
	old, oldRaw := observation(1)
	for n := int64(1); n <= 25; n++ {
		event, raw := observation(n)
		if _, replayed, err := j.append(ctx, event, raw); err != nil || replayed {
			t.Fatalf("hour %d append replay=%t err=%v", n, replayed, err)
		}
		if n == 1 {
			if _, replayed, err := j.append(ctx, event, raw); err != nil || !replayed {
				t.Fatalf("retry should reuse its receipt: replay=%t err=%v", replayed, err)
			}
		}
		if n < 25 {
			now = now.Add(time.Hour)
		}
	}
	if _, err := os.Stat(filepath.Join(path, firstHour)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old partition remains in the active store: %v", err)
	}
	if _, _, err := j.append(ctx, old, oldRaw); !errors.Is(err, errEventAge) {
		t.Fatalf("expired evidence was re-admitted: %v", err)
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	j, err = openJournal(path, policy, clock)
	if err != nil {
		t.Fatal(err)
	}
	page, err := j.page([]string{"edge-01"}, "", 50)
	if err != nil || len(page.Items) != 24 || page.Items[0].Sequence != 25 || page.Items[23].Sequence != 2 {
		t.Fatalf("unexpected retained timeline: %+v, %v", page, err)
	}
}
