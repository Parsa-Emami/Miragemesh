package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidentview"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func TestIncidentsDisabledIsExplicit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, "127.0.0.1:0", writer, nil); writer.Close() }()
	t.Cleanup(func() { cancel(); reader.Close(); <-done })
	var ready struct{ Address string }
	if err := json.NewDecoder(reader).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://" + ready.Address + "/api/v1/incidents")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]string
	json.NewDecoder(response.Body).Decode(&result)
	if response.StatusCode != 503 || result["error"] != "incidents_unavailable" {
		t.Fatalf("disabled incident workflow must be explicit: %d %v", response.StatusCode, result)
	}
}

func TestIncidentHTTPGuardsAndDurableWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	writer, err := events.Open(filepath.Join(root, "segments"), events.Limits{MaxSegments: 8, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	raw, err := os.ReadFile("../../tests/fixtures/miragemesh/C22/positive.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceEvents []string `json:"source_events"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, raw := range fixture.SourceEvents {
		if _, err := sensor.Accept(ctx, store, []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Append(ctx, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	view, err := incidentview.NewView(ctx, store, writer, alerts.Policy{RateLimit: 2, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	reader, ready := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, "127.0.0.1:0", ready, nil, view); ready.Close() }()
	t.Cleanup(func() { cancel(); reader.Close(); <-done })
	var address struct{ Address string }
	if err := json.NewDecoder(reader).Decode(&address); err != nil {
		t.Fatal(err)
	}
	base := "http://" + address.Address
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(base + "/api/v1/incidents")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot incidentview.ViewSnapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || len(snapshot.Incidents) != 4 {
		t.Fatalf("invalid source snapshot: %+v", snapshot)
	}
	id := snapshot.Incidents[0].ID
	body := `{"status":"investigating","reason":"synthetic local review"}`
	manifest := filepath.Join(root, "state", "manifest.json")
	before, _ := os.ReadFile(manifest)
	for _, row := range []struct {
		name, method, path, origin, media, key, body string
		want                                         int
	}{
		{"foreign origin", "POST", "/api/v1/incidents/" + id + "/triage", "https://example.invalid", "application/json", "synthetic-c22-key", body, 403},
		{"absent origin", "POST", "/api/v1/incidents/" + id + "/triage", "", "application/json", "synthetic-c22-key", body, 403},
		{"wrong media", "POST", "/api/v1/incidents/" + id + "/triage", base, "text/plain", "synthetic-c22-key", body, 415},
		{"missing key", "POST", "/api/v1/incidents/" + id + "/triage", base, "application/json", "", body, 422},
		{"duplicate body", "POST", "/api/v1/incidents/" + id + "/triage", base, "application/json", "synthetic-c22-key", `{"status":"x","status":"y","reason":"z"}`, 422},
		{"forged source", "POST", "/api/v1/incidents/" + id + "/triage", base, "application/json", "synthetic-c22-key", `{"status":"x","reason":"z","source":"forged"}`, 422},
		{"unknown incident", "POST", "/api/v1/incidents/incident-" + strings.Repeat("a", 64) + "/triage", base, "application/json", "synthetic-c22-key", body, 404},
		{"oversized body", "POST", "/api/v1/incidents/" + id + "/triage", base, "application/json", "synthetic-c22-key", strings.Repeat("a", 16385), 413},
		{"read method", "HEAD", "/api/v1/incidents", base, "", "", "", 405},
		{"write method", "GET", "/api/v1/incidents/" + id + "/triage", base, "", "", "", 405},
	} {
		t.Run(row.name, func(t *testing.T) {
			request, _ := http.NewRequest(row.method, base+row.path, strings.NewReader(row.body))
			if row.origin != "" {
				request.Header.Set("Origin", row.origin)
			}
			request.Header.Set("Content-Type", row.media)
			if row.key != "" {
				request.Header.Set("Idempotency-Key", row.key)
			}
			result, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, result.Body)
			result.Body.Close()
			if result.StatusCode != row.want {
				t.Fatalf("got %d, want %d", result.StatusCode, row.want)
			}
			after, _ := os.ReadFile(manifest)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected HTTP request changed durable state")
			}
		})
	}
	for index := 0; index < 2; index++ {
		request, _ := http.NewRequest("POST", base+"/api/v1/incidents/"+id+"/triage", strings.NewReader(body))
		request.Header.Set("Origin", base)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "synthetic-c22-committed")
		result, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			Status string `json:"status"`
			Data   struct {
				Replayed bool `json:"replayed"`
			} `json:"data"`
		}
		json.NewDecoder(result.Body).Decode(&value)
		result.Body.Close()
		if result.StatusCode != 202 || value.Status != "accepted" || value.Data.Replayed != (index == 1) {
			t.Fatalf("invalid durable result: %d %+v", result.StatusCode, value)
		}
	}
	current, err := view.Snapshot(ctx)
	if err != nil || len(current.Incidents[0].History) != 1 {
		t.Fatalf("HTTP history missing or duplicated: %+v %v", current, err)
	}
}
