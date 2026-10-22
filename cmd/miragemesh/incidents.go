package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/alerts"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/incidentview"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type incidentOptions struct {
	StateDir      string
	SegmentsDir   string
	StorageLimits storage.Limits
	SegmentLimits events.Limits
	RateLimit     int
	WindowSeconds int
}

func incidentFlags() *incidentOptions {
	options := &incidentOptions{}
	flag.StringVar(&options.StateDir, "incident-state-dir", "", "existing C05 directory for local incident triage")
	flag.StringVar(&options.SegmentsDir, "incident-segments-dir", "", "existing event segment directory for local replay")
	flag.IntVar(&options.StorageLimits.MaxOperations, "incident-max-operations", 0, "explicit C05 operation limit")
	flag.Int64Var(&options.StorageLimits.MaxBytes, "incident-max-bytes", 0, "explicit C05 byte limit")
	flag.Int64Var(&options.StorageLimits.MaxManifestBytes, "incident-max-manifest-bytes", 0, "explicit C05 manifest limit")
	flag.IntVar(&options.SegmentLimits.MaxSegments, "incident-segments-max-count", 0, "explicit segment count limit")
	flag.Int64Var(&options.SegmentLimits.MaxRecordsPerSegment, "incident-segments-max-records", 0, "explicit record limit per segment")
	flag.Int64Var(&options.SegmentLimits.MaxBytesPerSegment, "incident-segments-max-bytes", 0, "explicit byte limit per segment")
	flag.IntVar(&options.RateLimit, "incident-rate-limit", 0, "operator request count for incident rate findings")
	flag.IntVar(&options.WindowSeconds, "incident-window-seconds", 0, "operator whole-second rate window")
	return options
}

func incidentConfigured() bool {
	configured := false
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "incident-") {
			configured = true
		}
	})
	return configured
}

func openIncidentView(options incidentOptions, shared *storage.Store) (*incidentview.View, func(), error) {
	invalid := errors.New("invalid local incident configuration")
	if options.StateDir == "" || options.SegmentsDir == "" || segmentPathsConflict(options.StateDir, options.SegmentsDir) || options.RateLimit <= 0 || options.WindowSeconds <= 0 || int64(options.WindowSeconds) > int64(^uint64(0)>>1)/int64(time.Second) {
		return nil, nil, invalid
	}
	if requireExistingC05Store(options.StateDir) != nil {
		return nil, nil, invalid
	}
	segmentsPath, err := filepath.EvalSymlinks(options.SegmentsDir)
	if err != nil || segmentPathsConflict(options.StateDir, segmentsPath) {
		return nil, nil, invalid
	}
	store := shared
	if store == nil {
		store, err = storage.Open(options.StateDir, options.StorageLimits)
		if err != nil {
			return nil, nil, invalid
		}
	}
	closeStore := func() {
		if shared == nil {
			store.Close()
		}
	}
	writer, err := events.Open(options.SegmentsDir, options.SegmentLimits)
	if err != nil {
		closeStore()
		return nil, nil, invalid
	}
	closeAll := func() { writer.Close(); closeStore() }
	view, err := incidentview.NewView(context.Background(), store, writer, alerts.Policy{RateLimit: options.RateLimit, Window: time.Duration(options.WindowSeconds) * time.Second})
	if err != nil {
		closeAll()
		return nil, nil, invalid
	}
	return view, closeAll, nil
}

func serveIncidents(w http.ResponseWriter, r *http.Request, view *incidentview.View) bool {
	path := r.URL.Path
	list := path == "/api/v1/incidents"
	triage := strings.HasPrefix(path, "/api/v1/incidents/") && strings.HasSuffix(path, "/triage")
	if !list && !triage {
		return false
	}
	fail := func(code int, message string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
	}
	method := http.MethodGet
	if triage {
		method = http.MethodPost
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(405, "method_not_allowed")
		return true
	}
	if view == nil {
		fail(503, "incidents_unavailable")
		return true
	}
	if list {
		snapshot, err := view.Snapshot(r.Context())
		if err != nil {
			fail(503, "incidents_unavailable")
			return true
		}
		json.NewEncoder(w).Encode(snapshot)
		return true
	}
	if r.Header.Get("Origin") != "http://"+r.Host {
		fail(403, "forbidden_origin")
		return true
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail(415, "json_required")
		return true
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/incidents/"), "/triage")
	if !strings.HasPrefix(id, "incident-") || len(id) != 73 || strings.Contains(id, "/") {
		fail(404, "incident_not_found")
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, contracts.MaxStoredInputBytes))
	if err != nil {
		fail(413, "request_too_large")
		return true
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		fail(422, "invalid_triage")
		return true
	}
	result, err := view.Triage(r.Context(), id, keys[0], body)
	switch {
	case errors.Is(err, incidentview.ErrNotFound):
		fail(404, "incident_not_found")
	case errors.Is(err, incidents.ErrInvalidInput):
		fail(422, "invalid_triage")
	case errors.Is(err, incidents.ErrConflict):
		fail(409, "idempotency_conflict")
	case err != nil:
		fail(503, "triage_unavailable")
	default:
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"request_id": result.Receipt.OperationID, "operation_id": result.Receipt.OperationID, "resource_id": id, "status": "accepted", "data": map[string]any{"replayed": result.Replayed}})
	}
	return true
}
