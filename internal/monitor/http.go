package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/incidents"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

const (
	ingestPath    = "/api/ingest/v1/events"
	heartbeatPath = "/api/ingest/v1/heartbeat"
	teamAPI       = "/api/team/v1/"
	incidentsPath = teamAPI + "incidents"
)

var (
	validID     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	validCursor = regexp.MustCompile(`^[0-9]{10}:segment-[0-9]{20}:[0-9]{20}$`)
	validAsset  = regexp.MustCompile(`^assets/[A-Za-z0-9_.-]+\.(js|css|woff2|svg|png|webp)$`)
)

func Run(ctx context.Context, path string) (result error) {
	var cfg configuration
	if err := readConfig(path, &cfg); err != nil {
		return err
	}
	opScopes, authority, err := cfg.validate()
	if err != nil {
		return err
	}
	sensors, sensorCA, err := cfg.Collector.guard(cfg.Sensors)
	if err != nil {
		return fmt.Errorf("collector identity: %w", err)
	}
	operators, operatorCA, err := cfg.Workspace.guard(opScopes)
	if err != nil {
		return fmt.Errorf("workspace identity: %w", err)
	}
	if sensorCA == operatorCA {
		return errors.New("collector and workspace must use distinct certificate authorities")
	}
	assets, err := os.OpenRoot(cfg.WebDir)
	if err != nil {
		return err
	}
	defer assets.Close()
	index, err := assets.Stat("index.html")
	if err != nil || !index.Mode().IsRegular() {
		return errors.New("workspace web_dir must contain a built index.html")
	}
	j, err := openJournal(cfg.StateDir, journalPolicy{
		retentionHours: cfg.RetentionHours, eventsPerHour: cfg.EventsPerHour,
		maxEventAge: time.Duration(cfg.EventAge) * time.Minute, alertThreshold: cfg.AlertThreshold,
	}, time.Now)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, j.close()) }()
	ingest, err := net.Listen("tcp", cfg.Collector.Listen)
	if err != nil {
		return err
	}
	defer ingest.Close()
	team, err := net.Listen("tcp", cfg.Workspace.Listen)
	if err != nil {
		return err
	}
	defer team.Close()
	collector := boundedServer(j.collector(sensors))
	collector.TLSConfig = sensors.TLSConfig()
	workspace := boundedServer(j.workspace(operators, cfg.Operators, assets, authority, cfg.Origin))
	workspace.TLSConfig = operators.TLSConfig()
	return serveMonitor(ctx, collector, ingest, workspace, team, j)
}

func serveMonitor(ctx context.Context, collector *http.Server, ingest net.Listener, workspace *http.Server, team net.Listener, j *journal) error {
	exits := make(chan error, 2)
	go func() { exits <- collector.ServeTLS(ingest, "", "") }()
	go func() { exits <- workspace.ServeTLS(team, "", "") }()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	var result error
	for result == nil && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case result = <-exits:
			if errors.Is(result, http.ErrServerClosed) {
				result = errors.New("monitoring listener stopped unexpectedly")
			}
		case <-tick.C:
			result = j.maintain()
		}
	}
	return errors.Join(result, shutdown(collector), shutdown(workspace))
}

func boundedServer(handler http.Handler) *http.Server {
	active := make(chan struct{}, 32)
	var connections atomic.Int32
	return &http.Server{
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 12 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				if connections.Add(1) > 128 {
					_ = conn.Close()
				}
			case http.StateClosed, http.StateHijacked:
				connections.Add(-1)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			select {
			case active <- struct{}{}:
				defer func() { <-active }()
				handler.ServeHTTP(w, r)
			default:
				w.Header().Set("Retry-After", "1")
				problem(w, http.StatusServiceUnavailable, "busy")
			}
		}),
	}
}

func shutdown(s *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		return errors.Join(err, s.Close())
	}
	return nil
}

func (j *journal) collector(guard *pki.Guard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != ingestPath && r.URL.Path != heartbeatPath) || r.URL.RawQuery != "" {
			problem(w, 404, "not_found")
			return
		}
		if !method(w, r, http.MethodPost) {
			return
		}
		if r.TLS == nil {
			problem(w, 403, "forbidden_identity")
			return
		}
		identity, err := guard.Verify(*r.TLS)
		if err != nil || len(identity.AllowedScopes) == 0 {
			problem(w, 403, "forbidden_identity")
			return
		}
		if r.URL.Path == heartbeatPath {
			j.receiveHeartbeat(w, r, identity.AllowedScopes)
			return
		}
		body, ok := jsonBody(w, r, contracts.MaxInputBytes)
		if !ok {
			return
		}
		event, raw, err := decodeObservation(r.Context(), body)
		if err != nil {
			problem(w, 422, "invalid_event")
			return
		}
		if !allowed(identity.AllowedScopes, event.SensorID) {
			problem(w, 403, "forbidden_sensor")
			return
		}
		value, replay, err := j.append(r.Context(), event, raw)
		switch {
		case errors.Is(err, errEventAge):
			problem(w, 422, "event_outside_window")
		case errors.Is(err, errEventFuture):
			problem(w, 422, "event_from_future")
		case errors.Is(err, errConflict):
			problem(w, 409, "event_conflict")
		case errors.Is(err, errCapacity):
			w.Header().Set("Retry-After", "60")
			problem(w, 503, "collector_capacity")
		case err != nil:
			problem(w, 503, "collector_unavailable")
		case replay:
			respond(w, 200, value)
		default:
			respond(w, 201, value)
		}
	}
}

func (j *journal) receiveHeartbeat(w http.ResponseWriter, r *http.Request, scopes []string) {
	raw, ok := jsonBody(w, r, 1024)
	if !ok {
		return
	}
	var report sensorHeartbeat
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if !json.Valid(raw) || decoder.Decode(&report) != nil || !contracts.ValidSensorID(report.SensorID) ||
		report.Pending < 0 || report.Pending > 10000 || report.Held < 0 || report.Held > 10000-report.Pending {
		problem(w, 422, "invalid_heartbeat")
		return
	}
	if !allowed(scopes, report.SensorID) {
		problem(w, 403, "forbidden_sensor")
		return
	}
	if err := j.heartbeat(report); err != nil {
		problem(w, 503, "collector_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (j *journal) workspace(guard *pki.Guard, identities map[string]operator, assets *os.Root, authority, origin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		origins := r.Header.Values("Origin")
		if r.Host != authority || len(origins) > 1 || (len(origins) == 1 && origins[0] != origin) ||
			(r.Method != http.MethodGet && r.Method != http.MethodHead && len(origins) != 1) {
			problem(w, 403, "forbidden_origin")
			return
		}
		if r.TLS == nil {
			problem(w, 403, "forbidden_identity")
			return
		}
		identity, err := guard.Verify(*r.TLS)
		op, exists := identities[identity.Fingerprint]
		if err != nil || !exists {
			problem(w, 403, "forbidden_identity")
			return
		}
		op.Sensors = identity.AllowedScopes
		switch {
		case r.URL.Path == teamAPI+"session":
			if method(w, r, http.MethodGet) {
				respond(w, 200, op)
			}
		case r.URL.Path == teamAPI+"sensors":
			if method(w, r, http.MethodGet) {
				status, err := j.sensorStatus(op.Sensors)
				if err != nil {
					problem(w, 503, "workspace_unavailable")
					return
				}
				respond(w, 200, status)
			}
		case r.URL.Path == incidentsPath:
			if method(w, r, http.MethodGet) {
				j.listIncidents(w, r, op)
			}
		case strings.HasPrefix(r.URL.Path, incidentsPath+"/"):
			j.serveIncident(w, r, op)
		case r.URL.Path == "/readyz" || r.URL.Path == "/healthz":
			if method(w, r, http.MethodGet) {
				if r.URL.Path == "/readyz" && j.maintain() != nil {
					problem(w, 503, "workspace_unavailable")
					return
				}
				respond(w, 200, map[string]string{"status": "ok", "profile": "team-monitoring"})
			}
		default:
			serveAsset(w, r, assets)
		}
	}
}

func (j *journal) listIncidents(w http.ResponseWriter, r *http.Request, op operator) {
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 1024 {
		problem(w, 400, "invalid_page")
		return
	}
	for key, values := range params {
		if (key != "limit" && key != "before" && key != "sensor") || len(values) != 1 || values[0] == "" {
			problem(w, 400, "invalid_page")
			return
		}
	}
	before := params.Get("before")
	limit := 20
	if raw := params.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err != nil || limit < 1 || limit > 50 || before != "" && !validCursor.MatchString(before) {
		problem(w, 400, "invalid_page")
		return
	}
	ids := op.Sensors
	if id := params.Get("sensor"); id != "" {
		if !allowed(ids, id) {
			problem(w, 403, "forbidden_sensor")
			return
		}
		ids = []string{id}
	}
	page, err := j.page(ids, before, limit)
	if err != nil {
		problem(w, 503, "workspace_unavailable")
		return
	}
	respond(w, 200, page)
}

func (j *journal) serveIncident(w http.ResponseWriter, r *http.Request, op operator) {
	remainder := strings.TrimPrefix(r.URL.Path, incidentsPath+"/")
	id, action, subroute := strings.Cut(remainder, "/")
	if !validID.MatchString(id) || subroute && action != "triage" || r.URL.RawQuery != "" {
		problem(w, 404, "not_found")
		return
	}
	if !subroute {
		if !method(w, r, http.MethodGet) {
			return
		}
		detail, err := j.detail(r.Context(), op.Sensors, id)
		if err != nil {
			incidentProblem(w, err)
			return
		}
		respond(w, 200, detail)
		return
	}
	if !method(w, r, http.MethodPost) {
		return
	}
	if op.Role != "analyst" {
		problem(w, 403, "forbidden_operation")
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		problem(w, 400, "idempotency_key_required")
		return
	}
	raw, ok := jsonBody(w, r, 4096)
	if !ok {
		return
	}
	value, err := j.triage(r.Context(), op, id, keys[0], raw)
	if err != nil {
		incidentProblem(w, err)
		return
	}
	respond(w, 202, value)
}

func incidentProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		problem(w, 404, "incident_not_found")
	case errors.Is(err, incidents.ErrConflict), errors.Is(err, storage.ErrConflict):
		problem(w, 409, "idempotency_conflict")
	case errors.Is(err, incidents.ErrInvalidInput):
		problem(w, 422, "invalid_triage")
	default:
		problem(w, 503, "workspace_unavailable")
	}
}

func serveAsset(w http.ResponseWriter, r *http.Request, assets *os.Root) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, 405, "method_not_allowed")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	switch name {
	case "runtime-config.json":
		respond(w, 200, map[string]any{
			"projectId": "miragemesh", "apiBasePath": "/api", "engineEnabled": false,
			"maxPreviewBytes": 1048576, "deployment": "team-monitoring",
		})
		return
	case "":
		name = "index.html"
	case "index.html", "icon.svg", "favicon.svg", "manifest.webmanifest":
	default:
		if !fs.ValidPath(name) || !validAsset.MatchString(name) {
			problem(w, 404, "not_found")
			return
		}
	}
	f, err := assets.Open(name)
	if err != nil {
		problem(w, 404, "not_found")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		problem(w, 404, "not_found")
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method == want {
		return true
	}
	w.Header().Set("Allow", want)
	problem(w, 405, "method_not_allowed")
	return false
}

func jsonBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		problem(w, 415, "json_required")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problem(w, 413, "request_too_large")
		} else {
			problem(w, 400, "invalid_body")
		}
		return nil, false
	}
	return raw, true
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func problem(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"error": code})
}
