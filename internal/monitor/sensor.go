package monitor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

type sensorConfiguration struct {
	ID              string `json:"sensor_id"`
	Listen          string `json:"listen"`
	HealthListen    string `json:"health_listen"`
	SpoolDir        string `json:"spool_dir"`
	QueueLimit      int    `json:"queue_limit"`
	CollectorOrigin string `json:"collector_origin"`
	CA              string `json:"ca"`
	Certificate     string `json:"certificate"`
	Key             string `json:"key"`
}

func RunSensor(ctx context.Context, path string) (result error) {
	var cfg sensorConfiguration
	if err := readConfig(path, &cfg); err != nil {
		return err
	}
	if !contracts.ValidSensorID(cfg.ID) || cfg.QueueLimit < 1 || cfg.QueueLimit > 10000 || cfg.Listen == cfg.HealthListen {
		return errors.New("invalid sensor identity, queue capacity or listeners")
	}
	if _, err := privateListen(cfg.Listen); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(cfg.HealthListen)
	if _, err := privateListen(cfg.HealthListen); err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("sensor health listener must use a loopback IP")
	}
	origin, err := url.Parse(cfg.CollectorOrigin)
	if err != nil || origin.Scheme != "https" || origin.User != nil || origin.Hostname() == "" ||
		cfg.CollectorOrigin != "https://"+origin.Host {
		return errors.New("collector_origin must be an exact HTTPS origin")
	}
	client, err := cfg.client()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	q, err := openSpool(cfg.SpoolDir, cfg.ID, cfg.QueueLimit)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, q.dir.close()) }()
	decoy, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer decoy.Close()
	health, err := net.Listen("tcp", cfg.HealthListen)
	if err != nil {
		return err
	}
	defer health.Close()
	sensorServer := boundedServer(http.HandlerFunc(q.observe))
	healthServer := boundedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != cfg.HealthListen || (r.URL.Path != "/readyz" && r.URL.Path != "/healthz") || r.URL.RawQuery != "" {
			problem(w, 404, "not_found")
			return
		}
		if !method(w, r, http.MethodGet) {
			return
		}
		state := q.status()
		status := 200
		if r.URL.Path == "/readyz" && (!state.Available || state.Pending+state.Held >= state.Limit ||
			state.Held > 0 || state.DeliveryError != "") {
			status = 503
		}
		respond(w, status, state)
	}))
	return q.serve(ctx, client, cfg.CollectorOrigin, sensorServer, decoy, healthServer, health)
}

func (c sensorConfiguration) client() (*http.Client, error) {
	ca, err := readRegularFile(c.CA, 65536, false)
	if err != nil {
		return nil, err
	}
	cert, err := readRegularFile(c.Certificate, 65536, false)
	if err != nil {
		return nil, err
	}
	key, err := readRegularFile(c.Key, 65536, true)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid collector CA")
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}},
		TLSHandshakeTimeout: 3 * time.Second, MaxIdleConns: 1, IdleConnTimeout: 20 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func (q *sensorSpool) serve(ctx context.Context, client *http.Client, origin string, sensor *http.Server, decoy net.Listener, health *http.Server, probe net.Listener) error {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	exits := make(chan error, 2)
	worker := make(chan error, 1)
	heartbeat := make(chan struct{})
	go func() { exits <- sensor.Serve(decoy) }()
	go func() { exits <- health.Serve(probe) }()
	go func() { worker <- q.ship(workerCtx, client, origin+ingestPath) }()
	go func() {
		defer close(heartbeat)
		q.sendHeartbeats(workerCtx, client, origin+heartbeatPath)
	}()
	var result error
	var workerStopped bool
	select {
	case <-ctx.Done():
	case result = <-exits:
		if errors.Is(result, http.ErrServerClosed) {
			result = errors.New("sensor listener stopped unexpectedly")
		}
	case result = <-worker:
		workerStopped = true
	}
	cancel()
	result = errors.Join(result, shutdown(sensor), shutdown(health))
	if !workerStopped {
		result = errors.Join(result, <-worker)
	}
	<-heartbeat
	q.mu.Lock()
	q.failed = true
	q.mu.Unlock()
	return result
}

func (q *sensorSpool) sendHeartbeats(ctx context.Context, client *http.Client, target string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		state := q.status()
		raw, _ := json.Marshal(sensorHeartbeat{SensorID: q.id, Pending: state.Pending, Held: state.Held})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			if response, err := client.Do(req); err == nil {
				response.Body.Close()
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
		}
	}
}

func (q *sensorSpool) observe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		problem(w, 405, "method_not_allowed")
		return
	}
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 4096)); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problem(w, 413, "request_too_large")
		} else {
			problem(w, 400, "invalid_request")
		}
		return
	}
	switch err := q.enqueue(r.Context(), r.URL.EscapedPath()); {
	case errors.Is(err, errInvalidEvent):
		problem(w, 400, "invalid_request")
	case err != nil:
		problem(w, 503, "observation_unavailable")
	default:
		respond(w, 200, map[string]string{"status": "ok"})
	}
}

func (q *sensorSpool) ship(ctx context.Context, client *http.Client, target string) error {
	delay := 250 * time.Millisecond
	for ctx.Err() == nil {
		name, raw, err := q.peek()
		if err != nil {
			return err
		}
		if name == "" {
			select {
			case <-ctx.Done():
			case <-q.wake:
			}
			continue
		}
		result := sendObservation(ctx, client, target, raw)
		if result == "" || result == "event_outside_window" {
			if err := q.confirm(name, result != ""); err != nil {
				return err
			}
			delay = 250 * time.Millisecond
			continue
		}
		q.deliveryError(result)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
		delay = min(delay*2, 30*time.Second)
	}
	return nil
}

func sendObservation(ctx context.Context, client *http.Client, target string, raw []byte) string {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return "invalid_collector"
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return "collector_unreachable"
	}
	defer response.Body.Close()
	body, err := readLimit(response.Body, 4096)
	if err != nil {
		return "invalid_collector_response"
	}
	if response.StatusCode == 200 || response.StatusCode == 201 {
		var accepted receipt
		event, _, err := decodeObservation(ctx, raw)
		if err != nil || json.Unmarshal(body, &accepted) != nil || accepted.EventID != event.EventID ||
			accepted.Sequence != event.Sequence || accepted.SHA256 != digest(raw) {
			return "invalid_collector_receipt"
		}
		return ""
	}
	if response.StatusCode == 422 {
		var failure struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &failure) == nil && failure.Error == "event_outside_window" {
			return failure.Error
		}
	}
	return fmt.Sprintf("collector_http_%d", response.StatusCode)
}
