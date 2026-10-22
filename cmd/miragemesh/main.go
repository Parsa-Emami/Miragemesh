package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/incidentview"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/sensorview"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

const version = "0.0.1"

func health() map[string]any {
	return map[string]any{"status": "ok", "scope": "engine-runtime", "version": version, "toolchain": runtime.Version(), "coreReady": false}
}

type sensorStatusReader interface {
	Snapshot(context.Context, time.Time) (sensorview.Snapshot, error)
}

type localSensorStatus struct {
	store   *storage.Store
	applier *sensor.Applier
}

func (s *localSensorStatus) Snapshot(ctx context.Context, now time.Time) (sensorview.Snapshot, error) {
	return sensorview.BuildSnapshot(ctx, s.store, s.applier, now)
}

func serve(ctx context.Context, address string, ready io.Writer, sensorStatus sensorStatusReader, incidentViews ...*incidentview.View) error {
	var incidentView *incidentview.View
	if len(incidentViews) > 0 {
		incidentView = incidentViews[0]
	}
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 0 || number > 65535 || (host != "127.0.0.1" && host != "::1") {
		return errors.New("engine listen address must be loopback with a valid port")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Type", "application/json")
			host, rawPort, hostErr := net.SplitHostPort(r.Host)
			if hostErr != nil && listener.Addr().(*net.TCPAddr).Port == 80 {
				host, rawPort, hostErr = r.Host, "80", nil
				if host == "[::1]" {
					host = "::1"
				}
			}
			origins := r.Header.Values("Origin")
			if hostErr != nil || (host != "127.0.0.1" && host != "::1" && host != "localhost") || rawPort != strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) ||
				(len(origins) != 0 && (len(origins) != 1 || origins[0] != "http://"+r.Host)) {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"error":"forbidden_origin"}`)
				return
			}
			if serveIncidents(w, r, incidentView) {
				return
			}
			if r.URL.Path != "/healthz" {
				if r.URL.Path == "/api/v1/sensors" {
					if r.Method != http.MethodGet {
						w.Header().Set("Allow", http.MethodGet)
						w.WriteHeader(http.StatusMethodNotAllowed)
						io.WriteString(w, `{"error":"method_not_allowed"}`)
						return
					}
					if sensorStatus == nil {
						w.WriteHeader(http.StatusServiceUnavailable)
						io.WriteString(w, `{"error":"sensor_status_unavailable"}`)
						return
					}
					snapshot, err := sensorStatus.Snapshot(r.Context(), time.Now().UTC())
					if err != nil {
						w.WriteHeader(http.StatusServiceUnavailable)
						io.WriteString(w, `{"error":"sensor_status_unavailable"}`)
						return
					}
					if err := json.NewEncoder(w).Encode(snapshot); err != nil {
						return
					}
					return
				}
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"not_found"}`)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				io.WriteString(w, `{"error":"method_not_allowed"}`)
				return
			}
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(health())
			}
		}),
	}
	if err := json.NewEncoder(ready).Encode(map[string]any{"service": "miragemesh-engine", "address": listener.Addr().String(), "pid": os.Getpid()}); err != nil {
		return err
	}
	stopped := make(chan error, 1)
	served := make(chan struct{})
	defer close(served)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(shutdown)
			if err != nil {
				server.Close()
			}
			stopped <- err
		case <-served:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return <-stopped
	}
	return err
}

func main() {
	incidentOptions := incidentFlags()
	address := flag.String("listen", "127.0.0.1:0", "loopback listen address")
	showVersion := flag.Bool("version", false, "print runtime version and exit")
	validate := flag.Bool("validate-event", false, "validate one v1 event from stdin without accepting or storing it")
	isolation := flag.Bool("decoy-isolation", false, "start the isolated decoy container and report the verified isolation state")
	image := flag.String("decoy-image", "", "digest pinned image of the isolated decoy")
	artifact := flag.String("decoy-artifact", "", "host path of the decoy process, mounted read-only")
	state := flag.String("decoy-state", "", "host path of the durable state of the decoy, mounted writable")
	memory := flag.Int64("decoy-memory-bytes", 0, "hard memory limit of the isolated decoy")
	processes := flag.Int("decoy-pids-limit", 0, "hard process limit of the isolated decoy")
	decoyName := flag.String("decoy-name", "miragemesh-decoy", "name of the isolated decoy container")
	decoyListen := flag.String("decoy-listen", "127.0.0.1:8080", "address the decoy binds inside its own namespace")
	projectMode := flag.Bool("project-segments", false, "project the existing C05 snapshot into immutable segments and exit")
	storageDir := flag.String("storage-dir", "", "existing C05 storage directory for --project-segments")
	segmentsDir := flag.String("segments-dir", "", "immutable segment directory for --project-segments")
	storageMaxOperations := flag.Int("storage-max-operations", 0, "maximum C05 operations for --project-segments")
	storageMaxBytes := flag.Int64("storage-max-bytes", 0, "maximum C05 bytes for --project-segments")
	storageMaxManifestBytes := flag.Int64("storage-max-manifest-bytes", 0, "maximum C05 manifest bytes for --project-segments")
	segmentsMaxCount := flag.Int("segments-max-count", 0, "maximum immutable segments for --project-segments")
	segmentsMaxRecords := flag.Int64("segments-max-records", 0, "maximum records per segment for --project-segments")
	segmentsMaxBytes := flag.Int64("segments-max-bytes", 0, "maximum bytes per segment for --project-segments")
	alertsRateLimit := flag.Int("alerts-rate-limit", 0, "required HTTP request count for --project-segments alert derivation")
	alertsWindowSeconds := flag.Int("alerts-window-seconds", 0, "required whole-second rate window for --project-segments alert derivation")
	sensorStatusDir := flag.String("sensor-status-dir", "", "existing or new C05 directory for read-only sensor status")
	sensorStatusMaxOperations := flag.Int("sensor-status-max-operations", 0, "explicit C05 operation limit for sensor status")
	sensorStatusMaxBytes := flag.Int64("sensor-status-max-bytes", 0, "explicit C05 byte limit for sensor status")
	sensorStatusMaxManifestBytes := flag.Int64("sensor-status-max-manifest-bytes", 0, "explicit C05 manifest byte limit for sensor status")
	sensorConfigPublicKey := flag.String("sensor-config-public-key", "", "raw 32-byte Ed25519 public key file for applied sensor configuration")
	sensorConfigMaxSensors := flag.Int("sensor-config-max-sensors", 0, "explicit C10 sensor limit for status verification")
	sensorConfigMinHeartbeat := flag.Int("sensor-config-min-heartbeat-seconds", 0, "explicit C10 minimum heartbeat setting")
	sensorConfigMaxHeartbeat := flag.Int("sensor-config-max-heartbeat-seconds", 0, "explicit C10 maximum heartbeat setting")
	sensorConfigMinSpool := flag.Int("sensor-config-min-spool-limit-events", 0, "explicit C10 minimum spool limit")
	sensorConfigMaxSpool := flag.Int("sensor-config-max-spool-limit-events", 0, "explicit C10 maximum spool limit")
	sensorConfigMinBatch := flag.Int("sensor-config-min-event-batch-limit", 0, "explicit C10 minimum event batch limit")
	sensorConfigMaxBatch := flag.Int("sensor-config-max-event-batch-limit", 0, "explicit C10 maximum event batch limit")
	flag.Parse()
	hasIncidents := incidentConfigured()
	if hasIncidents && (*projectMode || *isolation || *showVersion || *validate) {
		fmt.Fprintln(os.Stderr, "incident configuration requires the local HTTP runtime")
		os.Exit(2)
	}
	validationFlag := false
	projectConfig := false
	alertsConfig := false
	sensorStatusConfigured := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "validate-event" {
			validationFlag = true
		}
		switch f.Name {
		case "storage-dir", "segments-dir", "storage-max-operations", "storage-max-bytes",
			"storage-max-manifest-bytes", "segments-max-count", "segments-max-records", "segments-max-bytes":
			projectConfig = true
		case "alerts-rate-limit", "alerts-window-seconds":
			projectConfig = true
			alertsConfig = true
		case "sensor-status-dir", "sensor-status-max-operations", "sensor-status-max-bytes", "sensor-status-max-manifest-bytes",
			"sensor-config-public-key", "sensor-config-max-sensors", "sensor-config-min-heartbeat-seconds", "sensor-config-max-heartbeat-seconds",
			"sensor-config-min-spool-limit-events", "sensor-config-max-spool-limit-events", "sensor-config-min-event-batch-limit", "sensor-config-max-event-batch-limit":
			sensorStatusConfigured = true
		}
	})
	if validationFlag {
		if !*validate || len(os.Args) != 2 || os.Args[1] != "--validate-event" {
			fmt.Fprintln(os.Stderr, "--validate-event must be used alone")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, contracts.ValidationTimeout)
		defer cancel()
		result := contracts.Validate(ctx, os.Stdin, version)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "Unable to write validation result")
			os.Exit(1)
		}
		if !result.Result.Valid {
			os.Exit(1)
		}
		return
	}
	if projectConfig && !*projectMode {
		fmt.Fprintln(os.Stderr, "--storage-dir and segment limits require --project-segments")
		os.Exit(2)
	}
	if *projectMode {
		if *isolation || *showVersion || sensorStatusConfigured {
			fmt.Fprintln(os.Stderr, "--project-segments cannot be combined with another engine mode")
			os.Exit(2)
		}
		if flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "unexpected engine arguments")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		os.Exit(runSegmentProjection(ctx, segmentProjectionOptions{
			StorageDir:  *storageDir,
			SegmentsDir: *segmentsDir,
			StorageLimits: storage.Limits{
				MaxOperations:    *storageMaxOperations,
				MaxBytes:         *storageMaxBytes,
				MaxManifestBytes: *storageMaxManifestBytes,
			},
			SegmentLimits: events.Limits{
				MaxSegments:          *segmentsMaxCount,
				MaxRecordsPerSegment: *segmentsMaxRecords,
				MaxBytesPerSegment:   *segmentsMaxBytes,
			},
			AlertsRequested:     alertsConfig,
			AlertsRateLimit:     *alertsRateLimit,
			AlertsWindowSeconds: *alertsWindowSeconds,
		}))
	}
	if *isolation {
		if sensorStatusConfigured {
			fmt.Fprintln(os.Stderr, "sensor status configuration cannot be combined with decoy isolation")
			os.Exit(2)
		}
		// The runtime calls of the workflow follow the signals of the
		// operator, so an interrupted command rolls its container back.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		os.Exit(runIsolation(ctx, isolationOptions{
			Image:       *image,
			Artifact:    *artifact,
			State:       *state,
			MemoryBytes: *memory,
			PidsLimit:   *processes,
			Name:        *decoyName,
			Listen:      *decoyListen,
		}))
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected engine arguments")
		os.Exit(2)
	}
	if *showVersion {
		if sensorStatusConfigured {
			fmt.Fprintln(os.Stderr, "sensor status configuration cannot be combined with --version")
			os.Exit(2)
		}
		json.NewEncoder(os.Stdout).Encode(health())
		return
	}
	var sensorStatus sensorStatusReader
	var sharedStore *storage.Store
	if sensorStatusConfigured {
		local, err := openSensorStatus(sensorStatusOptions{
			directory:     *sensorStatusDir,
			limits:        storage.Limits{MaxOperations: *sensorStatusMaxOperations, MaxBytes: *sensorStatusMaxBytes, MaxManifestBytes: *sensorStatusMaxManifestBytes},
			publicKeyPath: *sensorConfigPublicKey,
			maxSensors:    *sensorConfigMaxSensors,
			bounds: config.Bounds{
				MinHeartbeatSeconds: *sensorConfigMinHeartbeat, MaxHeartbeatSeconds: *sensorConfigMaxHeartbeat,
				MinSpoolLimitEvents: *sensorConfigMinSpool, MaxSpoolLimitEvents: *sensorConfigMaxSpool,
				MinEventBatchLimit: *sensorConfigMinBatch, MaxEventBatchLimit: *sensorConfigMaxBatch,
			},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid sensor status configuration")
			os.Exit(2)
		}
		defer local.store.Close()
		sensorStatus = local
		if hasIncidents {
			statePath, stateErr := filepath.Abs(incidentOptions.StateDir)
			sensorPath, sensorErr := filepath.Abs(*sensorStatusDir)
			if stateErr != nil || sensorErr != nil || statePath != sensorPath || incidentOptions.StorageLimits != (storage.Limits{MaxOperations: *sensorStatusMaxOperations, MaxBytes: *sensorStatusMaxBytes, MaxManifestBytes: *sensorStatusMaxManifestBytes}) {
				fmt.Fprintln(os.Stderr, "sensor and incident views must share the same local store and quotas")
				os.Exit(2)
			}
			sharedStore = local.store
		}
	}
	var incidentView *incidentview.View
	if hasIncidents {
		view, closeView, err := openIncidentView(*incidentOptions, sharedStore)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid local incident configuration")
			os.Exit(2)
		}
		defer closeView()
		incidentView = view
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The supervisor owns stdin; EOF also stops the engine after supervisor death.
	go func() { io.Copy(io.Discard, os.Stdin); stop() }()
	if err := serve(ctx, *address, os.Stdout, sensorStatus, incidentView); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
