package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/sensorview"
)

type failingSensorStatus struct{}

func (failingSensorStatus) Snapshot(context.Context, time.Time) (sensorview.Snapshot, error) {
	return sensorview.Snapshot{}, errors.New("private storage detail")
}

func TestLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, "127.0.0.1:0", writer, nil); writer.Close() }()
	var ready struct{ Address string }
	if err := json.NewDecoder(bufio.NewReader(reader)).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + ready.Address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || result["scope"] != "engine-runtime" || result["coreReady"] != false || result["version"] != "0.0.1" || result["toolchain"] != "go1.27.2" {
		t.Fatalf("invalid health: %v", result)
	}
	response, err = client.Get("http://" + ready.Address + "/api/v1/sensors")
	if err != nil {
		t.Fatal(err)
	}
	var unavailable map[string]string
	if err = json.NewDecoder(response.Body).Decode(&unavailable); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || unavailable["error"] != "sensor_status_unavailable" {
		t.Fatalf("unconfigured sensor status should fail explicitly: %d %+v", response.StatusCode, unavailable)
	}
	for _, method := range []string{http.MethodPost, http.MethodHead} {
		request, _ := http.NewRequest(method, "http://"+ready.Address+"/api/v1/sensors", nil)
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != http.MethodGet {
			t.Fatalf("sensor endpoint accepted %s or advertised a write method", method)
		}
		response.Body.Close()
	}
	for _, path := range []string{"/api/v1/sensors/", "/healthz/extra"} {
		response, err := client.Get("http://" + ready.Address + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("unexpected route admitted: %s", path)
		}
	}
	response, err = client.Post("http://"+ready.Address+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatal("mutation admitted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown deadline")
	}
	if connection, err := net.DialTimeout("tcp", ready.Address, time.Second); err == nil {
		connection.Close()
		t.Fatal("listener survived shutdown")
	}
}

func TestRejectsUnsafeAndOccupiedAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "example.invalid:80", "[::]:0", "127.0.0.1:bad"} {
		if err := serve(context.Background(), address, io.Discard, nil); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := serve(context.Background(), listener.Addr().String(), io.Discard, nil); err == nil {
		t.Fatal("occupied port accepted")
	}
}

func TestSensorStatusProviderFailureDoesNotLeakDetails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, "127.0.0.1:0", writer, failingSensorStatus{}); writer.Close() }()
	var ready struct{ Address string }
	if err := json.NewDecoder(bufio.NewReader(reader)).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://" + ready.Address + "/api/v1/sensors")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || string(body) != `{"error":"sensor_status_unavailable"}` || strings.Contains(string(body), "private storage detail") {
		t.Fatalf("provider failure was not safely bounded: %d %s %v", response.StatusCode, body, err)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSensorStatusRequiresCompleteLocalPolicy(t *testing.T) {
	if status, err := openSensorStatus(sensorStatusOptions{directory: t.TempDir()}); err == nil || status != nil {
		t.Fatalf("partial sensor status policy was accepted: %+v %v", status, err)
	}
}

// TestIsolationWorkflowRefusesIncompleteConfiguration proves that the
// supported engine workflow of the isolated decoy refuses an incomplete or
// unsafe configuration before any container is created.
func TestIsolationWorkflowRefusesIncompleteConfiguration(t *testing.T) {
	cases := []isolationOptions{
		{},
		{Image: "docker.io/library/alpine:latest", Artifact: "/opt/decoy", State: "/var/lib/miragemesh", MemoryBytes: 1, PidsLimit: 1},
		{Image: "docker.io/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000", Artifact: "/opt/decoy", State: "/var/lib/miragemesh", MemoryBytes: 67108864, PidsLimit: 32},
	}
	for index, options := range cases {
		if _, err := isolationPolicy(options); err == nil {
			t.Errorf("case %d was accepted", index)
		}
	}
	// A state path that is not a private directory of the owner is refused.
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(directory); err == nil {
		t.Error("a state directory that is not private was accepted")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(directory); err != nil {
		t.Errorf("a private state directory was refused: %v", err)
	}
	created := filepath.Join(t.TempDir(), "state")
	if err := prepareStateDirectory(created); err != nil {
		t.Errorf("a missing state directory was not created: %v", err)
	}
}

// c13FailingWriter refuses every write, like a closed output pipe.
type c13FailingWriter struct{}

func (c13FailingWriter) Write(data []byte) (int, error) {
	return 0, errors.New("the output is closed")
}

// TestIsolationOutcomeReportsAnUndeliveredResult proves that a typed outcome
// that cannot be delivered is an error: a caller must never read a silent
// success as a verified isolation.
func TestIsolationOutcomeReportsAnUndeliveredResult(t *testing.T) {
	outcome := isolationOutcome{Scope: "decoy-isolation", Status: "verified"}
	if err := writeOutcome(c13FailingWriter{}, outcome); err == nil {
		t.Fatal("the undelivered outcome reported no error")
	}
	var buffer bytes.Buffer
	if err := writeOutcome(&buffer, outcome); err != nil {
		t.Fatalf("the delivered outcome reported %v", err)
	}
	var decoded isolationOutcome
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Scope != "decoy-isolation" || decoded.Status != "verified" {
		t.Fatalf("the delivered outcome drifted: %+v", decoded)
	}
}
