package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"github.com/Parsa-Emami/Miragemesh/internal/update"
	fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C25"
)

type unavailableUpdateStatus struct{}

func (unavailableUpdateStatus) Snapshot(context.Context) (update.Snapshot, error) {
	return update.Snapshot{}, errors.New("private key or state path must not leak")
}

func TestUpdateHTTPReadsDurableStateAndRejectsMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	m := fixture.Generate()
	service, err := update.New(ctx, store, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 8, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	payload := fixture.Metadata(now, 1, "sensor-25", nil, 4)
	if _, err := service.Accept(ctx, payload, ed25519.Sign(m.Publisher, payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(ctx, update.Request{SensorID: "sensor-25", Version: 4, Artifact: bytes.NewReader(fixture.Artifact(4))}); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "state", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	read, write := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveViews(ctx, "127.0.0.1:0", write, nil, nil, nil, service); write.Close() }()
	t.Cleanup(func() { cancel(); read.Close(); <-done })
	var ready struct{ Address string }
	if err := json.NewDecoder(read).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	base := "http://" + ready.Address
	response, err := client.Get(base + "/api/v1/updates")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	var snapshot update.Snapshot
	if response.StatusCode != 200 || json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Sensors) != 1 || snapshot.Sensors[0].Version != 4 {
		t.Fatal("invalid update snapshot", response.StatusCode, string(raw))
	}
	for _, secret := range []string{"PRIVATE KEY", "CERTIFICATE REQUEST", "payload", "signature", "receipt", "reason"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("update view exposed operator material", secret)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "HEAD"} {
		request, _ := http.NewRequest(method, base+"/api/v1/updates", strings.NewReader("{}"))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 405 || response.Header.Get("Allow") != "GET" {
			t.Fatal("update view admitted mutation", method, response.StatusCode)
		}
	}
	request, _ := http.NewRequest("GET", base+"/api/v1/updates", nil)
	request.Header.Set("Origin", "https://foreign.invalid")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("foreign origin admitted")
	}
	after, _ := os.ReadFile(filepath.Join(root, "state", "manifest.json"))
	if !bytes.Equal(manifest, after) {
		t.Fatal("read-only update view changed durable state")
	}
}

func TestUpdateHTTPDisabledAndFailureAreExplicit(t *testing.T) {
	for _, reader := range []updateStatusReader{nil, unavailableUpdateStatus{}} {
		ctx, cancel := context.WithCancel(context.Background())
		read, write := io.Pipe()
		done := make(chan error, 1)
		go func() { done <- serveViews(ctx, "127.0.0.1:0", write, nil, nil, nil, reader); write.Close() }()
		var ready struct{ Address string }
		if err := json.NewDecoder(read).Decode(&ready); err != nil {
			t.Fatal(err)
		}
		response, err := http.Get("http://" + ready.Address + "/api/v1/updates")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 503 || strings.TrimSpace(string(raw)) != `{"error":"update_status_unavailable"}` {
			t.Fatal("private status failure leaked", string(raw))
		}
		cancel()
		read.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
