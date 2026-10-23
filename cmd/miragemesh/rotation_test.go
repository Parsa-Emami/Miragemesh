package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

type unavailableCertificateStatus struct{}

func (unavailableCertificateStatus) Snapshot(context.Context) (pki.RotationSnapshot, error) {
	return pki.RotationSnapshot{}, errors.New("private key or state path must not leak")
}

func TestCertificateHTTPReadsDurableStateAndRejectsMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "state"), storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	m := fixture.Generate(now, "sensor-24")
	service, err := pki.NewRotator(ctx, store, pki.RotationOptions{IssuerCertificatePEM: m.Authority, MaxSensors: 8, MaxLifetime: 24 * time.Hour, MaxOverlap: time.Hour, MaxRecoveryTTL: 15 * time.Minute, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Register(ctx, pki.RegisterCertificate{SensorID: "sensor-24", CertificatePEM: m.Initial, IdempotencyKey: "c24-http-register-key"}); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "state", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	read, write := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveViews(ctx, "127.0.0.1:0", write, nil, nil, service); write.Close() }()
	t.Cleanup(func() { cancel(); read.Close(); <-done })
	var ready struct{ Address string }
	if err := json.NewDecoder(read).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	base := "http://" + ready.Address
	response, err := client.Get(base + "/api/v1/certificates")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	var snapshot pki.RotationSnapshot
	if response.StatusCode != 200 || json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Sensors) != 1 || snapshot.Sensors[0].Revision != 1 {
		t.Fatal("invalid certificate snapshot", response.StatusCode, string(raw))
	}
	for _, secret := range []string{"PRIVATE KEY", "CERTIFICATE REQUEST", "certificate_pem", "token_hash", "receipt"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("certificate view exposed operator material", secret)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "HEAD"} {
		request, _ := http.NewRequest(method, base+"/api/v1/certificates", strings.NewReader("{}"))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 405 || response.Header.Get("Allow") != "GET" {
			t.Fatal("certificate view admitted mutation", method, response.StatusCode)
		}
	}
	request, _ := http.NewRequest("GET", base+"/api/v1/certificates", nil)
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
		t.Fatal("read-only certificate view changed durable state")
	}
}

func TestCertificateHTTPDisabledAndFailureAreExplicit(t *testing.T) {
	for _, reader := range []certificateStatusReader{nil, unavailableCertificateStatus{}} {
		ctx, cancel := context.WithCancel(context.Background())
		read, write := io.Pipe()
		done := make(chan error, 1)
		go func() { done <- serveViews(ctx, "127.0.0.1:0", write, nil, nil, reader); write.Close() }()
		var ready struct{ Address string }
		if err := json.NewDecoder(read).Decode(&ready); err != nil {
			t.Fatal(err)
		}
		response, err := http.Get("http://" + ready.Address + "/api/v1/certificates")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 503 || strings.TrimSpace(string(raw)) != `{"error":"certificate_status_unavailable"}` {
			t.Fatal("private status failure leaked", string(raw))
		}
		cancel()
		read.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
