package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

func TestMonitorChild(t *testing.T) {
	mode := os.Getenv("MIRAGEMESH_MONITOR_TEST_MODE")
	if mode == "" {
		return
	}
	os.Args = []string{"miragemesh", mode, os.Getenv("MIRAGEMESH_MONITOR_TEST_CONFIG")}
	flag.CommandLine = flag.NewFlagSet("miragemesh", flag.ExitOnError)
	main()
}

func TestMonitorAuthenticatesIngestAndKeepsPagedEvidenceAfterRestart(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	if err := os.Mkdir(web, 0700); err != nil {
		t.Fatal(err)
	}
	monitorFile(t, web, "index.html", "<!doctype html><title>Workspace</title>")
	ingestAddress, teamAddress := monitorTestAddress(t), monitorTestAddress(t)
	ingestOrigin, teamOrigin := "https://"+ingestAddress, "https://"+teamAddress
	now := time.Now().UTC()
	sensor := fixture.Generate(now, "edge-01")
	operator := fixture.Generate(now, "analyst-01")
	viewer := monitorViewerMaterial(t, operator, now)
	config := map[string]any{
		"state_dir": filepath.Join(dir, "state"), "web_dir": web,
		"retention_hours": 24, "max_events_per_hour": 400, "max_event_age_minutes": 60,
		"requests_per_hour_alert": 100, "workspace_origin": teamOrigin,
		"collector": monitorTestListener(t, dir, "sensor", ingestAddress, sensor),
		"workspace": monitorTestListener(t, dir, "operator", teamAddress, operator),
		"sensors":   map[string][]string{monitorFingerprint(sensor.Initial): {"edge-01", "decoy-02"}},
		"operators": map[string]any{
			monitorFingerprint(operator.Initial): map[string]any{"id": "analyst-01", "role": "analyst", "sensors": []string{"edge-01", "decoy-02"}},
			monitorFingerprint(viewer.Initial):   map[string]any{"id": "viewer-01", "role": "viewer", "sensors": []string{"decoy-02"}},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := monitorFile(t, dir, "monitor.json", string(encoded))
	ingest := monitorTestClient(t, sensor, sensor.Authority)
	team := monitorTestClient(t, operator, operator.Authority)
	readOnly := monitorTestClient(t, viewer, operator.Authority)
	wrong := monitorTestClient(t, operator, sensor.Authority)
	stop := startMonitorTest(t, "--monitor-config", configPath, team, teamOrigin+"/readyz")
	request := func(client *http.Client, method, url string, body []byte, status int, headers map[string]string) []byte {
		t.Helper()
		return monitorRequest(t, client, method, url, body, status, headers)
	}
	jsonHeader := map[string]string{"Content-Type": "application/json"}
	event := func(sensorID string, sequence int64, path string) []byte {
		payload, err := json.Marshal(contracts.Event{SchemaVersion: "1", SensorID: sensorID,
			EventID: fmt.Sprintf("event-%03d", sequence), Sequence: sequence, ObservedAt: now.Format(time.RFC3339Nano),
			Kind: "http.request", Metadata: contracts.HTTPMetadata{Path: path}})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	post := ingestOrigin + "/api/ingest/v1/events"
	wrongResponse, err := wrong.Post(post, "application/json", bytes.NewReader(event("edge-01", 1, "/decoy")))
	if err == nil {
		wrongResponse.Body.Close()
		t.Fatal("operator certificate passed collector TLS")
	}
	request(ingest, http.MethodPost, post, event("outside-scope", 1, "/decoy"), 403, jsonHeader)
	heartbeat := ingestOrigin + "/api/ingest/v1/heartbeat"
	request(ingest, http.MethodPost, heartbeat, []byte(`{"sensor_id":"outside-scope","pending":0,"held":0}`), 403, jsonHeader)
	request(ingest, http.MethodPost, heartbeat, []byte(`{"sensor_id":"edge-01","pending":2,"held":1}`), 204, jsonHeader)
	if status := request(team, http.MethodGet, teamOrigin+"/api/team/v1/sensors", nil, 200, nil); !bytes.Contains(status, []byte(`"online":true`)) ||
		!bytes.Contains(status, []byte(`"spool_pending":2`)) {
		t.Fatalf("authenticated sensor did not appear online: %s", status)
	}
	for sequence := int64(1); sequence <= 260; sequence++ {
		request(ingest, http.MethodPost, post, event("edge-01", sequence, "/decoy"), 201, jsonHeader)
	}
	request(ingest, http.MethodPost, post, event("edge-01", 260, "/decoy"), 200, jsonHeader)
	request(ingest, http.MethodPost, post, event("edge-01", 260, "/different"), 409, jsonHeader)
	pageURL := teamOrigin + "/api/team/v1/incidents?limit=2"
	type incident struct {
		ID       string `json:"id"`
		Sequence int64  `json:"sequence"`
	}
	var first, second struct {
		Items []incident `json:"items"`
		Next  string     `json:"next_cursor"`
	}
	if err := json.Unmarshal(request(team, http.MethodGet, pageURL, nil, 200, nil), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.Items[0].Sequence != 260 || first.Items[1].Sequence != 259 || first.Next == "" {
		t.Fatalf("unexpected first page: %+v", first)
	}
	if err := json.Unmarshal(request(team, http.MethodGet, pageURL+"&before="+first.Next, nil, 200, nil), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 2 || second.Items[0].Sequence != 258 || second.Items[1].Sequence != 257 {
		t.Fatalf("cursor returned unexpected events: %+v", second)
	}
	detail := teamOrigin + "/api/team/v1/incidents/" + first.Items[0].ID
	request(readOnly, http.MethodGet, detail, nil, 404, nil)
	request(readOnly, http.MethodGet, pageURL+"&sensor=edge-01", nil, 403, nil)
	body := []byte(`{"status":"investigating","reason":"Review this interaction"}`)
	request(team, http.MethodPost, detail+"/triage", body, 403, jsonHeader)
	writeHeaders := map[string]string{"Content-Type": "application/json", "Origin": teamOrigin, "Idempotency-Key": "evidence-review-0001"}
	request(team, http.MethodPost, detail+"/triage", body, 202, writeHeaders)
	stop()
	restartStop := startMonitorTest(t, "--monitor-config", configPath, team, teamOrigin+"/readyz")
	request(ingest, http.MethodPost, post, event("edge-01", 260, "/decoy"), 200, jsonHeader)
	request(team, http.MethodPost, detail+"/triage", body, 202, writeHeaders)
	var restored struct {
		History []struct {
			Actor  string `json:"actor"`
			Reason string `json:"reason"`
		} `json:"history"`
	}
	if err := json.Unmarshal(request(team, http.MethodGet, detail, nil, 200, nil), &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.History) != 1 || restored.History[0].Actor != "analyst-01" || restored.History[0].Reason != "Review this interaction" {
		t.Fatalf("triage was not durable and attributed: %+v", restored)
	}
	restartStop()
	decoyAddress, healthAddress := monitorTestAddress(t), monitorTestAddress(t)
	sensorCfg := map[string]any{
		"sensor_id": "decoy-02", "listen": decoyAddress, "health_listen": healthAddress,
		"spool_dir": filepath.Join(dir, "spool"), "queue_limit": 1,
		"collector_origin": ingestOrigin,
		"ca":               monitorFile(t, dir, "collector-client-ca.crt", sensor.Authority),
		"certificate":      monitorFile(t, dir, "collector-client.crt", sensor.Initial),
		"key":              monitorFile(t, dir, "collector-client.key", sensor.InitialKey),
	}
	encoded, err = json.Marshal(sensorCfg)
	if err != nil {
		t.Fatal(err)
	}
	sensorPath := monitorFile(t, dir, "edge.json", string(encoded))
	httpClient := &http.Client{Timeout: 2 * time.Second}
	healthURL := "http://" + healthAddress + "/healthz"
	stopSensor := startMonitorTest(t, "--monitor-sensor-config", sensorPath, httpClient, healthURL)
	request(httpClient, http.MethodPost, "http://"+decoyAddress+"/observed?secret=private-query", []byte("private-body"), 200, nil)
	request(httpClient, http.MethodGet, "http://"+decoyAddress+"/queue-full", nil, 503, nil)
	stopSensor()
	startMonitorTest(t, "--monitor-sensor-config", sensorPath, httpClient, healthURL)
	startMonitorTest(t, "--monitor-config", configPath, team, teamOrigin+"/readyz")
	list := teamOrigin + "/api/team/v1/incidents?sensor=decoy-02"
	var delivered struct {
		Items []incident `json:"items"`
	}
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if err := json.Unmarshal(request(team, http.MethodGet, list, nil, 200, nil), &delivered); err != nil {
			t.Fatal(err)
		}
		if len(delivered.Items) > 0 {
			break
		}
	}
	if len(delivered.Items) != 1 || delivered.Items[0].Sequence != 1 {
		t.Fatalf("expected one observation recovered from the spool: %+v", delivered)
	}
	raw := request(team, http.MethodGet, teamOrigin+"/api/team/v1/incidents/"+delivered.Items[0].ID, nil, 200, nil)
	if !bytes.Contains(raw, []byte(`"path":"/observed"`)) || bytes.Contains(raw, []byte("private-")) {
		t.Fatalf("unexpected sensor evidence: %s", raw)
	}
	viewerDetail := teamOrigin + "/api/team/v1/incidents/" + delivered.Items[0].ID
	request(readOnly, http.MethodGet, viewerDetail, nil, 200, nil)
	request(readOnly, http.MethodPost, viewerDetail+"/triage", body, 403, writeHeaders)
}

func monitorViewerMaterial(t *testing.T, authority fixture.Material, now time.Time) fixture.Material {
	t.Helper()
	certBlock, _ := pem.Decode([]byte(authority.Authority))
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode([]byte(authority.AuthorityKey))
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(27), Subject: pkix.Name{CommonName: "viewer-01"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	return fixture.Material{Initial: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), InitialKey: fixture.Private(private)}
}

func monitorTestAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func monitorFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func monitorFingerprint(cert string) string {
	block, _ := pem.Decode([]byte(cert))
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func monitorTestListener(t *testing.T, dir, name, address string, material fixture.Material) map[string]string {
	t.Helper()
	return map[string]string{"listen": address,
		"certificate": monitorFile(t, dir, name+".crt", material.Server),
		"key":         monitorFile(t, dir, name+".key", material.ServerKey),
		"ca":          monitorFile(t, dir, name+"-ca.crt", material.Authority),
		"crl":         monitorFile(t, dir, name+".crl", material.CRL),
	}
}

func monitorTestClient(t *testing.T, material fixture.Material, authority string) *http.Client {
	t.Helper()
	key, err := tls.X509KeyPair([]byte(material.Initial), []byte(material.InitialKey))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(authority)) {
		t.Fatal("invalid test authority")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{key}}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func startMonitorTest(t *testing.T, mode, config string, client *http.Client, ready string) func() {
	t.Helper()
	var logs bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestMonitorChild$")
	cmd.Env = append(os.Environ(), "MIRAGEMESH_MONITOR_TEST_MODE="+mode, "MIRAGEMESH_MONITOR_TEST_CONFIG="+config)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		client.CloseIdleConnections()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-finished:
			if err != nil {
				t.Errorf("monitor stop: %v\n%s", err, logs.String())
			}
		case <-time.After(8 * time.Second):
			_ = cmd.Process.Kill()
			<-finished
			t.Errorf("monitor did not stop\n%s", logs.String())
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-finished:
			stopped = true
			t.Fatalf("monitor exited before serving requests: %v\n%s", err, logs.String())
		default:
		}
		if res, err := client.Get(ready); err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode == 200 {
				return stop
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	t.Fatalf("monitor failed readiness at %s\n%s", ready, logs.String())
	return stop
}

func monitorRequest(t *testing.T, client *http.Client, method, url string, body []byte, want int, headers map[string]string) []byte {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d, body %s, error %v", method, url, res.StatusCode, want, strings.TrimSpace(string(payload)), err)
	}
	return payload
}
