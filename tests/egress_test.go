package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/podman"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c13Positive struct {
	FixtureVersion int      `json:"fixture_version"`
	License        string   `json:"license"`
	Provenance     string   `json:"provenance"`
	Image          string   `json:"image"`
	ImageDigest    string   `json:"image_digest"`
	ImagePlatform  string   `json:"image_platform"`
	MemoryBytes    int64    `json:"memory_bytes"`
	PidsLimit      int      `json:"pids_limit"`
	SensorID       string   `json:"sensor_id"`
	Listen         string   `json:"listen"`
	HostTarget     string   `json:"host_target"`
	HostCommand    string   `json:"host_command"`
	StoreTarget    string   `json:"store_target"`
	EgressTargets  []string `json:"egress_targets"`
	PrivateTargets []string `json:"private_subnet_targets"`
	Expected       struct {
		NetworkMode     string `json:"network_mode"`
		Capabilities    string `json:"capabilities"`
		Routes          int    `json:"routes"`
		EgressConnected bool   `json:"egress_connected"`
		ProcessLimit    bool   `json:"process_limit_held"`
		MemoryLimit     bool   `json:"memory_limit_held"`
		Observations    int    `json:"recorded_observations"`
		RecordedPath    string `json:"recorded_path"`
	} `json:"expected"`
}

type c13Expected struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Accepted       int    `json:"accepted_interactions"`
	EgressAttempts int    `json:"egress_attempts"`
	Rejected       int    `json:"rejected_cases"`
	Observed       struct {
		NetworkMode   string `json:"network_mode"`
		Capabilities  string `json:"capabilities"`
		Routes        int    `json:"routes"`
		PidsMax       int    `json:"pids_max"`
		MemoryMax     int64  `json:"memory_max"`
		MemorySwapMax int64  `json:"memory_swap_max"`
		ProcessLimit  bool   `json:"process_limit_held"`
		MemoryLimit   bool   `json:"memory_limit_held"`
		Observations  int    `json:"recorded_observations"`
		RecordedPath  string `json:"recorded_path"`
		RemovedOnStop bool   `json:"container_removed_on_stop"`
		Reconciled    bool   `json:"stale_container_reconciled"`
	} `json:"observed"`
}

type c13Invalid struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Cases          []struct {
		Name  string          `json:"name"`
		Kind  string          `json:"kind"`
		Field string          `json:"field"`
		Value json.RawMessage `json:"value"`
		Error string          `json:"expected_error"`
	} `json:"cases"`
}

// c13Report is the isolation report the container probe returns.
type c13Report struct {
	Capabilities  string   `json:"capabilities"`
	PidsMax       string   `json:"pids_max"`
	MemoryMax     string   `json:"memory_max"`
	MemorySwapMax string   `json:"memory_swap_max"`
	MemoryEvents  string   `json:"memory_events"`
	Routes        []string `json:"routes"`
}

var (
	c13HostOnce sync.Once
	c13HostDir  string
	c13HostPath string
	c13HostErr  error
)

// TestMain removes the shared decoy host build of the C13 tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if c13HostDir != "" {
		_ = os.RemoveAll(c13HostDir)
	}
	os.Exit(code)
}

func c13Files(t *testing.T) (*c13Positive, *c13Invalid, *c13Expected) {
	t.Helper()
	var positive c13Positive
	var invalid c13Invalid
	var expected c13Expected
	for name, target := range map[string]any{"positive": &positive, "invalid": &invalid, "expected-output": &expected} {
		raw, err := os.ReadFile("fixtures/miragemesh/C13/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C13 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || invalid.FixtureVersion != 1 || expected.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || invalid.License != "Apache-2.0" || expected.License != "Apache-2.0" ||
		positive.Provenance == "" || invalid.Provenance == "" || expected.Provenance == "" {
		t.Fatal("invalid C13 fixture metadata")
	}
	if positive.Image == "" || !strings.Contains(positive.Image, "@sha256:") || len(positive.Expected.RecordedPath) == 0 {
		t.Fatal("the C13 fixture carries no pinned image or expectation")
	}
	if expected.Accepted < 1 || expected.Rejected != len(invalid.Cases) {
		t.Fatalf("the expected outcomes %d/%d do not match the fixtures %d", expected.Accepted, expected.Rejected, len(invalid.Cases))
	}
	if expected.Observed.Observations != expected.Accepted {
		t.Fatalf("the expected outcomes declare %d observations and %d accepted interactions", expected.Observed.Observations, expected.Accepted)
	}
	return &positive, &invalid, &expected
}

// c13HostBinary builds the test only decoy host once. The host runs the real
// C12 decoy handler inside the container and measures the isolation from
// there.
func c13HostBinary(t *testing.T) string {
	t.Helper()
	c13HostOnce.Do(func() {
		directory, err := os.MkdirTemp("", "miragemesh-c13-host-")
		if err != nil {
			c13HostErr = err
			return
		}
		c13HostDir = directory
		binary := filepath.Join(directory, "decoyhost")
		command := exec.Command("go", "build", "-trimpath", "-o", binary, "./tests/decoyhost")
		command.Dir = ".."
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=go"+strings.TrimPrefix(runtime.Version(), "go"))
		output, err := command.CombinedOutput()
		if err != nil {
			c13HostErr = fmt.Errorf("building the decoy host failed: %v: %s", err, output)
			return
		}
		c13HostPath = binary
	})
	if c13HostErr != nil {
		t.Fatal(c13HostErr)
	}
	return c13HostPath
}

// c13Provider returns the real rootless container provider. A missing or
// unusable provider is an explicit failure: the isolation is never reported
// as proven without it.
func c13Provider(t *testing.T) *podman.Provider {
	t.Helper()
	provider, err := podman.New("podman")
	if err != nil {
		t.Fatalf("the rootless container provider is required for the C13 proof: %v", err)
	}
	return provider
}

// c13Name returns the deterministic container name of one test.
// c13Store creates the durable store directory of the decoy. The C05 adapter
// requires a private directory of the owner, so the mode is not left to the
// umask of the test process.
func c13Store(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func c13Name(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	return "miragemesh-decoy-c13-" + hex.EncodeToString(sum[:6])
}

func c13Policy(t *testing.T, f *c13Positive, store, host string) decoy.Policy {
	t.Helper()
	return decoy.Policy{
		Image: f.Image,
		Command: []string{
			f.HostCommand,
			"--store", f.StoreTarget,
			"--listen", f.Listen,
			"--sensor-id", f.SensorID,
			"--max-request-bytes", "1024",
			"--max-path-bytes", "256",
		},
		Mounts: []decoy.Mount{
			{Source: host, Target: f.HostTarget, Role: decoy.MountArtifact, ReadOnly: true},
			{Source: store, Target: f.StoreTarget, Role: decoy.MountState},
		},
		Env: map[string]string{
			"MIRAGEMESH_DECOY_STATE":  f.StoreTarget,
			"MIRAGEMESH_DECOY_LISTEN": f.Listen,
		},
		MemoryBytes: f.MemoryBytes,
		PidsLimit:   f.PidsLimit,
		User:        strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		Egress:      decoy.EgressDenied,
	}
}

func c13Supervisor(t *testing.T, provider *podman.Provider, policy decoy.Policy, name string) *decoy.Supervisor {
	t.Helper()
	supervisor, err := decoy.NewSupervisor(provider, policy, name)
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

// c13Probe runs one probe of the decoy host inside the container.
func c13Probe(t *testing.T, supervisor *decoy.Supervisor, id string, args ...string) decoy.ExecResult {
	t.Helper()
	result, err := supervisor.Exec(context.Background(), id, args)
	if err != nil {
		t.Fatalf("running the probe %v: %v", args, err)
	}
	return result
}

// c13Status reads the isolation report from inside the container.
func c13Status(t *testing.T, supervisor *decoy.Supervisor, id, host string) c13Report {
	t.Helper()
	result := c13Probe(t, supervisor, id, host, "probe", "status")
	if result.ExitCode != 0 {
		t.Fatalf("the status probe failed: %d %s", result.ExitCode, result.Output)
	}
	var report c13Report
	if err := json.Unmarshal([]byte(result.Output), &report); err != nil {
		t.Fatalf("the status probe returned no readable report: %v: %s", err, result.Output)
	}
	return report
}

// c13Observations reads the durable observations of the decoy after its
// container released the store.
func c13Observations(t *testing.T, store string) []storage.Record {
	t.Helper()
	opened, err := storage.Open(store, storage.Limits{MaxOperations: 64, MaxBytes: 1048576, MaxManifestBytes: 262144})
	if err != nil {
		t.Fatalf("opening the durable store of the decoy: %v", err)
	}
	defer opened.Close()
	records, err := opened.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestDecoyIsolationDeniesInternetAndPrivateSubnets(t *testing.T) {
	f, _, expected := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	provider := c13Provider(t)
	supervisor := c13Supervisor(t, provider, c13Policy(t, f, store, host), c13Name(t))
	container, err := supervisor.Start(context.Background())
	if err != nil {
		t.Fatalf("starting the isolated decoy: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Stop(context.Background(), container.ID) })
	state, err := supervisor.Observe(context.Background(), container.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != decoy.StateRunning || state.NetworkMode != f.Expected.NetworkMode {
		t.Fatalf("the container runs as %q with the network mode %q", state.State, state.NetworkMode)
	}
	if state.PidsLimit != f.PidsLimit || state.MemoryBytes != f.MemoryBytes || state.MemorySwapBytes != f.MemoryBytes {
		t.Fatalf("the container limits drifted: %+v", state)
	}
	if !state.ReadOnlyRoot || !state.CapabilitiesDropped || !state.NoNewPrivileges || state.User != supervisor.Policy().User {
		t.Fatalf("the container posture drifted: %+v", state)
	}
	request := c13Probe(t, supervisor, container.ID, f.HostCommand, "probe", "request", f.Listen, f.Expected.RecordedPath)
	if request.ExitCode != 0 {
		t.Fatalf("the decoy did not answer inside the container: %d %s", request.ExitCode, request.Output)
	}
	attempts := 0
	for _, target := range append(append([]string{}, f.EgressTargets...), f.PrivateTargets...) {
		attempts++
		result := c13Probe(t, supervisor, container.ID, f.HostCommand, "probe", "egress", target)
		if result.ExitCode != 0 || !strings.Contains(result.Output, "\"connected\":false") {
			t.Errorf("the container reached %s: %s", target, result.Output)
		}
	}
	if attempts != expected.EgressAttempts {
		t.Errorf("the fixture declares %d egress attempts, the test made %d", expected.EgressAttempts, attempts)
	}
	report := c13Status(t, supervisor, container.ID, f.HostCommand)
	if len(report.Routes) != expected.Observed.Routes {
		t.Errorf("the container has routes: %v", report.Routes)
	}
	if report.Capabilities != expected.Observed.Capabilities {
		t.Errorf("the container capabilities are %q", report.Capabilities)
	}
	if state.NetworkMode != expected.Observed.NetworkMode {
		t.Errorf("the network mode is %q", state.NetworkMode)
	}
	if err := supervisor.Stop(context.Background(), container.ID); err != nil {
		t.Fatal(err)
	}
	records := c13Observations(t, store)
	if len(records) != expected.Accepted {
		t.Fatalf("the decoy recorded %d observations, the fixture declares %d", len(records), expected.Accepted)
	}
	if len(records) != expected.Observed.Observations {
		t.Fatalf("the decoy recorded %d observations, want %d", len(records), expected.Observed.Observations)
	}
	if records[0].Event.Kind != "http.request" || records[0].Event.Metadata.Path != expected.Observed.RecordedPath {
		t.Fatalf("the recorded observation drifted: %+v", records[0].Event)
	}
	if records[0].Event.SensorID != f.SensorID {
		t.Fatalf("the recorded identity drifted: %+v", records[0].Event)
	}
}

func TestDecoyIsolationEnforcesPIDAndMemoryLimits(t *testing.T) {
	f, _, expected := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	provider := c13Provider(t)
	supervisor := c13Supervisor(t, provider, c13Policy(t, f, store, host), c13Name(t))
	container, err := supervisor.Start(context.Background())
	if err != nil {
		t.Fatalf("starting the isolated decoy: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Stop(context.Background(), container.ID) })
	report := c13Status(t, supervisor, container.ID, f.HostCommand)
	if report.PidsMax != strconv.Itoa(expected.Observed.PidsMax) {
		t.Errorf("the process limit is %q, want %d", report.PidsMax, expected.Observed.PidsMax)
	}
	if report.MemoryMax != strconv.FormatInt(expected.Observed.MemoryMax, 10) {
		t.Errorf("the memory limit is %q, want %d", report.MemoryMax, expected.Observed.MemoryMax)
	}
	if report.MemorySwapMax != strconv.FormatInt(expected.Observed.MemorySwapMax, 10) {
		t.Errorf("the container may swap beyond its memory limit: %q", report.MemorySwapMax)
	}
	forks := c13Probe(t, supervisor, container.ID, f.HostCommand, "probe", "fork", "200")
	if forks.ExitCode != 0 || !strings.Contains(forks.Output, "\"refused\":true") {
		t.Fatalf("the process limit did not hold: %d %s", forks.ExitCode, forks.Output)
	}
	if !expected.Observed.ProcessLimit {
		t.Fatal("the fixture does not expect the process limit to hold")
	}
	before := c13Status(t, supervisor, container.ID, f.HostCommand)
	allocation := c13Probe(t, supervisor, container.ID, f.HostCommand, "probe", "allocate", strconv.Itoa(int(f.MemoryBytes)*2))
	if allocation.ExitCode == 0 {
		t.Fatalf("the memory limit did not hold: %s", allocation.Output)
	}
	after := c13Status(t, supervisor, container.ID, f.HostCommand)
	if oomKills(before.MemoryEvents) >= oomKills(after.MemoryEvents) {
		t.Errorf("the memory limit did not kill the allocation: %q -> %q", before.MemoryEvents, after.MemoryEvents)
	}
	if !expected.Observed.MemoryLimit {
		t.Fatal("the fixture does not expect the memory limit to hold")
	}
	state, err := supervisor.Observe(context.Background(), container.ID)
	if err != nil || state.State != decoy.StateRunning {
		t.Fatalf("the decoy did not survive its limits: %+v %v", state, err)
	}
}

func TestDecoyIsolationReconcilesAfterRestart(t *testing.T) {
	f, _, expected := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	provider := c13Provider(t)
	policy := c13Policy(t, f, store, host)
	name := c13Name(t)
	first := c13Supervisor(t, provider, policy, name)
	container, err := first.Start(context.Background())
	if err != nil {
		t.Fatalf("starting the isolated decoy: %v", err)
	}
	t.Cleanup(func() { _ = first.Stop(context.Background(), container.ID) })
	// The decoy of the first container records a real observation.
	request := c13Probe(t, first, container.ID, f.HostCommand, "probe", "request", f.Listen, expected.Observed.RecordedPath)
	if request.ExitCode != 0 {
		t.Fatalf("the decoy did not answer inside the container: %d %s", request.ExitCode, request.Output)
	}
	second := c13Supervisor(t, provider, policy, name)
	replaced, err := second.Start(context.Background())
	if err != nil {
		t.Fatalf("restarting the decoy supervisor: %v", err)
	}
	t.Cleanup(func() { _ = second.Stop(context.Background(), replaced.ID) })
	if replaced.ID == container.ID {
		t.Fatal("the restart reused the container of the earlier supervisor")
	}
	if _, err := provider.Inspect(context.Background(), container.ID); !errors.Is(err, decoy.ErrUnknownContainer) {
		t.Fatalf("the container of the earlier supervisor survived: %v", err)
	}
	state, err := second.Observe(context.Background(), replaced.ID)
	if err != nil || state.NetworkMode != decoy.NetworkNone || state.PidsLimit != f.PidsLimit {
		t.Fatalf("the reconciled container drifted: %+v %v", state, err)
	}
	if err := second.Stop(context.Background(), replaced.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Inspect(context.Background(), replaced.ID); !errors.Is(err, decoy.ErrUnknownContainer) {
		t.Fatalf("the reconciled container survived the stop: %v", err)
	}
	// The durable state lives outside the container: the observation of the
	// first container is still there after the restart.
	records := c13Observations(t, store)
	if len(records) != expected.Accepted {
		t.Fatalf("the store holds %d observations, the fixture declares %d", len(records), expected.Accepted)
	}
	if records[0].Event.Metadata.Path != expected.Observed.RecordedPath {
		t.Fatalf("the observation of the first container did not survive: %+v", records[0].Event)
	}
	if records[0].Event.Kind != "http.request" || records[0].Event.Sequence != 1 {
		t.Fatalf("the observation of the first container drifted: %+v", records[0].Event)
	}
	if !expected.Observed.Reconciled {
		t.Fatal("the fixture does not expect the stale container to be reconciled")
	}
}

func TestDecoyIsolationProviderFailuresAreExplicit(t *testing.T) {
	f, invalid, _ := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	for _, test := range invalid.Cases {
		if test.Kind != "provider" {
			continue
		}
		switch test.Field {
		case "binary":
			provider, err := podman.New(c13Value(t, test.Value))
			if !errors.Is(err, decoy.ErrProviderUnavailable) {
				t.Errorf("%s error = %v, want %v", test.Name, err, decoy.ErrProviderUnavailable)
			}
			if provider != nil {
				t.Errorf("%s returned a provider", test.Name)
			}
		case "image":
			provider := c13Provider(t)
			policy := c13Policy(t, f, store, host)
			policy.Image = c13Value(t, test.Value)
			_, err := provider.Start(context.Background(), c13Name(t), policy)
			if err == nil || !strings.Contains(err.Error(), test.Error) {
				t.Errorf("%s error = %v, want %v", test.Name, err, test.Error)
			}
		case "stub":
			stub := filepath.Join(t.TempDir(), "podman")
			script := "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then echo false; exit 0; fi\nexit 1\n"
			if err := os.WriteFile(stub, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			provider, err := podman.New(stub)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Start(context.Background(), c13Name(t), c13Policy(t, f, store, host))
			if err == nil || !strings.Contains(err.Error(), test.Error) {
				t.Errorf("%s error = %v, want %v", test.Name, err, test.Error)
			}
		default:
			t.Fatalf("unknown provider field %q", test.Field)
		}
	}
}

func TestDecoyIsolationPolicyRejectsUnsafeConfiguration(t *testing.T) {
	f, invalid, _ := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	provider := c13Provider(t)
	for _, test := range invalid.Cases {
		if test.Kind != "policy" {
			continue
		}
		policy := c13Policy(t, f, store, host)
		name := c13Name(t)
		switch test.Field {
		case "image":
			policy.Image = c13Value(t, test.Value)
		case "command":
			policy.Command = nil
		case "egress":
			policy.Egress = decoy.EgressPolicy(c13Value(t, test.Value))
		case "user":
			policy.User = c13Value(t, test.Value)
		case "memory_bytes":
			policy.MemoryBytes = 0
		case "pids_limit":
			policy.PidsLimit = 0
		case "mount":
			value := c13Value(t, test.Value)
			policy.Mounts = append(policy.Mounts, decoy.Mount{Source: value, Target: value, Role: decoy.MountState})
		case "writable_artifact":
			policy.Mounts[0].ReadOnly = false
			policy.Mounts[0].Source = c13Value(t, test.Value)
		case "extra_state_mount":
			policy.Mounts = append(policy.Mounts, decoy.Mount{Source: c13Value(t, test.Value), Target: "/var/lib/extra", Role: decoy.MountState})
		case "unknown_role":
			policy.Mounts = append(policy.Mounts, decoy.Mount{Source: c13Value(t, test.Value), Target: "/var/lib/extra", Role: decoy.MountRole("other")})
		case "duplicate_target":
			policy.Mounts = append(policy.Mounts, decoy.Mount{Source: c13Value(t, test.Value), Target: policy.Mounts[0].Target, Role: decoy.MountState})
		case "proxy_env":
			policy.Env = map[string]string{c13Value(t, test.Value): "http://127.0.0.1:10808"}
		case "drop_artifact":
			policy.Mounts = policy.Mounts[1:]
		case "drop_state":
			policy.Mounts = policy.Mounts[:1]
		case "artifact_target":
			policy.Mounts[0].Target = c13Value(t, test.Value)
		case "state_target":
			policy.Mounts[1].Target = c13Value(t, test.Value)
		case "read_only_state":
			policy.Mounts[1].ReadOnly = true
		case "extra_mount":
			policy.Mounts = append(policy.Mounts, decoy.Mount{Source: c13Value(t, test.Value), Target: "/var/lib/extra", Role: decoy.MountState})
		case "name":
			name = c13Value(t, test.Value)
		default:
			t.Fatalf("unknown policy field %q", test.Field)
		}
		supervisor, err := decoy.NewSupervisor(provider, policy, name)
		if !errors.Is(err, decoy.ErrInvalidPolicy) {
			t.Errorf("%s error = %v, want %v", test.Name, err, decoy.ErrInvalidPolicy)
		}
		if supervisor != nil {
			t.Errorf("%s returned a supervisor", test.Name)
		}
	}
}

func TestDecoyIsolationStopsAndRemovesItsContainer(t *testing.T) {
	f, _, _ := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	provider := c13Provider(t)
	supervisor := c13Supervisor(t, provider, c13Policy(t, f, store, host), c13Name(t))
	container, err := supervisor.Start(context.Background())
	if err != nil {
		t.Fatalf("starting the isolated decoy: %v", err)
	}
	if err := supervisor.Stop(context.Background(), container.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Inspect(context.Background(), container.ID); !errors.Is(err, decoy.ErrUnknownContainer) {
		t.Fatalf("the container survived the stop: %v", err)
	}
	if err := supervisor.Stop(context.Background(), container.ID); err != nil {
		t.Fatalf("the cleanup is not idempotent: %v", err)
	}
}

// c13Value reads one fixture value as text.
func c13Value(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return string(raw)
}

// TestDecoyIsolationAdapterRunsOnlyTheContainerRuntime keeps the one new
// permission of the C13 work limited: the isolation adapter may run the
// container runtime and nothing else. The decoy package itself keeps the C12
// rules and never gains that permission.
func TestDecoyIsolationAdapterRunsOnlyTheContainerRuntime(t *testing.T) {
	problems, err := podmanPermissionViolations("../internal/podman")
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
}

func podmanPermissionViolations(directory string) ([]string, error) {
	var problems []string
	allowed := []string{
		"crypto/rand",
		"encoding/hex",
		"bytes",
		"context",
		"encoding/json",
		"errors",
		"fmt",
		"os",
		"os/exec",
		"strconv",
		"strings",
		"syscall",
		"time",
		"github.com/Parsa-Emami/Miragemesh/internal/decoy",
	}
	permitted := make(map[string]bool, len(allowed))
	for _, path := range allowed {
		permitted[path] = true
	}
	allowedIdentifiers := map[string]map[string]bool{
		"os":      {"TempDir": true, "ReadFile": true, "Stat": true},
		"os/exec": {"Command": true, "LookPath": true, "ExitError": true},
		"syscall": {"Kill": true, "SIGKILL": true, "SysProcAttr": true},
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	union := make(map[string]bool)
	sources := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		sources++
		path := filepath.Join(directory, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, forbidden := range []string{"sh -c", "/bin/sh", "bash -c", "/bin/bash", "net/http", "net.Dial", "http.Get", "http.Post"} {
			if strings.Contains(string(data), forbidden) {
				problems = append(problems, fmt.Sprintf("%s uses %s", path, forbidden))
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			if !permitted[imported] {
				problems = append(problems, fmt.Sprintf("%s imports %s", path, imported))
			}
			union[imported] = true
		}
		full, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(full, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			identifiers, known := allowedIdentifiers[pkg.Name]
			if !known {
				return true
			}
			if !identifiers[selector.Sel.Name] {
				problems = append(problems, fmt.Sprintf("%s names the %s identifier %s, which is not part of the limited permission", path, pkg.Name, selector.Sel.Name))
			}
			return true
		})
	}
	if sources == 0 {
		return nil, errors.New("the isolation adapter has no source file")
	}
	for _, path := range allowed {
		if !union[path] {
			problems = append(problems, fmt.Sprintf("the isolation adapter no longer imports %s", path))
		}
	}
	if len(union) != len(allowed) {
		problems = append(problems, fmt.Sprintf("the isolation adapter imports %v", union))
	}
	return problems, nil
}

func TestC37PermissionGuardRejectsProductionCapabilities(t *testing.T) {
	directory := t.TempDir()
	production, err := os.ReadFile("../internal/podman/podman.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "podman.go"), production, 0600); err != nil {
		t.Fatal(err)
	}
	testOnly := []byte("package podman\nimport \"testing\"\nfunc TestOnly(t *testing.T) {}\n")
	if err := os.WriteFile(filepath.Join(directory, "helper_test.go"), testOnly, 0600); err != nil {
		t.Fatal(err)
	}
	problems, err := podmanPermissionViolations(directory)
	if err != nil || len(problems) != 0 {
		t.Fatalf("valid production plus test-only imports: %v %v", problems, err)
	}
	for _, source := range []string{
		"package podman\nimport \"net/http\"\nvar forbidden = http.Get\n",
		"package podman\nimport \"os\"\nvar forbidden = os.WriteFile\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, "extra.go"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		problems, err := podmanPermissionViolations(directory)
		if err != nil || len(problems) == 0 {
			t.Fatalf("production capability escaped guard: %v %v", problems, err)
		}
	}
}

// oomKills returns the number of out of memory kills of a cgroup report.
func oomKills(events string) int {
	for _, line := range strings.Split(events, "\n") {
		if strings.HasPrefix(line, "oom_kill ") {
			value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "oom_kill ")))
			if err == nil {
				return value
			}
		}
	}
	return -1
}
