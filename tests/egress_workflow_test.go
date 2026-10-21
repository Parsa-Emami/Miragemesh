package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/podman"
)

// c13StubProvider is a provider that reports a chosen runtime state and can
// fail its cleanup. It proves that the supervisor refuses a container whose
// effective controls are weaker than the policy and that a failed cleanup is
// never hidden.
type c13StubProvider struct {
	runtime decoy.Runtime
	stopErr error
	stopped bool
}

func (p *c13StubProvider) Start(ctx context.Context, name string, policy decoy.Policy) (decoy.Container, error) {
	return decoy.Container{ID: "stub-container", Name: name}, nil
}

func (p *c13StubProvider) Inspect(ctx context.Context, id string) (decoy.Runtime, error) {
	if id != "stub-container" {
		return decoy.Runtime{}, decoy.ErrUnknownContainer
	}
	return p.runtime, nil
}

func (p *c13StubProvider) Exec(ctx context.Context, id string, argv []string) (decoy.ExecResult, error) {
	return decoy.ExecResult{}, nil
}

func (p *c13StubProvider) Stop(ctx context.Context, id string) error {
	p.stopped = true
	return p.stopErr
}

// c13VerifiedRuntime is the runtime state of a container that honours the
// policy of the tests.
func c13VerifiedRuntime(f *c13Positive) decoy.Runtime {
	return decoy.Runtime{
		ID:                  "stub-container",
		State:               decoy.StateRunning,
		NetworkMode:         decoy.NetworkNone,
		PidsLimit:           f.PidsLimit,
		MemoryBytes:         f.MemoryBytes,
		MemorySwapBytes:     f.MemoryBytes,
		ReadOnlyRoot:        true,
		User:                strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		CapabilitiesDropped: true,
		EffectiveCaps:       "0000000000000000",
		NoNewPrivileges:     true,
		EffectivePidsLimit:  int64(f.PidsLimit),
		EffectiveMemory:     f.MemoryBytes,
		EffectiveSwap:       0,
		ControlsObserved:    true,
	}
}

// TestDecoyIsolationRejectsWeakRuntimeControls proves that the supervisor
// refuses a container whose effective controls are weaker than the policy.
func TestDecoyIsolationRejectsWeakRuntimeControls(t *testing.T) {
	f, _, _ := c13Files(t)
	cases := []struct {
		name   string
		change func(*decoy.Runtime)
	}{
		{"partial-capability-drop", func(r *decoy.Runtime) { r.EffectiveCaps = "00000000a80425fb" }},
		{"capabilities-not-dropped", func(r *decoy.Runtime) { r.CapabilitiesDropped = false }},
		{"added-capabilities", func(r *decoy.Runtime) { r.AddedCapabilities = true }},
		{"privilege-protection-disabled", func(r *decoy.Runtime) { r.NoNewPrivileges = false }},
		{"limits-not-observed", func(r *decoy.Runtime) { r.ControlsObserved = false }},
		{"effective-process-limit", func(r *decoy.Runtime) { r.EffectivePidsLimit = int64(f.PidsLimit) + 1 }},
		{"effective-memory-limit", func(r *decoy.Runtime) { r.EffectiveMemory = f.MemoryBytes / 2 }},
		{"effective-swap-limit", func(r *decoy.Runtime) { r.EffectiveSwap = f.MemoryBytes }},
		{"network-mode", func(r *decoy.Runtime) { r.NetworkMode = "bridge" }},
		{"writable-root", func(r *decoy.Runtime) { r.ReadOnlyRoot = false }},
	}
	for _, test := range cases {
		state := c13VerifiedRuntime(f)
		test.change(&state)
		provider := &c13StubProvider{runtime: state}
		supervisor, err := decoy.NewSupervisor(provider, c13Policy(t, f, t.TempDir(), c13HostBinary(t)), "miragemesh-stub")
		if err != nil {
			t.Fatal(err)
		}
		_, err = supervisor.Start(context.Background())
		if !errors.Is(err, decoy.ErrPolicyViolated) {
			t.Errorf("%s error = %v, want %v", test.name, err, decoy.ErrPolicyViolated)
		}
		if !provider.stopped {
			t.Errorf("%s left the container running", test.name)
		}
	}
}

// TestDecoyIsolationReportsCleanupFailure proves that a cleanup that fails is
// reported together with the failure that caused it.
func TestDecoyIsolationReportsCleanupFailure(t *testing.T) {
	f, _, _ := c13Files(t)
	state := c13VerifiedRuntime(f)
	state.ReadOnlyRoot = false
	provider := &c13StubProvider{runtime: state, stopErr: errors.New("the runtime refused the removal")}
	supervisor, err := decoy.NewSupervisor(provider, c13Policy(t, f, t.TempDir(), c13HostBinary(t)), "miragemesh-stub")
	if err != nil {
		t.Fatal(err)
	}
	_, err = supervisor.Start(context.Background())
	if !errors.Is(err, decoy.ErrPolicyViolated) {
		t.Fatalf("error = %v, want %v", err, decoy.ErrPolicyViolated)
	}
	if !strings.Contains(err.Error(), "the runtime refused the removal") {
		t.Fatalf("the cleanup failure is hidden: %v", err)
	}
}

// TestDecoyIsolationPolicyIsImmutable proves that a caller cannot change a
// validated policy after the supervisor accepted it.
func TestDecoyIsolationPolicyIsImmutable(t *testing.T) {
	f, _, _ := c13Files(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	policy := c13Policy(t, f, store, host)
	supervisor, err := decoy.NewSupervisor(c13Provider(t), policy, c13Name(t))
	if err != nil {
		t.Fatal(err)
	}
	// The caller changes the policy it passed in.
	policy.Mounts[0].ReadOnly = false
	policy.Mounts[0].Source = "/etc"
	policy.Mounts = append(policy.Mounts, decoy.Mount{Source: "/etc", Target: "/etc", Role: decoy.MountState})
	policy.Command[0] = "/bin/sh"
	policy.MemoryBytes = 1
	// The caller changes the policy the supervisor returned.
	returned := supervisor.Policy()
	returned.Mounts[0].ReadOnly = false
	returned.Command[0] = "/bin/sh"
	returned.MemoryBytes = 1
	observed := supervisor.Policy()
	if observed.MemoryBytes != f.MemoryBytes {
		t.Fatalf("the memory limit of the supervisor changed: %d", observed.MemoryBytes)
	}
	if len(observed.Mounts) != 2 {
		t.Fatalf("the supervisor accepted an extra mount: %+v", observed.Mounts)
	}
	if !observed.Mounts[0].ReadOnly || observed.Mounts[0].Source != host {
		t.Fatalf("the mounts of the supervisor changed: %+v", observed.Mounts)
	}
	if observed.Mounts[0].Role != decoy.MountArtifact || observed.Mounts[1].Role != decoy.MountState {
		t.Fatalf("the roles of the mounts changed: %+v", observed.Mounts)
	}
	if observed.Command[0] == "/bin/sh" || observed.Command[0] != f.HostCommand {
		t.Fatalf("the command of the supervisor changed: %+v", observed.Command)
	}
}

// TestDecoyIsolationAdapterBoundsRuntimeOutput proves that a noisy runtime
// cannot grow the memory of the engine and that the runtime is called with
// the arguments of the policy.
func TestDecoyIsolationAdapterBoundsRuntimeOutput(t *testing.T) {
	f, _, _ := c13Files(t)
	directory := t.TempDir()
	record := filepath.Join(directory, "argv")
	noisy := filepath.Join(directory, "podman")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"info\" ]; then echo true; exit 0; fi\n" +
		"if [ \"$1\" = \"image\" ]; then exit 0; fi\n" +
		"printf '%s\\n' \"$@\" >> " + record + "\n" +
		"i=0\nwhile [ $i -lt 4000 ]; do printf '%01000d' $i; i=$((i+1)); done\nexit 0\n"
	if err := os.WriteFile(noisy, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	provider, err := podman.New(noisy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Exec(context.Background(), "stub", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("the runtime exited with %d", result.ExitCode)
	}
	if len(result.Output) > 1<<20+64 {
		t.Fatalf("the captured output is %d bytes", len(result.Output))
	}
	if !strings.Contains(result.Output, "bytes dropped") {
		t.Fatalf("the dropped bytes are not reported: %q", result.Output[len(result.Output)-64:])
	}
	// The run call of the provider carries the isolation of the policy.
	_, _ = provider.Start(context.Background(), "miragemesh-stub", c13Policy(t, f, c13Store(t), c13HostBinary(t)))
	recorded, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	arguments := string(recorded)
	for _, wanted := range []string{"--pull=never", "--http-proxy=false", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--pids-limit=32", "--memory=67108864", "--memory-swap=67108864", "--userns=keep-id"} {
		if !strings.Contains(arguments, wanted) {
			t.Errorf("the runtime call is missing %s: %s", wanted, arguments)
		}
	}
	if strings.Contains(arguments, "http_proxy=http") {
		t.Error("the runtime call carries a proxy setting")
	}
	if strings.Contains(arguments, "ftp_proxy=http") {
		t.Error("the runtime call carries a ftp proxy setting")
	}
}

// TestDecoyIsolationAdapterHonorsCancellation proves that a cancelled call
// stops the runtime instead of waiting for the timeout.
func TestDecoyIsolationAdapterHonorsCancellation(t *testing.T) {
	directory := t.TempDir()
	blocking := filepath.Join(directory, "podman")
	if err := os.WriteFile(blocking, []byte("#!/bin/sh\nsleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	provider, err := podman.New(blocking)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	_, err = provider.Exec(ctx, "stub", []string{"true"})
	if err == nil {
		t.Fatal("the cancelled call reported a result")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled call reported %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the cancelled call took %s", elapsed)
	}
}

// TestDecoyIsolationWorkflowReportsTypedOutcome proves that the supported
// engine workflow starts the isolated decoy and propagates its typed outcome.
func TestDecoyIsolationWorkflowReportsTypedOutcome(t *testing.T) {
	f, _, _ := c13Files(t)
	engine := c13Engine(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	command := exec.Command(engine,
		"--decoy-isolation",
		"--decoy-image", f.Image,
		"--decoy-artifact", host,
		"--decoy-state", store,
		"--decoy-memory-bytes", strconv.FormatInt(f.MemoryBytes, 10),
		"--decoy-pids-limit", strconv.Itoa(f.PidsLimit),
		"--decoy-name", "miragemesh-decoy-workflow",
		"--decoy-listen", f.Listen,
	)
	command.Dir = ".."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the isolated decoy workflow failed: %v: %s", err, output)
	}
	var outcome struct {
		Scope          string `json:"scope"`
		Status         string `json:"status"`
		Container      string `json:"container"`
		NetworkMode    string `json:"network_mode"`
		EffectivePids  int64  `json:"effective_pids_limit"`
		EffectiveBytes int64  `json:"effective_memory_bytes"`
		EffectiveSwap  int64  `json:"effective_memory_swap_bytes"`
		Capabilities   string `json:"effective_capabilities"`
	}
	if err := json.Unmarshal([]byte(output), &outcome); err != nil {
		t.Fatalf("the workflow reported no typed outcome: %v: %s", err, output)
	}
	if outcome.Scope != "decoy-isolation" || outcome.Status != "verified" {
		t.Fatalf("the workflow reported %+v", outcome)
	}
	if outcome.NetworkMode != decoy.NetworkNone || outcome.EffectivePids != int64(f.PidsLimit) || outcome.EffectiveBytes != f.MemoryBytes || outcome.EffectiveSwap != 0 {
		t.Fatalf("the workflow reported weaker controls: %+v", outcome)
	}
	if outcome.Capabilities != "0000000000000000" {
		t.Fatalf("the workflow reported the capabilities %q", outcome.Capabilities)
	}
	if outcome.Container != "miragemesh-decoy-workflow" {
		t.Fatalf("the workflow reported the container %q", outcome.Container)
	}
	// The workflow removes its container again.
	provider := c13Provider(t)
	if _, err := provider.Inspect(context.Background(), "miragemesh-decoy-workflow"); !errors.Is(err, decoy.ErrUnknownContainer) {
		t.Fatalf("the workflow left its container behind: %v", err)
	}
}

// TestDecoyIsolationWorkflowReportsMissingPrerequisites proves that the
// engine workflow refuses an incomplete configuration.
func TestDecoyIsolationWorkflowReportsMissingPrerequisites(t *testing.T) {
	engine := c13Engine(t)
	command := exec.Command(engine, "--decoy-isolation", "--decoy-image", "docker.io/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000")
	command.Dir = ".."
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("the incomplete workflow reported a result: %s", output)
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Fatalf("the incomplete workflow reported %v: %s", err, output)
	}
	if !strings.Contains(string(output), "decoy-isolation") {
		t.Fatalf("the workflow reported no typed outcome: %s", output)
	}
}

// c13Engine builds the engine binary once for the workflow regressions.
var (
	c13EngineOnce sync.Once
	c13EnginePath string
	c13EngineErr  error
)

func c13Engine(t *testing.T) string {
	t.Helper()
	c13EngineOnce.Do(func() {
		directory, err := os.MkdirTemp("", "miragemesh-c13-engine-")
		if err != nil {
			c13EngineErr = err
			return
		}
		binary := filepath.Join(directory, "miragemesh")
		command := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/miragemesh")
		command.Dir = ".."
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=go"+strings.TrimPrefix(runtime.Version(), "go"))
		output, err := command.CombinedOutput()
		if err != nil {
			c13EngineErr = fmt.Errorf("building the engine failed: %v: %s", err, output)
			return
		}
		c13EnginePath = binary
	})
	if c13EngineErr != nil {
		t.Fatal(c13EngineErr)
	}
	return c13EnginePath
}

// TestDecoyIsolationAdapterRollsBackAnUncertainStart proves that a start call
// that was cancelled after the runtime created the detached container removes
// that container by its known name.
func TestDecoyIsolationAdapterRollsBackAnUncertainStart(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "container")
	runtime := filepath.Join(directory, "podman")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"info\" ]; then echo true; exit 0; fi\n" +
		"if [ \"$1\" = \"image\" ]; then exit 0; fi\n" +
		"if [ \"$1\" = \"rm\" ]; then rm -f " + marker + "; exit 0; fi\n" +
		"touch " + marker + "\n" +
		"sleep 60\n"
	if err := os.WriteFile(runtime, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	provider, err := podman.New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	_, err = provider.Start(ctx, "miragemesh-uncertain", decoy.Policy{
		Image:       "docker.io/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Command:     []string{"/usr/local/bin/decoy"},
		MemoryBytes: 67108864,
		PidsLimit:   32,
		User:        strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		Egress:      decoy.EgressDenied,
	})
	if err == nil {
		t.Fatal("the cancelled start reported a container")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the cancelled start left the container behind")
	}
}

// TestDecoyIsolationWorkflowRemovesItsContainerOnSignal proves that an
// interrupted engine workflow does not leave its named container behind.
func TestDecoyIsolationWorkflowRemovesItsContainerOnSignal(t *testing.T) {
	f, _, _ := c13Files(t)
	engine := c13Engine(t)
	store := c13Store(t)
	host := c13HostBinary(t)
	command := exec.Command(engine,
		"--decoy-isolation",
		"--decoy-image", f.Image,
		"--decoy-artifact", host,
		"--decoy-state", store,
		"--decoy-memory-bytes", strconv.FormatInt(f.MemoryBytes, 10),
		"--decoy-pids-limit", strconv.Itoa(f.PidsLimit),
		"--decoy-name", "miragemesh-decoy-signal",
		"--decoy-listen", f.Listen,
	)
	command.Dir = ".."
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	provider := c13Provider(t)
	if _, err := provider.Inspect(context.Background(), "miragemesh-decoy-signal"); !errors.Is(err, decoy.ErrUnknownContainer) {
		t.Fatalf("the interrupted workflow left its container behind: %v", err)
	}
}
