// Package podman provides the rootless Podman provider of the decoy isolation.
//
// The adapter is the only place in the engine that runs another program. It
// runs exactly one program, the container runtime named by the deployment, and
// it never uses a shell: every call is a fixed argument vector. The adapter
// has no network client of its own, so it can neither reach the Internet nor
// answer a request.
//
// The adapter never pulls an image. The pinned image must already be present
// locally and every run refuses an implicit pull, so starting a decoy never
// reaches a registry.
package podman

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
)

var (
	// ErrNotRootless reports a container runtime that does not run rootless.
	ErrNotRootless = errors.New("podman: the container runtime is not rootless")
	// ErrImageMissing reports a pinned image that is not present locally.
	ErrImageMissing = errors.New("podman: the pinned image is not present locally")
)

// maxOutputBytes bounds the output the adapter keeps of one runtime call.
const maxOutputBytes = 1 << 20

// cleanupTimeout bounds the removal of a container that a start call may have
// left behind.
const cleanupTimeout = 30 * time.Second

// proxyVariables are cleared inside the container: an inherited proxy would
// turn a denied egress attempt into a tunnel through the operator's proxy and
// would hand its credentials to the decoy process.
var proxyVariables = []string{
	"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
	"ftp_proxy", "FTP_PROXY", "all_proxy", "ALL_PROXY",
	"no_proxy", "NO_PROXY",
}

// Provider runs the decoy container with the rootless container runtime.
type Provider struct {
	binary  string
	timeout time.Duration
}

// New resolves the container runtime binary. A missing runtime is an explicit
// error: the isolation is never reported as active without a provider.
func New(binary string) (*Provider, error) {
	if binary == "" {
		binary = "podman"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", decoy.ErrProviderUnavailable, err)
	}
	return &Provider{binary: path, timeout: 120 * time.Second}, nil
}

// Binary returns the resolved container runtime path.
func (p *Provider) Binary() string {
	if p == nil {
		return ""
	}
	return p.binary
}

// Start creates the decoy container from the policy.
func (p *Provider) Start(ctx context.Context, name string, policy decoy.Policy) (decoy.Container, error) {
	if p == nil {
		return decoy.Container{}, decoy.ErrProviderUnavailable
	}
	if err := policy.Validate(); err != nil {
		return decoy.Container{}, err
	}
	if err := p.check(ctx, policy); err != nil {
		return decoy.Container{}, err
	}
	if err := checkMountSources(policy); err != nil {
		return decoy.Container{}, err
	}
	output, code, err := p.run(ctx, runArgs(name, policy)...)
	if err != nil || code != 0 {
		// The runtime creates a detached container before it reports the
		// identifier. An uncertain result may leave that container behind, so
		// it is removed by its known name and both failures are reported.
		return decoy.Container{}, p.rollback(ctx, name, startFailure(output, code, err))
	}
	id := strings.TrimSpace(output)
	if id == "" {
		return decoy.Container{}, p.rollback(ctx, name, fmt.Errorf("%w: the container runtime returned no container", decoy.ErrProviderUnavailable))
	}
	return decoy.Container{ID: id, Name: name}, nil
}

// startFailure reports the failure of a start call.
func startFailure(output string, code int, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", decoy.ErrProviderUnavailable, strings.TrimSpace(output))
}

// rollback removes a container that a start call may have left behind. The
// removal runs on its own bounded context, so it also works when the call was
// cancelled.
func (p *Provider) rollback(ctx context.Context, name string, cause error) error {
	cleanup, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	output, code, err := p.run(cleanup, "rm", "--force", "--ignore", name)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("decoy: the container %s could not be removed: %w", name, err))
	}
	if code != 0 {
		return errors.Join(cause, fmt.Errorf("decoy: the container %s could not be removed: %s", name, strings.TrimSpace(output)))
	}
	return cause
}

// Inspect returns the observed runtime state of a container. The state carries
// the effective controls of the running container: the capability sets of its
// process and the limits of its control group.
func (p *Provider) Inspect(ctx context.Context, id string) (decoy.Runtime, error) {
	if p == nil {
		return decoy.Runtime{}, decoy.ErrProviderUnavailable
	}
	if id == "" {
		return decoy.Runtime{}, decoy.ErrUnknownContainer
	}
	output, code, err := p.run(ctx, "inspect", "--format", "json", id)
	if err != nil {
		return decoy.Runtime{}, err
	}
	if code != 0 {
		if unknownContainer(output) {
			return decoy.Runtime{}, decoy.ErrUnknownContainer
		}
		return decoy.Runtime{}, fmt.Errorf("%w: %s", decoy.ErrProviderUnavailable, strings.TrimSpace(output))
	}
	var inspected []containerState
	if err := json.Unmarshal([]byte(output), &inspected); err != nil || len(inspected) == 0 {
		return decoy.Runtime{}, fmt.Errorf("%w: the container runtime returned no readable state", decoy.ErrProviderUnavailable)
	}
	state := inspected[0]
	runtime := decoy.Runtime{
		ID:                state.ID,
		State:             state.State.Status,
		NetworkMode:       state.HostConfig.NetworkMode,
		PidsLimit:         state.HostConfig.PidsLimit,
		MemoryBytes:       state.HostConfig.Memory,
		MemorySwapBytes:   state.HostConfig.MemorySwap,
		ReadOnlyRoot:      state.HostConfig.ReadonlyRootfs,
		User:              state.Config.User,
		AddedCapabilities: len(state.HostConfig.CapAdd) > 0,
		NoNewPrivileges:   privilegeProtected(state.HostConfig.SecurityOpt),
	}
	if runtime.State == "" {
		runtime.State = decoy.StateUnknown
	}
	// The capability sets of the container process decide whether the
	// capabilities are really dropped. The effective set shows what the
	// process holds and the bounding set shows what it could regain.
	if state.State.Pid > 0 {
		effective, bounding, err := capabilitySets(state.State.Pid)
		if err == nil {
			runtime.EffectiveCaps = effective
			runtime.BoundingCaps = bounding
			runtime.CapabilitiesDropped = effective == decoy.EmptyCapabilities && bounding == decoy.EmptyCapabilities
		}
	}
	// The effective limits of the control group decide whether the limits are
	// really in force. A runtime without cgroup delegation reports no limit.
	if state.State.CgroupPath != "" {
		processes, processErr := cgroupLimit(state.State.CgroupPath, "pids.max")
		memory, memoryErr := cgroupLimit(state.State.CgroupPath, "memory.max")
		swap, swapErr := cgroupLimit(state.State.CgroupPath, "memory.swap.max")
		if processErr == nil && memoryErr == nil && swapErr == nil {
			runtime.ControlsObserved = true
			runtime.EffectivePidsLimit = processes
			runtime.EffectiveMemory = memory
			runtime.EffectiveSwap = swap
		}
	}
	return runtime, nil
}

// Exec runs one command inside the container namespace and returns its exit
// code. The command is passed as an argument vector: there is no shell.
func (p *Provider) Exec(ctx context.Context, id string, argv []string) (decoy.ExecResult, error) {
	if p == nil {
		return decoy.ExecResult{}, decoy.ErrProviderUnavailable
	}
	if id == "" || len(argv) == 0 {
		return decoy.ExecResult{}, decoy.ErrInvalidPolicy
	}
	args := append([]string{"exec", id}, argv...)
	output, code, err := p.run(ctx, args...)
	if err != nil {
		return decoy.ExecResult{}, err
	}
	return decoy.ExecResult{ExitCode: code, Output: output}, nil
}

// Stop removes the container and the resources it owns. Removing a container
// that is already gone is not an error: the cleanup is idempotent.
func (p *Provider) Stop(ctx context.Context, id string) error {
	if p == nil {
		return decoy.ErrProviderUnavailable
	}
	if id == "" {
		return decoy.ErrUnknownContainer
	}
	output, code, err := p.run(ctx, "rm", "--force", "--ignore", id)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%w: %s", decoy.ErrProviderUnavailable, strings.TrimSpace(output))
	}
	return nil
}

// check verifies the provider prerequisites: the runtime is rootless and the
// pinned image is present locally. The runtime is never asked to fetch it.
func (p *Provider) check(ctx context.Context, policy decoy.Policy) error {
	// The runtime answers with the single fact the isolation depends on, so
	// the call stays small and bounded.
	output, code, err := p.run(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%w: %s", decoy.ErrProviderUnavailable, strings.TrimSpace(output))
	}
	if strings.TrimSpace(output) != "true" {
		return ErrNotRootless
	}
	output, code, err = p.run(ctx, "image", "exists", policy.Image)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%w: %s", ErrImageMissing, policy.Image)
	}
	return nil
}

// run executes the container runtime with a fixed argument vector and returns
// its combined output and exit code. The lifetime of the child follows the
// context of the caller and stays bounded by the timeout of the adapter. The
// runtime is called from a neutral working directory: the runtime writes a
// memory profile into its working directory when a container is killed by the
// memory limit, and that diagnostic must not land in the working directory
// of the engine.
func (p *Provider) run(ctx context.Context, args ...string) (string, int, error) {
	command := exec.CommandContext(ctx, p.binary, args...)
	command.Dir = os.TempDir()
	// The runtime and the children it starts end with the call: they run in
	// their own process group, which the adapter kills when the call ends.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 2 * time.Second
	captured := &boundedWriter{limit: maxOutputBytes}
	command.Stdout = captured
	command.Stderr = captured
	if err := command.Start(); err != nil {
		return "", 0, fmt.Errorf("%w: %v", decoy.ErrProviderUnavailable, err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timeout := time.NewTimer(p.timeout)
	defer timeout.Stop()
	select {
	case err := <-done:
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				if ctx.Err() != nil {
					return "", 0, ctx.Err()
				}
				return "", 0, fmt.Errorf("%w: %v", decoy.ErrProviderUnavailable, err)
			}
			code = exit.ExitCode()
		}
		return captured.String(), code, nil
	case <-ctx.Done():
		killGroup(command)
		<-done
		return "", 0, ctx.Err()
	case <-timeout.C:
		killGroup(command)
		<-done
		return "", 0, fmt.Errorf("%w: the container runtime did not answer in time", decoy.ErrProviderUnavailable)
	}
}

// killGroup ends the runtime and the children it started.
func killGroup(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	_ = command.Process.Kill()
}

// checkMountSources verifies the host paths of the mounts. The artifact is a
// file and the durable state is a directory, so a policy cannot mount an
// unrelated host path in place of the decoy.
func checkMountSources(policy decoy.Policy) error {
	for _, mount := range policy.Mounts {
		info, err := os.Stat(mount.Source)
		if err != nil {
			return fmt.Errorf("%w: the mount %s is not available: %v", decoy.ErrInvalidPolicy, mount.Source, err)
		}
		switch mount.Role {
		case decoy.MountArtifact:
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%w: the artifact %s is not a regular file", decoy.ErrInvalidPolicy, mount.Source)
			}
		case decoy.MountState:
			if !info.IsDir() {
				return fmt.Errorf("%w: the state %s is not a directory", decoy.ErrInvalidPolicy, mount.Source)
			}
		default:
			return decoy.ErrInvalidPolicy
		}
	}
	return nil
}

// runArgs builds the argument vector of one decoy container. The vector is
// fixed: there is no shell, no user supplied flag, no inherited proxy setting
// inside the container and no implicit pull.
func runArgs(name string, policy decoy.Policy) []string {
	args := []string{
		"run",
		"--detach",
		"--name=" + name,
		// The decoy keeps the identity of the operator so that its durable
		// state stays owned by that identity inside and outside the container.
		"--userns=keep-id",
		"--network=" + decoy.NetworkNone,
		"--ipc=none",
		"--uts=private",
		"--pid=private",
		"--cgroupns=private",
		"--pids-limit=" + strconv.Itoa(policy.PidsLimit),
		"--memory=" + strconv.FormatInt(policy.MemoryBytes, 10),
		"--memory-swap=" + strconv.FormatInt(policy.MemoryBytes, 10),
		"--cap-drop=" + decoy.DropAllCaps,
		"--security-opt=" + decoy.NoNewPrivilege,
		"--read-only",
		"--user=" + policy.User,
		// The image is pinned by digest and present locally: the runtime never
		// contacts a registry for it.
		"--pull=never",
		// The runtime copies the proxy settings of the host into the container
		// by default. The decoy never gets them, not even the credentials of
		// a proxy of the operator.
		"--http-proxy=false",
	}
	for _, variable := range proxyVariables {
		args = append(args, "--env", variable+"=")
	}
	for name, value := range policy.Env {
		args = append(args, "--env", name+"="+value)
	}
	for _, mount := range policy.Mounts {
		args = append(args, "--volume", volume(mount))
	}
	args = append(args, policy.Image)
	return append(args, policy.Command...)
}

// volume renders one mount of the decoy container.
func volume(mount decoy.Mount) string {
	mode := "rw"
	if mount.ReadOnly {
		mode = "ro"
	}
	return mount.Source + ":" + mount.Target + ":" + mode
}

// privilegeProtected reports the exact privilege protection of the runtime.
// A setting that switches the protection off is not accepted.
func privilegeProtected(options []string) bool {
	enabled := false
	for _, option := range options {
		if option == decoy.NoNewPrivilege {
			enabled = true
			continue
		}
		if strings.HasPrefix(option, decoy.NoNewPrivilege) {
			return false
		}
	}
	return enabled
}

// capabilitySets returns the effective and the bounding capability set of a
// process of the host.
func capabilitySets(pid int) (string, string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "", "", err
	}
	effective, bounding := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "CapEff:"):
			effective = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		case strings.HasPrefix(line, "CapBnd:"):
			bounding = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		}
	}
	if effective == "" || bounding == "" {
		return "", "", errors.New("the process reports no capability set")
	}
	return effective, bounding, nil
}

// cgroupLimit returns one effective limit of the control group of a
// container. A limit that is not a number is not a limit.
func cgroupLimit(cgroupPath, name string) (int64, error) {
	data, err := os.ReadFile("/sys/fs/cgroup" + cgroupPath + "/" + name)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

// unknownContainer reports the runtime message of a container that is gone.
func unknownContainer(output string) bool {
	lowered := strings.ToLower(output)
	return strings.Contains(lowered, "no such container") || strings.Contains(lowered, "no container with name or id") || strings.Contains(lowered, "no such object")
}

// boundedWriter keeps the first bytes of the output of a runtime call and
// drops the rest, so a noisy runtime cannot grow the memory of the engine.
type boundedWriter struct {
	limit   int
	kept    bytes.Buffer
	dropped int
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if remaining := w.limit - w.kept.Len(); remaining > 0 {
		if len(data) <= remaining {
			w.kept.Write(data)
		} else {
			w.kept.Write(data[:remaining])
			w.dropped += len(data) - remaining
		}
	}
	return len(data), nil
}

// String returns the captured output and reports the dropped bytes.
func (w *boundedWriter) String() string {
	if w.dropped == 0 {
		return w.kept.String()
	}
	return w.kept.String() + fmt.Sprintf("\n[%d bytes dropped]", w.dropped)
}

// containerState is the part of the runtime inspection the supervisor reads.
type containerState struct {
	ID    string `json:"Id"`
	State struct {
		Status     string `json:"Status"`
		Pid        int    `json:"Pid"`
		CgroupPath string `json:"CgroupPath"`
	} `json:"State"`
	HostConfig struct {
		PidsLimit      int      `json:"PidsLimit"`
		Memory         int64    `json:"Memory"`
		MemorySwap     int64    `json:"MemorySwap"`
		NetworkMode    string   `json:"NetworkMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapDrop        []string `json:"CapDrop"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
}
