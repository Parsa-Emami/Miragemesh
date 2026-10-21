package decoy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EgressPolicy is the outbound posture of a decoy container. Only the denied
// posture exists: a decoy never reaches the Internet and never reaches an
// operational private subnet.
type EgressPolicy string

// EgressDenied is the only accepted egress posture.
const EgressDenied EgressPolicy = "denied"

// The observed runtime facts the supervisor compares against the policy.
const (
	// cleanupTimeout bounds the removal of a container that failed the
	// verification. The cleanup runs on its own context, so it still works
	// when the request context is already cancelled.
	cleanupTimeout = 30 * time.Second
	// EmptyCapabilities is the effective capability set of a container that
	// holds no capability at all.
	EmptyCapabilities = "0000000000000000"
	NetworkNone       = "none"
	StateRunning      = "running"
	StateExited       = "exited"
	StateCreated      = "created"
	StateUnknown      = "unknown"
	DropAllCaps       = "ALL"
	NoNewPrivilege    = "no-new-privileges"
)

var (
	// ErrInvalidPolicy reports an incomplete or contradictory isolation policy.
	ErrInvalidPolicy = errors.New("decoy: invalid isolation policy")
	// ErrPolicyViolated reports a container that does not match its policy.
	ErrPolicyViolated = errors.New("decoy: the provider did not honour the isolation policy")
	// ErrProviderUnavailable reports a missing or unusable container provider.
	ErrProviderUnavailable = errors.New("decoy: the container provider is unavailable")
	// ErrUnknownContainer reports a container the provider does not know.
	ErrUnknownContainer = errors.New("decoy: unknown container")
)

// MountRole names the role of one host path inside the decoy container. The
// decoy sees exactly two host paths: the artifact it runs and the durable
// state it records into.
type MountRole string

const (
	// MountArtifact is the decoy process. It is always read-only.
	MountArtifact MountRole = "artifact"
	// MountState is the durable state of the decoy. It is writable.
	MountState MountRole = "state"
	// ArtifactTarget is the fixed path of the decoy process inside the
	// container.
	ArtifactTarget = "/usr/local/bin/decoy"
	// StateTarget is the fixed path of the durable state inside the
	// container.
	StateTarget = "/var/lib/miragemesh"
)

// Mount exposes one host path to the decoy container. The decoy artifact is
// mounted read-only; only the durable state of the decoy may be writable.
type Mount struct {
	// Source is the host path of the mount.
	Source string `json:"source"`
	// Target is the path inside the decoy container.
	Target string `json:"target"`
	// Role is the documented role of the mount.
	Role MountRole `json:"role"`
	// ReadOnly reports whether the container may write into the mount.
	ReadOnly bool `json:"read_only"`
}

// Policy is the isolation policy of one decoy container. It is explicit: the
// engine ships no default posture, no hidden limit and no egress option.
type Policy struct {
	// Image is the digest pinned image reference of the decoy container.
	Image string `json:"image"`
	// Command is the decoy process inside the container.
	Command []string `json:"command"`
	// Mounts are the host paths the decoy container may see.
	Mounts []Mount `json:"mounts"`
	// Env is the environment of the decoy process. It carries the paths the
	// decoy needs inside the container and never a proxy setting.
	Env map[string]string `json:"env"`
	// MemoryBytes is the hard memory limit of the container.
	MemoryBytes int64 `json:"memory_bytes"`
	// PidsLimit is the hard process limit of the container.
	PidsLimit int `json:"pids_limit"`
	// User is the unprivileged user the decoy process runs as.
	User string `json:"user"`
	// Egress is the outbound posture. Only EgressDenied is accepted.
	Egress EgressPolicy `json:"egress"`
}

// copy returns a policy that owns its own command and mounts. A caller
// cannot change a validated policy through the value it passed in.
func (p Policy) copy() Policy {
	duplicate := p
	duplicate.Command = append([]string(nil), p.Command...)
	duplicate.Mounts = append([]Mount(nil), p.Mounts...)
	if p.Env != nil {
		duplicate.Env = make(map[string]string, len(p.Env))
		for name, value := range p.Env {
			duplicate.Env[name] = value
		}
	}
	return duplicate
}

// Container identifies one decoy container.
type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Runtime is the observed state of a decoy container. It carries the effective
// controls of the running container, not only the requested configuration.
type Runtime struct {
	ID                  string `json:"id"`
	State               string `json:"state"`
	NetworkMode         string `json:"network_mode"`
	PidsLimit           int    `json:"pids_limit"`
	MemoryBytes         int64  `json:"memory_bytes"`
	MemorySwapBytes     int64  `json:"memory_swap_bytes"`
	ReadOnlyRoot        bool   `json:"read_only_root"`
	User                string `json:"user"`
	CapabilitiesDropped bool   `json:"capabilities_dropped"`
	EffectiveCaps       string `json:"effective_capabilities"`
	BoundingCaps        string `json:"bounding_capabilities"`
	NoNewPrivileges     bool   `json:"no_new_privileges"`
	AddedCapabilities   bool   `json:"added_capabilities"`
	EffectivePidsLimit  int64  `json:"effective_pids_limit"`
	EffectiveMemory     int64  `json:"effective_memory_bytes"`
	EffectiveSwap       int64  `json:"effective_memory_swap_bytes"`
	ControlsObserved    bool   `json:"controls_observed"`
}

// ExecResult is the outcome of one command executed inside a decoy container.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

// Provider is the container runtime port of the decoy isolation. The decoy
// package never runs a container itself: it states the policy and verifies
// what the provider actually did.
type Provider interface {
	// Start creates the decoy container from the policy.
	Start(ctx context.Context, name string, policy Policy) (Container, error)
	// Inspect returns the observed runtime state of a container.
	Inspect(ctx context.Context, id string) (Runtime, error)
	// Exec runs one command inside the container namespace.
	Exec(ctx context.Context, id string, argv []string) (ExecResult, error)
	// Stop removes the container and the resources it owns.
	Stop(ctx context.Context, id string) error
}

// Supervisor starts the decoy container, verifies that the provider honoured
// the isolation policy and reconciles a container left behind by an earlier
// supervisor.
type Supervisor struct {
	provider Provider
	policy   Policy
	name     string
}

// NewSupervisor requires a provider and a complete policy. There is no
// default posture: an incomplete policy is an explicit error. The supervisor
// owns a copy of the policy, so the caller cannot change what was validated.
func NewSupervisor(provider Provider, policy Policy, name string) (*Supervisor, error) {
	if provider == nil {
		return nil, ErrProviderUnavailable
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if !validName(name) {
		return nil, ErrInvalidPolicy
	}
	return &Supervisor{provider: provider, policy: policy.copy(), name: name}, nil
}

// Policy returns the isolation policy of the supervised decoy. The result owns
// its own command and mounts: a caller cannot change the policy of a running
// supervisor.
func (s *Supervisor) Policy() Policy {
	if s == nil {
		return Policy{}
	}
	return s.policy.copy()
}

// Name returns the container name of the supervised decoy.
func (s *Supervisor) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Start reconciles a container left behind by an earlier supervisor, starts
// the decoy and verifies the observed runtime state against the policy. A
// container that does not match the policy is removed and reported as an
// explicit failure: the supervisor never reports an unverified decoy. A
// cleanup that fails is reported together with the failure that caused it, so
// a container that stayed behind is never hidden.
func (s *Supervisor) Start(ctx context.Context) (Container, error) {
	if s == nil || s.provider == nil {
		return Container{}, ErrProviderUnavailable
	}
	if err := s.reconcile(ctx); err != nil {
		return Container{}, err
	}
	container, err := s.provider.Start(ctx, s.name, s.policy.copy())
	if err != nil {
		return Container{}, err
	}
	runtime, err := s.waitRunning(ctx, container.ID)
	if err != nil {
		return Container{}, s.cleanup(container.ID, err)
	}
	if err := s.verify(runtime); err != nil {
		return Container{}, s.cleanup(container.ID, err)
	}
	return container, nil
}

// cleanup removes a container that failed the verification and reports the
// failure of the cleanup together with the failure that caused it. The
// cleanup runs on its own bounded context, so it still works when the request
// context is already cancelled.
func (s *Supervisor) cleanup(id string, cause error) error {
	cleanup, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := s.provider.Stop(cleanup, id); err != nil {
		return errors.Join(cause, fmt.Errorf("decoy: the container %s could not be removed: %w", id, err))
	}
	return cause
}

// waitRunning waits for the started container to reach the running state. A
// container that leaves the running state is reported with the state it
// reached: the supervisor never verifies a container that is not running.
func (s *Supervisor) waitRunning(ctx context.Context, id string) (Runtime, error) {
	for attempt := 0; attempt < 50; attempt++ {
		runtime, err := s.provider.Inspect(ctx, id)
		if err != nil {
			return Runtime{}, err
		}
		if runtime.State == StateRunning {
			return runtime, nil
		}
		if runtime.State == StateExited {
			return Runtime{}, fmt.Errorf("%w: the container exited before it served", ErrPolicyViolated)
		}
		select {
		case <-ctx.Done():
			return Runtime{}, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return Runtime{}, fmt.Errorf("%w: the container did not reach the running state", ErrPolicyViolated)
}

// Observe returns the observed runtime state of the supervised container.
func (s *Supervisor) Observe(ctx context.Context, id string) (Runtime, error) {
	if s == nil || s.provider == nil {
		return Runtime{}, ErrProviderUnavailable
	}
	return s.provider.Inspect(ctx, id)
}

// Exec runs one command inside the supervised container.
func (s *Supervisor) Exec(ctx context.Context, id string, argv []string) (ExecResult, error) {
	if s == nil || s.provider == nil {
		return ExecResult{}, ErrProviderUnavailable
	}
	return s.provider.Exec(ctx, id, argv)
}

// Stop removes the supervised container and its resources.
func (s *Supervisor) Stop(ctx context.Context, id string) error {
	if s == nil || s.provider == nil {
		return ErrProviderUnavailable
	}
	return s.provider.Stop(ctx, id)
}

// reconcile removes a container left behind by an earlier supervisor. A
// decoy container is never reused across supervisor restarts: the durable
// state lives outside the container and the policy is applied again.
func (s *Supervisor) reconcile(ctx context.Context) error {
	leftover, err := s.provider.Inspect(ctx, s.name)
	if err != nil {
		if errors.Is(err, ErrUnknownContainer) {
			return nil
		}
		return err
	}
	if leftover.ID == "" {
		return nil
	}
	return s.provider.Stop(ctx, leftover.ID)
}

// verify compares the observed runtime state with the isolation policy. The
// effective controls of the running container are verified, not only the
// configuration the runtime was asked for.
func (s *Supervisor) verify(runtime Runtime) error {
	switch {
	case runtime.State != StateRunning:
		return fmt.Errorf("%w: the container state is %q", ErrPolicyViolated, runtime.State)
	case runtime.NetworkMode != NetworkNone:
		return fmt.Errorf("%w: the network mode is %q", ErrPolicyViolated, runtime.NetworkMode)
	case runtime.PidsLimit != s.policy.PidsLimit:
		return fmt.Errorf("%w: the process limit is %d", ErrPolicyViolated, runtime.PidsLimit)
	case runtime.MemoryBytes != s.policy.MemoryBytes:
		return fmt.Errorf("%w: the memory limit is %d", ErrPolicyViolated, runtime.MemoryBytes)
	case runtime.MemorySwapBytes != s.policy.MemoryBytes:
		return fmt.Errorf("%w: the swap limit is %d", ErrPolicyViolated, runtime.MemorySwapBytes)
	case !runtime.ReadOnlyRoot:
		return fmt.Errorf("%w: the root filesystem is writable", ErrPolicyViolated)
	case runtime.User != s.policy.User:
		return fmt.Errorf("%w: the container user is %q", ErrPolicyViolated, runtime.User)
	case !runtime.CapabilitiesDropped:
		return fmt.Errorf("%w: the container capabilities are not dropped", ErrPolicyViolated)
	case runtime.EffectiveCaps != "" && runtime.EffectiveCaps != EmptyCapabilities:
		return fmt.Errorf("%w: the effective capabilities are %s", ErrPolicyViolated, runtime.EffectiveCaps)
	case runtime.BoundingCaps != "" && runtime.BoundingCaps != EmptyCapabilities:
		return fmt.Errorf("%w: the container may regain the capabilities %s", ErrPolicyViolated, runtime.BoundingCaps)
	case runtime.AddedCapabilities:
		return fmt.Errorf("%w: the container gained capabilities", ErrPolicyViolated)
	case !runtime.NoNewPrivileges:
		return fmt.Errorf("%w: the container may gain privileges", ErrPolicyViolated)
	case !runtime.ControlsObserved:
		return fmt.Errorf("%w: the effective limits of the container could not be observed", ErrPolicyViolated)
	case runtime.EffectivePidsLimit != int64(s.policy.PidsLimit):
		return fmt.Errorf("%w: the effective process limit is %d", ErrPolicyViolated, runtime.EffectivePidsLimit)
	case runtime.EffectiveMemory != s.policy.MemoryBytes:
		return fmt.Errorf("%w: the effective memory limit is %d", ErrPolicyViolated, runtime.EffectiveMemory)
	case runtime.EffectiveSwap != 0:
		return fmt.Errorf("%w: the effective swap limit is %d", ErrPolicyViolated, runtime.EffectiveSwap)
	}
	return nil
}

// Validate fails closed on an incomplete or contradictory policy.
func (p Policy) Validate() error {
	if !pinnedImage(p.Image) {
		return ErrInvalidPolicy
	}
	if len(p.Command) == 0 {
		return ErrInvalidPolicy
	}
	if p.MemoryBytes <= 0 || p.PidsLimit <= 0 {
		return ErrInvalidPolicy
	}
	if p.Egress != EgressDenied {
		return ErrInvalidPolicy
	}
	if !validUser(p.User) {
		return ErrInvalidPolicy
	}
	if err := p.validateEnv(); err != nil {
		return err
	}
	return p.validateMounts()
}

// validateEnv accepts the environment of the decoy process. A proxy setting
// is never accepted: the decoy must not reach a proxy of the operator.
func (p Policy) validateEnv() error {
	for name, value := range p.Env {
		if name == "" || strings.ContainsAny(name, "=\x00") || strings.ContainsAny(value, "\x00") {
			return ErrInvalidPolicy
		}
		if proxyVariable(name) {
			return ErrInvalidPolicy
		}
	}
	return nil
}

// proxyVariable reports whether a name is a proxy setting.
func proxyVariable(name string) bool {
	switch strings.ToLower(name) {
	case "http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy":
		return true
	}
	return false
}

// validateMounts accepts only the two documented roles of a decoy container:
// the artifact it runs, which is always read-only, and the durable state it
// records into, which may be writable. Every other mount, mode or target
// fails closed, so a policy can never expose an unrelated host path.
func (p Policy) validateMounts() error {
	if len(p.Mounts) != 2 {
		return ErrInvalidPolicy
	}
	seen := make(map[MountRole]bool, len(p.Mounts))
	for _, mount := range p.Mounts {
		if !validTarget(mount.Source) || !validTarget(mount.Target) {
			return ErrInvalidPolicy
		}
		if seen[mount.Role] {
			return ErrInvalidPolicy
		}
		seen[mount.Role] = true
		switch mount.Role {
		case MountArtifact:
			// The artifact is the decoy process: it is read-only and it
			// always sits at the documented path.
			if !mount.ReadOnly || mount.Target != ArtifactTarget {
				return ErrInvalidPolicy
			}
		case MountState:
			// The state is the durable store of the decoy: it is writable
			// and it always sits at the documented path.
			if mount.ReadOnly || mount.Target != StateTarget {
				return ErrInvalidPolicy
			}
		default:
			return ErrInvalidPolicy
		}
	}
	if !seen[MountArtifact] || !seen[MountState] {
		return ErrInvalidPolicy
	}
	return nil
}

// pinnedImage reports whether the image reference carries a digest. A mutable
// tag is not accepted: the decoy runs the image that was recorded.
func pinnedImage(image string) bool {
	if image == "" {
		return false
	}
	_, digest, found := strings.Cut(image, "@")
	return found && strings.HasPrefix(digest, "sha256:") && len(digest) == len("sha256:")+64
}

// validUser accepts an unprivileged user identity. The decoy never runs as
// root: a root container would own the capabilities the policy drops.
func validUser(user string) bool {
	if user == "" || strings.TrimSpace(user) != user {
		return false
	}
	name, _, found := strings.Cut(user, ":")
	if !found {
		name = user
	}
	if name == "root" {
		return false
	}
	if number, err := strconv.Atoi(name); err == nil && number == 0 {
		return false
	}
	return true
}

// validTarget accepts an absolute host or container path. A path never
// contains a traversal or a volume separator.
func validTarget(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.Contains(path, "..") && !strings.Contains(path, ":")
}

// validName accepts a container name the provider can address.
func validName(name string) bool {
	if name == "" || len(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '_' || character == '.':
		default:
			return false
		}
	}
	return true
}
