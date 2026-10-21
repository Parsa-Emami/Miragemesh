package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/podman"
)

// The paths the decoy artifact sees inside its own namespace. The decoy
// process reads them from its environment; the operator never passes a
// command line to an artifact it does not own.
const (
	decoyStateVariable  = "MIRAGEMESH_DECOY_STATE"
	decoyListenVariable = "MIRAGEMESH_DECOY_LISTEN"
)

// isolationOptions is the operator configuration of the isolated decoy.
type isolationOptions struct {
	Image       string
	Artifact    string
	State       string
	MemoryBytes int64
	PidsLimit   int
	Name        string
	Listen      string
}

// isolationOutcome is the typed result of the isolated decoy workflow.
type isolationOutcome struct {
	Scope          string `json:"scope"`
	Status         string `json:"status"`
	Container      string `json:"container,omitempty"`
	Image          string `json:"image,omitempty"`
	NetworkMode    string `json:"network_mode,omitempty"`
	PidsLimit      int    `json:"pids_limit,omitempty"`
	MemoryBytes    int64  `json:"memory_bytes,omitempty"`
	EffectivePids  int64  `json:"effective_pids_limit,omitempty"`
	EffectiveBytes int64  `json:"effective_memory_bytes,omitempty"`
	EffectiveSwap  int64  `json:"effective_memory_swap_bytes,omitempty"`
	Capabilities   string `json:"effective_capabilities,omitempty"`
	Error          string `json:"error,omitempty"`
}

// runIsolation starts the isolated decoy, reports the verified isolation
// state and removes the container again. The command verifies one isolated
// decoy: it does not leave a service behind. The typed outcome is the result
// of the workflow, and it is written only after the removal succeeded.
func runIsolation(ctx context.Context, options isolationOptions) int {
	outcome := isolationOutcome{Scope: "decoy-isolation", Status: "failed"}
	policy, err := isolationPolicy(options)
	if err != nil {
		outcome.Error = err.Error()
		if !report(outcome) {
			return 1
		}
		return 2
	}
	provider, err := podman.New("podman")
	if err != nil {
		outcome.Error = err.Error()
		if !report(outcome) {
			return 1
		}
		return 1
	}
	supervisor, err := decoy.NewSupervisor(provider, policy, options.Name)
	if err != nil {
		outcome.Error = err.Error()
		if !report(outcome) {
			return 1
		}
		return 1
	}
	start, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	container, err := supervisor.Start(start)
	if err != nil {
		outcome.Error = err.Error()
		if !report(outcome) {
			return 1
		}
		return 1
	}
	state, err := supervisor.Observe(start, container.ID)
	if err != nil {
		outcome.Error = err.Error()
		outcome = removalOutcome(outcome, supervisor, container.ID)
		if !report(outcome) {
			return 1
		}
		return 1
	}
	// The removal is explicit: a workflow that leaves its container behind is
	// not a verified workflow.
	stop, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := supervisor.Stop(stop, container.ID); err != nil {
		outcome.Error = fmt.Sprintf("the isolated decoy could not be removed: %v", err)
		if !report(outcome) {
			return 1
		}
		return 1
	}
	outcome.Container = container.Name
	outcome.Image = policy.Image
	outcome.NetworkMode = state.NetworkMode
	outcome.PidsLimit = state.PidsLimit
	outcome.MemoryBytes = state.MemoryBytes
	outcome.EffectivePids = state.EffectivePidsLimit
	outcome.EffectiveBytes = state.EffectiveMemory
	outcome.EffectiveSwap = state.EffectiveSwap
	outcome.Capabilities = state.EffectiveCaps
	outcome.Status = "verified"
	if !report(outcome) {
		return 1
	}
	return 0
}

// isolationPolicy turns the operator configuration into the isolation policy.
// The durable state is prepared and checked here: the C05 adapter requires a
// private directory of the owner, and a state path that is not one is
// refused before any container is created.
func isolationPolicy(options isolationOptions) (decoy.Policy, error) {
	if options.Image == "" || options.Artifact == "" || options.State == "" {
		return decoy.Policy{}, fmt.Errorf("the isolated decoy needs an image, an artifact and a state directory")
	}
	if options.MemoryBytes <= 0 || options.PidsLimit <= 0 {
		return decoy.Policy{}, fmt.Errorf("the isolated decoy needs a memory limit and a process limit")
	}
	if err := prepareStateDirectory(options.State); err != nil {
		return decoy.Policy{}, err
	}
	policy := decoy.Policy{
		Image:   options.Image,
		Command: []string{decoy.ArtifactTarget},
		Mounts: []decoy.Mount{
			{Source: options.Artifact, Target: decoy.ArtifactTarget, Role: decoy.MountArtifact, ReadOnly: true},
			{Source: options.State, Target: decoy.StateTarget, Role: decoy.MountState},
		},
		Env: map[string]string{
			decoyStateVariable:  decoy.StateTarget,
			decoyListenVariable: options.Listen,
		},
		MemoryBytes: options.MemoryBytes,
		PidsLimit:   options.PidsLimit,
		User:        strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		Egress:      decoy.EgressDenied,
	}
	if err := policy.Validate(); err != nil {
		return decoy.Policy{}, err
	}
	return policy, nil
}

// prepareStateDirectory creates the durable state of the decoy when it is
// missing and refuses a directory that is not private to its owner.
func prepareStateDirectory(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return fmt.Errorf("the state directory %s is not usable: %v", directory, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("the state directory %s is not usable: %v", absolute, err)
		}
		if err := os.MkdirAll(absolute, 0700); err != nil {
			return fmt.Errorf("the state directory %s could not be created: %v", absolute, err)
		}
		if info, err = os.Stat(absolute); err != nil {
			return fmt.Errorf("the state directory %s is not usable: %v", absolute, err)
		}
	}
	if !info.IsDir() {
		return fmt.Errorf("the state path %s is not a directory", absolute)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("the state directory %s is not owned by the current user", absolute)
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("the state directory %s is not private: it has the mode %o", absolute, info.Mode().Perm())
	}
	return nil
}

// removalOutcome reports the failure of a workflow that could not remove its
// container.
func removalOutcome(outcome isolationOutcome, supervisor *decoy.Supervisor, id string) isolationOutcome {
	stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := supervisor.Stop(stop, id); err != nil {
		outcome.Error = fmt.Sprintf("%s; the isolated decoy could not be removed: %v", outcome.Error, err)
	}
	return outcome
}

// writeOutcome prints the typed outcome of the workflow. A result that cannot
// be delivered is an error: a caller must never read a silent success as a
// verified isolation.
func writeOutcome(writer io.Writer, outcome isolationOutcome) error {
	return json.NewEncoder(writer).Encode(outcome)
}

// report writes the typed outcome of the workflow and reports whether it could
// be delivered.
func report(outcome isolationOutcome) bool {
	if err := writeOutcome(os.Stdout, outcome); err != nil {
		fmt.Fprintln(os.Stderr, "Unable to write the isolation outcome:", err)
		return false
	}
	return true
}
