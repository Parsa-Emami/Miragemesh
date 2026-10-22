# C13: decoy isolation

The decoy runs inside a rootless container that has no network at all, no
capabilities, no host namespace and a read-only root filesystem, and that is
bounded by a hard process and memory limit. The C13 code states the policy,
applies it through the container runtime and then verifies what the runtime
actually did. It never reports an unverified decoy.

## The policy

```go
policy := decoy.Policy{
    Image:   "docker.io/library/alpine@sha256:865b95f4…",
    Command: []string{"/usr/local/bin/decoy"},
    Mounts: []decoy.Mount{
        {Source: artifact, Target: decoy.ArtifactTarget, Role: decoy.MountArtifact, ReadOnly: true},
        {Source: state, Target: decoy.StateTarget, Role: decoy.MountState},
    },
    Env:          map[string]string{"MIRAGEMESH_DECOY_STATE": "/var/lib/miragemesh"},
    MemoryBytes:  67108864,
    PidsLimit:    32,
    User:         "1000:1000",
    Egress:       decoy.EgressDenied,
}
supervisor, err := decoy.NewSupervisor(provider, policy, "miragemesh-decoy")
container, err := supervisor.Start(ctx)
```

`Policy.Validate` fails closed. There is no default posture and no hidden
limit: the image must carry a digest, the command must exist, the limits must
be positive, the user must be unprivileged and the egress posture must be
`denied`. A request for any other egress posture is an explicit error, so the
decoy has no way to ask for outbound access. The environment of the decoy may
not carry a proxy setting.

The mounts are limited to the two documented roles and to their fixed container
targets. A policy carries exactly one artifact mount, which is read-only and
sits at `/usr/local/bin/decoy`, and exactly one state mount, which is writable
and sits at `/var/lib/miragemesh`. Every other role, target, mode or number of
mounts fails closed, so a policy can never expose an unrelated host path to the
decoy.

The provider checks the host side of the mounts before it creates anything:
the artifact must be a regular file and the state must be a directory. The
engine prepares the state directory when it is missing and refuses one that is
not a private directory of the owner, because the C05 adapter requires mode
`0700` and the identity of the operator. A state path that is not such a
directory is an explicit failure before any container exists.

The supervisor owns a copy of the policy. A caller that changes the policy it
passed in, or the policy the supervisor returns, does not change what was
validated and what the provider receives.

## The provider

`internal/podman` is the only package of the engine that runs another
program. It runs exactly one program, the container runtime named by the
deployment, with a fixed argument vector and without a shell. It has no
network client of its own, and it never pulls an image: the pinned image must
already be present locally and every run refuses an implicit pull, so
starting a decoy never reaches a registry.

The runtime call carries the isolation of the policy:

| Argument | Effect |
| --- | --- |
| `--network=none` | no interface, no route, no DNS: no Internet and no operational private subnet |
| `--ipc=none --uts=private --pid=private --cgroupns=private` | no host namespace is shared |
| `--userns=keep-id` | the durable state keeps the identity of the operator |
| `--cap-drop=ALL --security-opt=no-new-privileges` | no capability and no privilege gain |
| `--read-only` and an unprivileged `--user` | no writable root filesystem and no root process |
| `--pids-limit` and `--memory` with `--memory-swap` | hard process and memory limits without swap headroom |
| `--pull=never` | the runtime never contacts a registry |
| `--http-proxy=false` | the runtime copies no proxy setting of the host, not even a credential |
| `--env http_proxy= …` | no inherited proxy: an egress attempt cannot be tunnelled through the operator's proxy |

The provider reports the runtime version, the rootless state and the presence
of the image before it starts anything. A runtime that is not rootless, a
missing image and a missing runtime are explicit errors.

The call follows the context of the caller and stays bounded: the runtime and
the children it starts end with the call, and only the first bytes of its
output are kept, so a noisy runtime cannot grow the memory of the engine.

## The verification

`Supervisor.Start` reconciles a container left behind by an earlier supervisor,
starts the decoy, waits for it to reach the running state and then compares the
observed state with the policy: the network mode, the requested limits, the
read-only root filesystem, the user and the privilege protection. The
**effective** controls are verified as well: the capability set of the
container process must be empty, the control group of the container must carry
the process limit and the memory limit of the policy, and its swap limit must
be zero. A container that does not match the policy is removed and reported
as an explicit failure, and a removal that fails is reported together with the
failure that caused it, so a container that stayed behind is never hidden.

The limit is only proven when the runtime enforces it. A rootless runtime
without cgroup delegation cannot apply the memory limit, the effective limits
are then not observed and the supervisor fails. The limit is never reported as
held because it was requested.

## The reconciliation

A decoy container is never reused across supervisor restarts. A supervisor
removes a container of an earlier run only after its installation ownership
marker matches, starts a fresh one and verifies it again. The durable state of the decoy lives outside the container, in the C05
store, so the observations of the earlier container survive the restart.

`Supervisor.Stop` removes the container and the resources it owns. Removing a
container that is already gone is not an error, so the cleanup is idempotent
and leaves no leaked runtime resource behind.

## The supported workflow

The engine starts the isolated decoy and reports its typed outcome:

```sh
miragemesh --decoy-isolation \
  --decoy-image docker.io/library/alpine@sha256:865b95f4… \
  --decoy-artifact "$HOME/.local/lib/miragemesh/decoy" \
  --decoy-state "$HOME/.local/state/miragemesh" \
  --decoy-memory-bytes 67108864 --decoy-pids-limit 32
```

The command verifies one isolated decoy: it starts the container, verifies the
isolation, reports the outcome and removes the container again. It does not
leave a service behind, and a removal that fails is reported as a failed
outcome with a non zero status instead of a success. A result that cannot be
delivered is an error as well: the command never reports a success that no
caller received.

The outcome is a JSON document on the standard output:

```json
{"scope":"decoy-isolation","status":"verified","container":"miragemesh-decoy","network_mode":"none","effective_pids_limit":32,"effective_memory_bytes":67108864,"effective_memory_swap_bytes":0,"effective_capabilities":"0000000000000000"}
```

The decoy process receives the paths of its own namespace through the
environment (`MIRAGEMESH_DECOY_STATE`, `MIRAGEMESH_DECOY_LISTEN`); the
operator never passes a command line to an artifact it does not own. The
workflow removes the container again and exits with a non zero status when the
isolation is not proven.

The signals of the operator reach the runtime calls: an interrupted command
cancels the call, the runtime and the children it started end with it, and the
container that a start call may have created is removed by its known name with
a separate bounded cleanup.

## Not proven here

The container has no network at all, so the decoy address is reachable only
from inside its own namespace. Publishing the decoy to untrusted peers needs a
controlled inbound path that keeps the outbound denial, and that is later
workflow work. C13 also proves nothing about a remote runner, about a public
decoy surface or about the capacity of the C28 hardware target.

The image is pinned by digest and recorded in
`docs/engineering/toolchain-lock.json` with its provenance and the license of
every component it carries. MirageMesh neither redistributes nor modifies the
image.

The command vector follows the Podman run documentation
(<https://docs.podman.io/en/v4.9.3/markdown/podman-run.1.html>) and the
image is pulled with the digest form of the runtime pull
(<https://docs.podman.io/en/v4.9.3/markdown/podman-pull.1.html>).

## Ownership and safe rollback (C01–C21 review remediation)

Every new container carries `io.miragemesh.owner` and `io.miragemesh.run` labels.
The owner is SHA-256 of the container name, configured user and state-mount
source, separated by NUL bytes. The run token is 16 cryptographically random
bytes rendered as hex. Labels are local ownership markers, not authentication
against a same-UID attacker.

Reconciliation checks the owner before removing the inspected immutable ID.
A name belonging to another installation, including an unlabeled legacy
container, returns typed `ErrOwnershipConflict` without removal. The operator
must inspect and explicitly resolve an unlabeled legacy container; the engine
never guesses ownership or deletes it automatically.

An uncertain start inspects using a separate bounded cleanup context. Rollback
requires both owner and this exact run token, then removes only the inspected
ID. A competing run that loses a name collision cannot delete the winner.
Real-provider regressions exercise these collisions and preserve the original
running container. The cancellation regression also checks that a container
was actually created before cancellation and that cleanup uses its ID.

Official API: [Podman 4.9.3 run labels](https://docs.podman.io/en/v4.9.3/markdown/podman-run.1.html).
