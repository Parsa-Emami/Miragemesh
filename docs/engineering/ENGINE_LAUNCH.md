# Local Go runtime lifecycle (C03)

The C03 runtime is a real Go HTTP process with lifecycle/health only. It does not enroll sensors, process events, persist state, authenticate domain operations or run decoys. C04 defines domain contracts, C05 proves the compatible ADR-0003 storage adapter, and C06 adds dedicated engine integration CI. C17 remains dependency-blocked.

## Prepare and run

Supported evidence profile: Linux amd64. Install Git, Node 24.19.0, Go (1.21+ supports managed toolchains), and rootless Podman 4.9.3. The reference provider package is Ubuntu 24.04's 4.9.3+ds1-1ubuntu0.2. The operator installs prerequisites; setup never uses sudo, installs a global runtime, changes trust, provisions containers or edits environment files.

```sh
npx --yes --package=npm@11.9.0 --call 'npm run setup'
npx --yes --package=npm@11.9.0 --call 'npm start'
```

Setup selects exactly Go 1.27.2 via process-local GOTOOLCHAIN, with the official proxy and checksum database. Initial preparation may download the compiler and locked npm dependencies. Startup only executes the built local binary and makes loopback health requests. The runtime has no external client, container execution or payload admission.

`setup -- --check` lists prerequisites/steps without probes, download, installation or build. `--skip-install` still checks prerequisites and builds both outputs. A failed Go build removes its own staging directory and preserves the previous binary; it never reports setup success. `doctor` checks real tool/provider versions, rootless operation and the built binary's version; it does not claim the service is currently running or the product ready.

The web defaults to 127.0.0.1:4173; use `npm start -- --port 4307` for another port. Port 0 chooses a free port and prints it for isolated tests. Existing --host (loopback only), --root and --config options remain supported. The owned engine uses an automatically assigned IPv4 loopback port. No engine destination comes from browser configuration.

## Health and shutdown

The launcher starts dist/engine/miragemesh directly, waits for its bounded startup record and actual health, then starts the existing Node web server. Startup has a ten-second deadline. Its ready record reports the web port, engine address/PID and coreReady=false. The engine supports --version without opening a listener.

GET/HEAD `/api/engine/health` reads `/healthz` from the owned engine. A valid response is `{ "status": "ok", "scope": "engine-runtime", "version": "0.0.1", "toolchain": "go1.27.2", "coreReady": false }`. Non-200, redirects, malformed/oversized (>4096-byte) responses and a two-second timeout yield 503. Other domain routes remain unavailable and mutations return 405. Browser status refreshes every five seconds; failed health does not disable the existing local preview.

Web `/healthz` and `/readyz` retain their web-shell meaning; engineReady=false and coreReady=false never certify domain readiness. The public engineEnabled flag remains false. Health contains no credentials, data directory or configuration values. The loopback endpoint supplies no domain commands, so it does not substitute for the identity/object permissions required with future APIs.

SIGINT/SIGTERM stop both services, with a ten-second outer deadline and a five-second Go HTTP shutdown deadline. An unexpected child exit fails the supervisor and closes the web listener. The Go process also watches supervisor stdin: EOF stops it if the supervisor dies. Only the owned child is signalled. Occupied ports fail without stopping the existing owner. Restart with npm start; no C03 user data needs restoration. Later durable-state recovery belongs to C05 and C30.

## Tests and official sources

Use the pinned npm CLI for npm test, typecheck, build, browser, clone and package commands. Use `GOTOOLCHAIN=go1.27.2 GOSUMDB=sum.golang.org GOPROXY='https://proxy.golang.org|direct'` for `go test ./...`, `go vet ./...` and `gofmt -l cmd/miragemesh`. Go tests and Node subprocess tests exercise actual sockets/processes. Synthetic upstream failures verify rejection only; they are not evidence of provider durability or identity.

The existing web workflow prepares the pinned Go/Podman prerequisites on Ubuntu 24.04; the dedicated runtime integration workflow remains C06. package:web still ships a web-only artifact and cannot run the engine. Local workflow commands do not certify a remote Actions run.

Sources: [Go toolchain selection](https://go.dev/doc/toolchain), [Go HTTP shutdown](https://pkg.go.dev/net/http#Server.Shutdown), [Node child processes](https://nodejs.org/docs/latest-v24.x/api/child_process.html). Go uses its BSD-3-Clause standard library; no third-party Go modules or synthetic go.sum are added.
