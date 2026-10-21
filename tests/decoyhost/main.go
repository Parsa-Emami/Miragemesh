// Command decoyhost runs the real C12 decoy service inside the isolated
// container of the C13 tests.
//
// It is a test fixture, not a product listener: it is never shipped, it opens
// no public surface and it exists only so that the C12 handler itself runs
// under the C13 isolation policy. The probe modes measure the isolation from
// inside the container, so the proof does not depend on the tools of the base
// image.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		os.Exit(probe(os.Args[2:]))
	}
	os.Exit(serve(os.Args[1:]))
}

// serve runs the C12 decoy handler against a durable store.
func serve(args []string) int {
	flags := flag.NewFlagSet("decoyhost", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8080", "loopback listen address of the decoy")
	directory := flags.String("store", "", "durable store directory of the decoy")
	sensorID := flags.String("sensor-id", "decoy-01", "identity of the decoy observations")
	maxRequest := flags.Int64("max-request-bytes", 1024, "largest accepted request body")
	maxPath := flags.Int("max-path-bytes", 256, "largest accepted path")
	maxOperations := flags.Int("store-max-operations", 64, "durable operation limit")
	maxBytes := flags.Int64("store-max-bytes", 1048576, "durable byte limit")
	maxManifest := flags.Int64("store-max-manifest-bytes", 262144, "durable manifest limit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// The engine workflow passes the paths of the decoy through the
	// environment of the container.
	if *directory == "" {
		*directory = os.Getenv("MIRAGEMESH_DECOY_STATE")
	}
	if *listen == "127.0.0.1:8080" {
		if address := os.Getenv("MIRAGEMESH_DECOY_LISTEN"); address != "" {
			*listen = address
		}
	}
	if *directory == "" {
		fmt.Fprintln(os.Stderr, "a store directory is required")
		return 2
	}
	store, err := storage.Open(*directory, storage.Limits{
		MaxOperations:    *maxOperations,
		MaxBytes:         *maxBytes,
		MaxManifestBytes: *maxManifest,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service, err := decoy.New(ctx, store, decoy.Options{
		SensorID:        *sensorID,
		MaxRequestBytes: *maxRequest,
		MaxPathBytes:    *maxPath,
		Clock:           time.Now,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "decoy:", err)
		return 1
	}
	server := &http.Server{
		Handler:           service,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	fmt.Printf("{\"decoy\":\"%s\",\"address\":\"%s\"}\n", *sensorID, listener.Addr().String())
	stopped := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stopped <- server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	<-stopped
	return 0
}

// probe measures the isolation from inside the container.
func probe(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "a probe is required")
		return 2
	}
	switch args[0] {
	case "egress":
		return probeEgress(args[1:])
	case "fork":
		return probeFork(args[1:])
	case "allocate":
		return probeAllocate(args[1:])
	case "status":
		return probeStatus(args[1:])
	case "request":
		return probeRequest(args[1:])
	case "noop":
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown probe")
	return 2
}

// probeEgress attempts one outbound connection. A refused or unreachable
// destination proves that the container has no route to it.
func probeEgress(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "a destination is required")
		return 2
	}
	connection, err := net.DialTimeout("tcp", args[0], 3*time.Second)
	if err == nil {
		connection.Close()
		fmt.Printf("{\"connected\":true,\"destination\":\"%s\"}\n", args[0])
		return 1
	}
	fmt.Printf("{\"connected\":false,\"destination\":\"%s\",\"error\":\"%s\"}\n", args[0], err)
	return 0
}

// probeFork starts child processes until the process limit refuses one.
func probeFork(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "a child count is required")
		return 2
	}
	count, err := strconv.Atoi(args[0])
	if err != nil || count <= 0 {
		fmt.Fprintln(os.Stderr, "a positive child count is required")
		return 2
	}
	started := 0
	refused := false
	children := make([]*os.Process, 0, count)
	for index := 0; index < count; index++ {
		child, err := os.StartProcess(os.Args[0], []string{os.Args[0], "probe", "noop"}, &os.ProcAttr{})
		if err != nil {
			refused = true
			break
		}
		children = append(children, child)
		started++
	}
	for _, child := range children {
		_, _ = child.Wait()
	}
	fmt.Printf("{\"started\":%d,\"refused\":%t}\n", started, refused)
	if refused {
		return 0
	}
	return 1
}

// probeAllocate allocates memory inside the container limit. The memory is
// mapped outside the Go heap on purpose: the runtime would report the failed
// allocation with a profile file in the working directory, while the kernel
// limit of the container ends the process without a side effect.
func probeAllocate(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "a byte count is required")
		return 2
	}
	size, err := strconv.Atoi(args[0])
	if err != nil || size <= 0 {
		fmt.Fprintln(os.Stderr, "a positive byte count is required")
		return 2
	}
	// The runtime writes a memory profile into the working directory when it
	// cannot allocate. The read-only root of the container is used so that the
	// probe leaves no file behind.
	_ = os.Chdir("/")
	region, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		fmt.Printf("{\"refused\":true,\"error\":\"%s\"}\n", err)
		return 0
	}
	defer syscall.Munmap(region)
	for offset := 0; offset < len(region); offset += 4096 {
		region[offset] = 1
	}
	fmt.Printf("{\"allocated\":%d}\n", len(region))
	return 1
}

// probeRequest calls the decoy inside the container and reports the answer.
func probeRequest(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "an address and a path are required")
		return 2
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + args[0] + args[1])
	if err != nil {
		fmt.Printf("{\"error\":\"%s\"}\n", err)
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		fmt.Printf("{\"error\":\"%s\"}\n", err)
		return 1
	}
	fmt.Printf("{\"status\":%d,\"body\":%s}\n", response.StatusCode, strconv.Quote(string(body)))
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// probeStatus reports the effective isolation state of the container.
func probeStatus(args []string) int {
	status := struct {
		Capabilities  string   `json:"capabilities"`
		PidsMax       string   `json:"pids_max"`
		MemoryMax     string   `json:"memory_max"`
		MemorySwapMax string   `json:"memory_swap_max"`
		MemoryEvents  string   `json:"memory_events"`
		Routes        []string `json:"routes"`
	}{
		Routes: []string{},
	}
	status.Capabilities = readValue("/proc/self/status", "CapEff:")
	status.PidsMax = readValue("/sys/fs/cgroup/pids.max", "")
	status.MemoryMax = readValue("/sys/fs/cgroup/memory.max", "")
	status.MemorySwapMax = readValue("/sys/fs/cgroup/memory.swap.max", "")
	status.MemoryEvents = readValue("/sys/fs/cgroup/memory.events", "")
	status.Routes = readRoutes("/proc/net/route")
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(status); err != nil {
		return 1
	}
	return 0
}

// readValue returns one value of a file. Without a prefix the whole content
// is returned; with a prefix the value behind it is returned.
func readValue(path, prefix string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if prefix == "" {
		return strings.TrimSpace(string(data))
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

// readRoutes returns the routes of the container namespace without the header
// line of the kernel report.
func readRoutes(path string) []string {
	routes := []string{}
	for _, line := range readLines(path) {
		if line == "" || strings.HasPrefix(line, "Iface") {
			continue
		}
		routes = append(routes, line)
	}
	return routes
}

// readLines returns the lines of a file.
func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}
