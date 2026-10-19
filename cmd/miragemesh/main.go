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
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

const version = "0.0.1"

func health() map[string]any {
	return map[string]any{"status": "ok", "scope": "engine-runtime", "version": version, "toolchain": runtime.Version(), "coreReady": false}
}

func serve(ctx context.Context, address string, ready io.Writer) error {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 0 || number > 65535 || (host != "127.0.0.1" && host != "::1") {
		return errors.New("engine listen address must be loopback with a valid port")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path != "/healthz" {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"not_found"}`)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				io.WriteString(w, `{"error":"method_not_allowed"}`)
				return
			}
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(health())
			}
		}),
	}
	if err := json.NewEncoder(ready).Encode(map[string]any{"service": "miragemesh-engine", "address": listener.Addr().String(), "pid": os.Getpid()}); err != nil {
		return err
	}
	stopped := make(chan error, 1)
	served := make(chan struct{})
	defer close(served)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(shutdown)
			if err != nil {
				server.Close()
			}
			stopped <- err
		case <-served:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return <-stopped
	}
	return err
}

func main() {
	address := flag.String("listen", "127.0.0.1:0", "loopback listen address")
	showVersion := flag.Bool("version", false, "print runtime version and exit")
	validate := flag.Bool("validate-event", false, "validate one v1 event from stdin without accepting or storing it")
	flag.Parse()
	validationFlag := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "validate-event" {
			validationFlag = true
		}
	})
	if validationFlag {
		if !*validate || len(os.Args) != 2 || os.Args[1] != "--validate-event" {
			fmt.Fprintln(os.Stderr, "--validate-event must be used alone")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, contracts.ValidationTimeout)
		defer cancel()
		result := contracts.Validate(ctx, os.Stdin, version)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "Unable to write validation result")
			os.Exit(1)
		}
		if !result.Result.Valid {
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected engine arguments")
		os.Exit(2)
	}
	if *showVersion {
		json.NewEncoder(os.Stdout).Encode(health())
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The supervisor owns stdin; EOF also stops the engine after supervisor death.
	go func() { io.Copy(io.Discard, os.Stdin); stop() }()
	if err := serve(ctx, *address, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
