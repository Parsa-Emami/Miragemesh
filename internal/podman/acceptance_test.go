package podman

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestC37ProviderHonorsPrecancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := &Provider{binary: os.Args[0], timeout: time.Second}
	_, _, err := provider.run(ctx, "-test.run=TestC37ProviderProcess")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled runtime error: %v", err)
	}
}

func TestC37ProviderCancellationReturnsTypedError(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ready")
	provider := &Provider{binary: os.Args[0], timeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := provider.run(ctx, "-test.run=TestC37ProviderProcess", "--", marker); done <- err }()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("runtime ended before readiness: %v", err)
		case <-deadline:
			t.Fatal("runtime did not start")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("running cancellation error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled runtime did not terminate")
	}
}

func TestC37ProviderProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			if err := os.WriteFile(os.Args[i+1], []byte("ready"), 0600); err != nil {
				os.Exit(8)
			}
			time.Sleep(60 * time.Second)
			os.Exit(0)
		}
	}
}
