package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func TestC37AcceptedFixtureSurvivesRestartAndRejectsInvalidRetry(t *testing.T) {
	load := func(name string) json.RawMessage {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "fixtures", "miragemesh", "C37", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Version    int             `json:"fixture_version"`
			License    string          `json:"license"`
			Provenance string          `json:"provenance"`
			Event      json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		if fixture.Version != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" {
			t.Fatal("unsupported or unlicensed C37 fixture")
		}
		return fixture.Event
	}
	valid, invalid := load("positive"), load("negative")
	directory := filepath.Join(t.TempDir(), "state")
	expectedRaw, err := os.ReadFile(filepath.Join("..", "fixtures", "miragemesh", "C37", "expected-output.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Generation uint64 `json:"recorded_generation"`
		License    string `json:"license"`
		Version    int    `json:"fixture_version"`
	}
	if err := json.Unmarshal(expectedRaw, &expected); err != nil || expected.Version != 1 || expected.License != "Apache-2.0" || expected.Generation != 1 {
		t.Fatal("invalid C37 expected outcomes")
	}
	limits := storage.Limits{MaxOperations: 16, MaxBytes: 1048576, MaxManifestBytes: 65536}
	store, err := storage.Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sensor.Accept(context.Background(), store, valid)
	if err != nil || receipt.Generation != expected.Generation {
		t.Fatalf("initial acceptance: %+v %v", receipt, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for restart := 0; restart < 2; restart++ {
		reopened, err := storage.Open(directory, limits)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sensor.Accept(context.Background(), reopened, invalid); !errors.Is(err, sensor.ErrInvalidEvent) {
			reopened.Close()
			t.Fatalf("invalid event: %v", err)
		}
		replay, err := sensor.Accept(context.Background(), reopened, valid)
		if err != nil || replay != receipt {
			reopened.Close()
			t.Fatalf("replayed acceptance: %+v %v", replay, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("restart/invalid retry changed accepted manifest: %v", err)
		}
	}
}
