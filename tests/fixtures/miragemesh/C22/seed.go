package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Parsa-Emami/Miragemesh/internal/events"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

func main() {
	if len(os.Args) != 2 {
		panic("one temporary directory required")
	}
	ctx := context.Background()
	store, err := storage.Open(filepath.Join(os.Args[1], "state"), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	if err != nil {
		panic(err)
	}
	defer store.Close()
	writer, err := events.Open(filepath.Join(os.Args[1], "segments"), events.Limits{MaxSegments: 16, MaxRecordsPerSegment: 2, MaxBytesPerSegment: 32768})
	if err != nil {
		panic(err)
	}
	defer writer.Close()
	raw, err := os.ReadFile("tests/fixtures/miragemesh/C22/positive.json")
	if err != nil {
		panic(err)
	}
	var fixture struct {
		SourceEvents []string `json:"source_events"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}
	for _, event := range fixture.SourceEvents {
		if _, err := sensor.Accept(ctx, store, []byte(event)); err != nil {
			panic(err)
		}
		if _, err := writer.Append(ctx, []byte(event)); err != nil {
			panic(err)
		}
	}
}
