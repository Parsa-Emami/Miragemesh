package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Parsa-Emami/Miragemesh/tests/acceptance"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: seed <temporary-directory>")
		os.Exit(2)
	}
	directory := os.Args[1]
	fixtureDir := "tests/fixtures/miragemesh/C30"
	if override := os.Getenv("MIRAGEMESH_C30_FIXTURES"); override != "" {
		fixtureDir = override
	}
	ctx := context.Background()
	outcome, err := acceptance.Run(ctx, acceptance.Options{Directory: directory, FixtureDir: fixtureDir})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	negative, err := acceptance.RunNegativeCases(ctx, acceptance.Options{
		Directory: filepath.Join(directory, "negative"), FixtureDir: fixtureDir,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	outcome.Negative = negative
	for _, result := range negative {
		if !result.Passed {
			fmt.Fprintf(os.Stderr, "negative case %s expected %s observed %s\n", result.Name, result.Expected, result.Observed)
			os.Exit(1)
		}
	}
	if err := acceptance.WriteOutcome(filepath.Join(directory, "outcome.json"), outcome); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(outcome); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
