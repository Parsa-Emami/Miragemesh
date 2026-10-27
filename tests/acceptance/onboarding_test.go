package acceptance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

func TestC36OnboardingEventFixtures(t *testing.T) {
	for _, name := range []string{"positive", "negative"} {
		raw, err := os.ReadFile(filepath.Join("..", "fixtures", "miragemesh", "C36", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			FixtureVersion int             `json:"fixture_version"`
			License        string          `json:"license"`
			Provenance     string          `json:"provenance"`
			Event          json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		if fixture.FixtureVersion != 1 || fixture.License != "Apache-2.0" || fixture.Provenance == "" {
			t.Fatalf("unlicensed fixture %s", name)
		}
		_, decodeError := contracts.DecodeEvent(context.Background(), fixture.Event)
		if (name == "positive") != (decodeError == nil) {
			t.Fatalf("%s decode: %v", name, decodeError)
		}
	}
}

func TestC36IndependentOnboardingPreservesReferenceWorkflow(t *testing.T) {
	roots := []string{filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "independent")}
	var previous Outcome
	for i, root := range roots {
		outcome, err := Run(context.Background(), Options{Directory: root, FixtureDir: fixtures(t)})
		if err != nil {
			t.Fatal(err)
		}
		checkExpected(t, outcome)
		negative, err := RunNegativeCases(context.Background(), Options{Directory: filepath.Join(root, "negative"), FixtureDir: fixtures(t)})
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range negative {
			if !result.Passed || result.Observed != result.Expected {
				t.Fatalf("negative: %+v", result)
			}
		}
		if i > 0 && (previous.Runtime.StateDir == outcome.Runtime.StateDir || previous.Result.ManifestDigest == outcome.Result.ManifestDigest) {
			t.Fatal("independent onboarding reused accepted state or identity")
		}
		previous = outcome
	}
}
