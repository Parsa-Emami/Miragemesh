package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"github.com/Parsa-Emami/Miragemesh/internal/update"
	f "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C25"
)

func main() {
	if len(os.Args) != 2 {
		panic("temporary fixture directory required")
	}
	dir := os.Args[1]
	m := f.Generate()
	now := time.Now().UTC().Add(-time.Minute)
	write := func(name string, raw []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			panic(err)
		}
	}
	write("publisher.pub", m.Publisher.Public().(ed25519.PublicKey))
	write("recovery.pub", m.Recovery.Public().(ed25519.PublicKey))
	for _, n := range []uint64{2, 4} {
		name := "release-2.bin"
		if n == 4 {
			name = "release-4.bin"
		}
		write(name, f.Artifact(n))
	}
	for _, rev := range []uint64{1, 2, 3} {
		revoked := []uint64{3}
		versions := []uint64{2, 4}
		name := "metadata-1"
		if rev == 2 {
			name = "metadata-2"
		}
		if rev == 3 {
			name = "metadata-3"
		}
		if rev > 1 {
			revoked = []uint64{3, 4}
			versions = []uint64{2}
		}
		p := f.Metadata(now, rev, "sensor-25", revoked, versions...)
		write(name+".json", p)
		write(name+".sig", ed25519.Sign(m.Publisher, p))
	}
	g := f.Grant(time.Now().UTC(), "recovery-25", "sensor-25", 2, 4, 2)
	write("grant.json", g)
	write("grant.sig", ed25519.Sign(m.Recovery, g))
	s, err := storage.Open(filepath.Join(dir, "state"), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	if err != nil {
		panic(err)
	}
	defer s.Close()
	v, err := update.New(context.Background(), s, update.Options{PublisherKey: m.Publisher.Public().(ed25519.PublicKey), RecoveryKey: m.Recovery.Public().(ed25519.PublicKey), Platform: "linux/amd64", MaxSensors: 16, MaxArtifactBytes: 1048576, MaxMetadataTTL: time.Hour, MaxRecoveryTTL: 10 * time.Minute, Clock: time.Now})
	if err != nil {
		panic(err)
	}
	p := f.Metadata(now, 1, "sensor-25", []uint64{3}, 2, 4)
	if _, err = v.Accept(context.Background(), p, ed25519.Sign(m.Publisher, p)); err != nil {
		panic(err)
	}
	if _, err = v.Verify(context.Background(), update.Request{SensorID: "sensor-25", Version: 4, Artifact: bytes.NewReader(f.Artifact(4))}); err != nil {
		panic(err)
	}
}
