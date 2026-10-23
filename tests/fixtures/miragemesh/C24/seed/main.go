package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

func main() {
	if len(os.Args) != 2 {
		panic("one temporary directory required")
	}
	directory := os.Args[1]
	now := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	m := fixture.Generate(now, "sensor-24")
	for name, content := range map[string]string{"issuer.pem": m.Authority, "issuer-key.pem": m.AuthorityKey, "initial.pem": m.Initial, "initial-key.pem": m.InitialKey, "next-csr.pem": m.CSR, "next-key.pem": m.Key, "recovery-csr.pem": m.RecoveryCSR, "recovery-key.pem": m.RecoveryKey, "server.pem": m.Server, "server-key.pem": m.ServerKey, "crl.pem": m.CRL} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			panic(err)
		}
	}
	store, err := storage.Open(filepath.Join(directory, "state"), storage.Limits{MaxOperations: 128, MaxBytes: 2097152, MaxManifestBytes: 131072})
	if err != nil {
		panic(err)
	}
	defer store.Close()
	r, err := pki.NewRotator(context.Background(), store, pki.RotationOptions{IssuerCertificatePEM: m.Authority, MaxSensors: 16, MaxLifetime: 24 * time.Hour, MaxOverlap: time.Hour, MaxRecoveryTTL: 15 * time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		panic(err)
	}
	if _, err := r.Register(context.Background(), pki.RegisterCertificate{SensorID: "sensor-24", CertificatePEM: m.Initial, IdempotencyKey: "c24-seed-register-key"}); err != nil {
		panic(err)
	}
	block, _ := pem.Decode([]byte(m.AuthorityKey))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	if _, err := r.Rotate(context.Background(), pki.RotateCertificate{SensorID: "sensor-24", ExpectedRevision: 1, CSRPEM: m.CSR, Lifetime: 24 * time.Hour, Overlap: time.Hour, IdempotencyKey: "c24-seed-rotate-key"}, key.(crypto.Signer)); err != nil {
		panic(err)
	}
}
