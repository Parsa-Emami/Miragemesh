package fixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

type Material struct {
	Authority    string `json:"authority"`
	AuthorityKey string `json:"authority_key"`
	Server       string `json:"server"`
	ServerKey    string `json:"server_key"`
	Initial      string `json:"initial"`
	InitialKey   string `json:"initial_key"`
	CSR          string `json:"csr"`
	Key          string `json:"key"`
	RecoveryCSR  string `json:"recovery_csr"`
	RecoveryKey  string `json:"recovery_key"`
	CRL          string `json:"crl"`
}

func Private(key ed25519.PrivateKey) string {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

func NewCSR(sensor string) (string, string) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: sensor}}, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), Private(key)
}

func Generate(now time.Time, sensor string) Material {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "C24 synthetic authority"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(730 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte("C24-synthetic-authority")}
	raw, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		panic(err)
	}
	authority, err := x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	result := Material{Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), AuthorityKey: Private(key)}
	issue := func(serial int64, server bool) (string, string) {
		pub, leafKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: sensor}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		raw, err := x509.CreateCertificate(rand.Reader, template, authority, pub, key)
		if err != nil {
			panic(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), Private(leafKey)
	}
	result.Initial, result.InitialKey = issue(2, false)
	result.Server, result.ServerKey = issue(3, true)
	result.CSR, result.Key = NewCSR(sensor)
	result.RecoveryCSR, result.RecoveryKey = NewCSR(sensor)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(47 * time.Hour)}, authority, key)
	if err != nil {
		panic(err)
	}
	result.CRL = string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}))
	return result
}
