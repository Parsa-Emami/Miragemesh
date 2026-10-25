package acceptance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/collector"
	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/spool"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	c24fixture "github.com/Parsa-Emami/Miragemesh/tests/fixtures/miragemesh/C24"
)

// RunNegativeCases executes the required negative cases against fresh local
// state. A case that does not observe its declared typed outcome is reported
// as failed instead of being treated as a skipped success.
func RunNegativeCases(ctx context.Context, options Options) ([]NegativeResult, error) {
	if ctx == nil || options.Directory == "" || options.FixtureDir == "" {
		return nil, ErrInvalidOptions
	}
	fixtures, err := Load(options.FixtureDir)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if options.Now != nil {
		now = options.Now().UTC().Truncate(time.Second)
	}
	root, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	results := make([]NegativeResult, 0, len(fixtures.Negative.Cases))
	for _, testCase := range fixtures.Negative.Cases {
		result := NegativeResult{Name: testCase.Name, Expected: testCase.Expected}
		observed, err := runNegativeCase(ctx, fixtures, testCase, filepath.Join(root, testCase.Name), now)
		if err != nil {
			return nil, fmt.Errorf("acceptance: negative case %s: %w", testCase.Name, err)
		}
		result.Observed = observed
		result.Passed = observed == testCase.Expected
		results = append(results, result)
	}
	return results, nil
}

func runNegativeCase(ctx context.Context, fixtures Fixtures, testCase NegativeCase, dir string, now time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	switch testCase.Name {
	case "enrollment-token-replay":
		return negativeTokenReplay(ctx, fixtures, dir)
	case "untrusted-client-certificate":
		return negativeUntrustedCertificate(ctx, fixtures, dir, now)
	case "unconfigured-batch-ingest":
		return negativeUnconfiguredIngest(ctx, fixtures, dir)
	case "malformed-event":
		return negativeMalformedEvent(ctx, fixtures, dir)
	case "spool-overflow":
		return negativeSpoolOverflow(ctx, fixtures, dir, now)
	case "missing-fixture":
		if _, err := Load(filepath.Join(dir, "missing")); !errors.Is(err, ErrFixture) {
			return fmt.Sprintf("%v", err), nil
		}
		return "acceptance.ErrFixture", nil
	default:
		return "", ErrFixture
	}
}

func negativeTokenReplay(ctx context.Context, fixtures Fixtures, dir string) (string, error) {
	store, err := storage.Open(filepath.Join(dir, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return "", err
	}
	defer store.Close()
	service, err := enrollment.New(store, time.Duration(fixtures.Positive.EnrollmentTTLSecond)*time.Second, time.Now)
	if err != nil {
		return "", err
	}
	token, err := service.Issue(ctx, fixtures.Positive.SensorID, time.Duration(fixtures.Positive.EnrollmentTTLSecond)*time.Second)
	if err != nil {
		return "", err
	}
	if _, err := service.Consume(ctx, token.Token, fixtures.Positive.SensorID); err != nil {
		return "", err
	}
	if _, err := service.Consume(ctx, token.Token, fixtures.Positive.SensorID); !errors.Is(err, enrollment.ErrReplay) {
		return fmt.Sprintf("%v", err), nil
	}
	return "enrollment.ErrReplay", nil
}

func negativeUntrustedCertificate(ctx context.Context, fixtures Fixtures, dir string, now time.Time) (string, error) {
	store, err := storage.Open(filepath.Join(dir, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return "", err
	}
	defer store.Close()
	guard, material, err := newGuard(ctx, store, fixtures, now)
	if err != nil {
		return "", err
	}
	before, err := manifestDigest(filepath.Join(dir, "state"))
	if err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	verdict := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			verdict <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, guard.TLSConfig())
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		_, handshakeErr := guard.Authenticate(tlsConn)
		verdict <- handshakeErr
	}()
	client, err := rogueClient(material, now)
	if err != nil {
		return "", err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, _ := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), client)
	if conn != nil {
		conn.Close()
	}
	// A client-side TLS 1.3 handshake can complete before the server validates
	// the certificate, so the server verdict is authoritative here.
	select {
	case serverErr := <-verdict:
		if serverErr == nil {
			return "", errors.New("acceptance: untrusted handshake was accepted")
		}
	case <-time.After(5 * time.Second):
		return "", errors.New("acceptance: untrusted handshake was not rejected")
	}
	after, err := manifestDigest(filepath.Join(dir, "state"))
	if err != nil {
		return "", err
	}
	if before != after {
		return "", errors.New("acceptance: rejected identity changed durable state")
	}
	return "tls.handshake_rejected", nil
}

func negativeUnconfiguredIngest(ctx context.Context, fixtures Fixtures, dir string) (string, error) {
	store, err := storage.Open(filepath.Join(dir, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return "", err
	}
	defer store.Close()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	verifier := config.Verifier{
		PublicKey: public, Clock: time.Now, MaxSensors: fixtures.Positive.ConfigMaxSensors,
		Bounds: fixtures.Positive.Bounds.configBounds(),
	}
	applier, err := sensor.NewApplier(ctx, store, verifier)
	if err != nil {
		return "", err
	}
	raw, err := fixtures.eventBytes(0, time.Now().UTC())
	if err != nil {
		return "", err
	}
	ingestor, err := collector.New(store, applier)
	if err != nil {
		return "", err
	}
	if _, err := ingestor.Ingest(ctx, fixtures.Positive.SensorID, collector.Batch{
		ID: "batch-unconfigured", FirstSequence: 1, LastSequence: 1, Events: [][]byte{raw},
	}); !errors.Is(err, sensor.ErrUnconfigured) {
		return fmt.Sprintf("%v", err), nil
	}
	return "sensor.ErrUnconfigured", nil
}

func negativeMalformedEvent(ctx context.Context, fixtures Fixtures, dir string) (string, error) {
	store, err := storage.Open(filepath.Join(dir, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return "", err
	}
	defer store.Close()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	verifier := config.Verifier{
		PublicKey: public, Clock: time.Now, MaxSensors: fixtures.Positive.ConfigMaxSensors,
		Bounds: fixtures.Positive.Bounds.configBounds(),
	}
	applier, err := sensor.NewApplier(ctx, store, verifier)
	if err != nil {
		return "", err
	}
	queue, err := spool.New(store, applier)
	if err != nil {
		return "", err
	}
	_, failure := contracts.DecodeEvent(ctx, []byte(fixtures.Negative.MalformedEvent))
	if failure == nil || failure.Code != contracts.InvalidInput {
		return fmt.Sprintf("%v", failure), nil
	}
	if _, err := queue.Enqueue(ctx, []byte(fixtures.Negative.MalformedEvent)); !errors.Is(err, sensor.ErrInvalidEvent) {
		return fmt.Sprintf("%v", err), nil
	}
	return "contracts.INVALID_INPUT", nil
}

func negativeSpoolOverflow(ctx context.Context, fixtures Fixtures, dir string, now time.Time) (string, error) {
	store, err := storage.Open(filepath.Join(dir, "state"), fixtures.Positive.StorageLimits)
	if err != nil {
		return "", err
	}
	defer store.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	verifier := config.Verifier{
		PublicKey: public, Clock: time.Now, MaxSensors: fixtures.Positive.ConfigMaxSensors,
		Bounds: fixtures.Positive.Bounds.configBounds(),
	}
	applier, err := sensor.NewApplier(ctx, store, verifier)
	if err != nil {
		return "", err
	}
	payload, signature, err := desiredState(fixtures, now, private)
	if err != nil {
		return "", err
	}
	if _, err := applier.Apply(ctx, payload, signature); err != nil {
		return "", err
	}
	queue, err := spool.New(store, applier)
	if err != nil {
		return "", err
	}
	for index := 0; index < fixtures.Positive.Settings.SpoolLimitEvents+1; index++ {
		raw, err := fixtures.eventBytes(index, now)
		if err != nil {
			return "", err
		}
		_, err = queue.Enqueue(ctx, raw)
		if index < fixtures.Positive.Settings.SpoolLimitEvents {
			if err != nil {
				return "", err
			}
			continue
		}
		if !errors.Is(err, spool.ErrDropped) {
			return fmt.Sprintf("%v", err), nil
		}
	}
	loss, err := queue.Losses(ctx, fixtures.Positive.SensorID)
	if err != nil || loss.Count != 1 {
		return fmt.Sprintf("%v", err), nil
	}
	return "spool.ErrDropped", nil
}

func newGuard(ctx context.Context, store *storage.Store, fixtures Fixtures, now time.Time) (*pki.Guard, c24fixture.Material, error) {
	material := c24fixture.Generate(now, fixtures.Positive.SensorID)
	rotator, err := pki.NewRotator(ctx, store, pki.RotationOptions{
		IssuerCertificatePEM: material.Authority, MaxSensors: fixtures.Positive.Rotation.MaxSensors,
		MaxLifetime:    time.Duration(fixtures.Positive.Rotation.MaxLifetimeSeconds) * time.Second,
		MaxOverlap:     time.Duration(fixtures.Positive.Rotation.MaxOverlapSeconds) * time.Second,
		MaxRecoveryTTL: time.Duration(fixtures.Positive.Rotation.MaxRecoveryTTLSeconds) * time.Second,
		Clock:          time.Now,
	})
	if err != nil {
		return nil, material, err
	}
	if _, err := rotator.Register(ctx, pki.RegisterCertificate{
		SensorID: fixtures.Positive.SensorID, CertificatePEM: material.Initial, IdempotencyKey: "c30-negative-register-key",
	}); err != nil {
		return nil, material, err
	}
	guard, err := pki.New(pki.Options{
		Rotation: rotator, Anchors: []string{material.Authority},
		ServerCertificatePEM: material.Server, ServerKeyPEM: material.ServerKey,
		RevocationListPEM: material.CRL, Scopes: map[string][]string{},
		MaxAnchors: 1, MaxScopes: 1, MaxScopesPerIdentity: 1, Clock: time.Now,
	})
	return guard, material, err
}

func rogueClient(material c24fixture.Material, now time.Time) (*tls.Config, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "sensor-01"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(material.Authority)) {
		return nil, errors.New("acceptance: authority is not a certificate")
	}
	return &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}
