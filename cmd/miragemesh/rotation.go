package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/enrollment"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type certificateOptions struct {
	Enabled          bool
	HTTPStatus       bool
	StateDir         string
	IssuerFile       string
	Limits           storage.Limits
	MaxSensors       int
	MaxLifetime      int64
	MaxOverlap       int64
	MaxRecoveryTTL   int64
	Action           string
	SensorID         string
	CertificateFile  string
	CSRFile          string
	KeyFile          string
	TokenFile        string
	ExpectedRevision uint64
	Lifetime         int64
	Overlap          int64
	TokenTTL         int64
	IdempotencyKey   string
}

func certificateFlags() *certificateOptions {
	o := new(certificateOptions)
	flag.BoolVar(&o.Enabled, "rotate-certificates", false, "run one local certificate operator action and exit")
	flag.BoolVar(&o.HTTPStatus, "certificate-status", false, "enable read-only local certificate rotation status")
	flag.StringVar(&o.StateDir, "rotation-state-dir", "", "C05 certificate ledger directory")
	flag.StringVar(&o.IssuerFile, "rotation-issuer-file", "", "local public CA certificate PEM file")
	flag.IntVar(&o.Limits.MaxOperations, "rotation-max-operations", 0, "explicit C05 operation limit")
	flag.Int64Var(&o.Limits.MaxBytes, "rotation-max-bytes", 0, "explicit C05 byte limit")
	flag.Int64Var(&o.Limits.MaxManifestBytes, "rotation-max-manifest-bytes", 0, "explicit C05 manifest limit")
	flag.IntVar(&o.MaxSensors, "rotation-max-sensors", 0, "explicit managed sensor limit")
	flag.Int64Var(&o.MaxLifetime, "rotation-max-lifetime-seconds", 0, "maximum issued certificate lifetime")
	flag.Int64Var(&o.MaxOverlap, "rotation-max-overlap-seconds", 0, "maximum certificate overlap window")
	flag.Int64Var(&o.MaxRecoveryTTL, "rotation-max-recovery-ttl-seconds", 0, "maximum scoped recovery token lifetime")
	flag.StringVar(&o.Action, "rotation-action", "", "status, register, rotate, issue-token or recover")
	flag.StringVar(&o.SensorID, "rotation-sensor", "", "sensor identity for the local action")
	flag.StringVar(&o.CertificateFile, "rotation-certificate-file", "", "existing client certificate PEM for registration")
	flag.StringVar(&o.CSRFile, "rotation-csr-file", "", "sensor-generated signed certificate request PEM")
	flag.StringVar(&o.KeyFile, "rotation-key-file", "", "private operator PKCS8 CA signing key file")
	flag.StringVar(&o.TokenFile, "rotation-token-file", "", "private recovery token file; created exclusively by issue-token")
	flag.Uint64Var(&o.ExpectedRevision, "rotation-expected-revision", 0, "expected current certificate revision")
	flag.Int64Var(&o.Lifetime, "rotation-lifetime-seconds", 0, "requested new certificate lifetime")
	flag.Int64Var(&o.Overlap, "rotation-overlap-seconds", 0, "requested old/new certificate overlap")
	flag.Int64Var(&o.TokenTTL, "rotation-token-ttl-seconds", 0, "requested recovery token lifetime")
	flag.StringVar(&o.IdempotencyKey, "rotation-idempotency-key", "", "stable idempotency key for register, rotate or recover")
	return o
}

func certificateConfigured() bool {
	configured := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "rotate-certificates" || f.Name == "certificate-status" || strings.HasPrefix(f.Name, "rotation-") {
			configured = true
		}
	})
	return configured
}

func rotationDuration(seconds int64) (time.Duration, error) {
	if seconds <= 0 || seconds > math.MaxInt64/int64(time.Second) {
		return 0, pki.ErrInvalidInput
	}
	return time.Duration(seconds) * time.Second, nil
}

func readCertificateFile(path string, secret bool) ([]byte, error) {
	if path == "" {
		return nil, pki.ErrInvalidInput
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, pki.ErrInvalidInput
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Dir(absolute) {
		return nil, pki.ErrInvalidInput
	}
	f, err := os.OpenFile(absolute, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, storage.ErrIO
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, storage.ErrIO
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 8192 || secret && (stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0) {
		return nil, pki.ErrInvalidInput
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return nil, storage.ErrIO
	}
	if len(data) > 8192 {
		return nil, pki.ErrInvalidInput
	}
	return data, nil
}

func openCertificateLedger(ctx context.Context, o certificateOptions, shared *storage.Store, create bool) (*pki.Rotator, *storage.Store, func(), error) {
	issuer, err := readCertificateFile(o.IssuerFile, false)
	if err != nil {
		return nil, nil, nil, err
	}
	lifetime, err := rotationDuration(o.MaxLifetime)
	if err != nil {
		return nil, nil, nil, err
	}
	overlap, err := rotationDuration(o.MaxOverlap)
	if err != nil {
		return nil, nil, nil, err
	}
	recovery, err := rotationDuration(o.MaxRecoveryTTL)
	if err != nil {
		return nil, nil, nil, err
	}
	if o.StateDir == "" || o.Limits.MaxOperations <= 0 || o.Limits.MaxBytes <= 0 || o.Limits.MaxManifestBytes <= 0 || o.MaxSensors <= 0 {
		return nil, nil, nil, pki.ErrInvalidInput
	}
	store := shared
	if store == nil {
		if !create {
			if err := requireExistingC05Store(o.StateDir); err != nil {
				return nil, nil, nil, storage.ErrRecovery
			}
		}
		store, err = storage.Open(o.StateDir, o.Limits)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	closeStore := func() {
		if shared == nil {
			store.Close()
		}
	}
	r, err := pki.NewRotator(ctx, store, pki.RotationOptions{IssuerCertificatePEM: string(issuer), MaxSensors: o.MaxSensors, MaxLifetime: lifetime, MaxOverlap: overlap, MaxRecoveryTTL: recovery, Clock: time.Now})
	if err != nil {
		closeStore()
		return nil, nil, nil, err
	}
	return r, store, closeStore, nil
}

func certificateErrorKind(err error) string {
	switch {
	case errors.Is(err, pki.ErrInvalidInput), errors.Is(err, enrollment.ErrInvalidInput), errors.Is(err, enrollment.ErrInvalidTTL):
		return "invalid_input"
	case errors.Is(err, pki.ErrSigner):
		return "signer_unavailable"
	case errors.Is(err, pki.ErrRotationConflict), errors.Is(err, pki.ErrRecoveryTokenUsed):
		return "conflict"
	case errors.Is(err, pki.ErrRotationBusy):
		return "overlap_active"
	case errors.Is(err, pki.ErrRecoveryToken):
		return "invalid_recovery_token"
	default:
		return segmentProjectionErrorKind(err)
	}
}

func issueCertificateRecoveryToken(ctx context.Context, o certificateOptions, r *pki.Rotator, store *storage.Store) (string, error) {
	ttl, err := rotationDuration(o.TokenTTL)
	if err != nil || o.TokenTTL > o.MaxRecoveryTTL || o.TokenFile == "" {
		return "", pki.ErrInvalidInput
	}
	snapshot, err := r.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	found := false
	for _, s := range snapshot.Sensors {
		if s.SensorID == o.SensorID {
			found = true
		}
	}
	if !found {
		return "", pki.ErrRotationConflict
	}
	absolute, err := filepath.Abs(o.TokenFile)
	if err != nil {
		return "", pki.ErrInvalidInput
	}
	parent := filepath.Dir(absolute)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return "", pki.ErrInvalidInput
	}
	info, err := os.Stat(parent)
	if err != nil {
		return "", storage.ErrIO
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return "", pki.ErrInvalidInput
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return "", storage.ErrIO
	}
	defer root.Close()
	name := filepath.Base(absolute)
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return "", pki.ErrInvalidInput
	}
	service, err := enrollment.New(store, time.Duration(o.MaxRecoveryTTL)*time.Second, time.Now)
	if err != nil {
		return "", err
	}
	token, err := service.Issue(ctx, o.SensorID, ttl)
	if err != nil {
		return "", err
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", storage.ErrIO
	}
	raw := []byte(token.Token + "\n")
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		f.Close()
		return "", storage.ErrIO
	}
	if f.Sync() != nil {
		f.Close()
		return "", storage.ErrIO
	}
	if f.Close() != nil {
		return "", storage.ErrIO
	}
	dir, err := root.Open(".")
	if err != nil {
		return "", storage.ErrIO
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return "", storage.ErrIO
	}
	return token.ExpiresAt.UTC().Format(time.RFC3339Nano), nil
}

func runCertificateAction(o certificateOptions) int {
	type outcome struct {
		Scope          string                 `json:"scope"`
		Status         string                 `json:"status"`
		Result         *pki.CertificateResult `json:"result,omitempty"`
		Snapshot       *pki.RotationSnapshot  `json:"snapshot,omitempty"`
		TokenExpiresAt string                 `json:"token_expires_at,omitempty"`
		ErrorKind      string                 `json:"error_kind,omitempty"`
	}
	value := outcome{Scope: "certificate-rotation", Status: "failed"}
	finish := func(err error) int {
		if err != nil {
			value.Status = "failed"
			value.ErrorKind = certificateErrorKind(err)
		}
		if json.NewEncoder(os.Stdout).Encode(value) != nil {
			return 1
		}
		if err == nil {
			return 0
		}
		if errors.Is(err, pki.ErrInvalidInput) || errors.Is(err, enrollment.ErrInvalidInput) || errors.Is(err, enrollment.ErrInvalidTTL) {
			return 2
		}
		return 1
	}
	mixed := flag.NArg() != 0 || !o.Enabled || o.HTTPStatus
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "rotate-certificates" && !strings.HasPrefix(f.Name, "rotation-") {
			mixed = true
		}
	})
	if mixed || !validCertificateActionFlags(o.Action) || o.Action != "status" && o.Action != "register" && o.Action != "rotate" && o.Action != "recover" && o.Action != "issue-token" {
		return finish(pki.ErrInvalidInput)
	}
	if o.Action == "status" && (o.SensorID != "" || o.CSRFile != "" || o.KeyFile != "" || o.TokenFile != "" || o.CertificateFile != "" || o.IdempotencyKey != "" || o.ExpectedRevision != 0 || o.Lifetime != 0 || o.Overlap != 0 || o.TokenTTL != 0) {
		return finish(pki.ErrInvalidInput)
	}
	ctx := context.Background()
	r, store, closeStore, err := openCertificateLedger(ctx, o, nil, o.Action == "register")
	if err != nil {
		return finish(err)
	}
	defer closeStore()
	if o.Action == "status" {
		snapshot, err := r.Snapshot(ctx)
		if err == nil {
			value.Snapshot = &snapshot
			value.Status = "snapshot"
		}
		return finish(err)
	}
	if o.Action == "issue-token" {
		expires, err := issueCertificateRecoveryToken(ctx, o, r, store)
		if err == nil {
			value.TokenExpiresAt = expires
			value.Status = "token_issued"
		}
		return finish(err)
	}
	var result pki.CertificateResult
	if o.Action == "register" {
		cert, readErr := readCertificateFile(o.CertificateFile, false)
		if readErr != nil {
			return finish(readErr)
		}
		result, err = r.Register(ctx, pki.RegisterCertificate{SensorID: o.SensorID, CertificatePEM: string(cert), IdempotencyKey: o.IdempotencyKey})
		value.Status = "registered"
	} else {
		csr, readErr := readCertificateFile(o.CSRFile, false)
		if readErr != nil {
			return finish(readErr)
		}
		lifetime, readErr := rotationDuration(o.Lifetime)
		if readErr != nil {
			return finish(readErr)
		}
		var signer crypto.Signer
		if o.KeyFile != "" {
			raw, readErr := readCertificateFile(o.KeyFile, true)
			if readErr != nil {
				return finish(readErr)
			}
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 || !strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN PRIVATE KEY-----") {
				return finish(pki.ErrInvalidInput)
			}
			parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return finish(pki.ErrInvalidInput)
			}
			var ok bool
			signer, ok = parsed.(crypto.Signer)
			if !ok {
				return finish(pki.ErrInvalidInput)
			}
		}
		request := pki.RotateCertificate{SensorID: o.SensorID, ExpectedRevision: o.ExpectedRevision, CSRPEM: string(csr), Lifetime: lifetime, IdempotencyKey: o.IdempotencyKey}
		if o.Action == "rotate" {
			overlap, readErr := rotationDuration(o.Overlap)
			if readErr != nil {
				return finish(readErr)
			}
			request.Overlap = overlap
			result, err = r.Rotate(ctx, request, signer)
			value.Status = "rotated"
		} else {
			if o.Overlap != 0 {
				return finish(pki.ErrInvalidInput)
			}
			token, readErr := readCertificateFile(o.TokenFile, true)
			if readErr != nil {
				return finish(readErr)
			}
			result, err = r.Recover(ctx, pki.RecoverCertificate{RotateCertificate: request, Token: strings.TrimSpace(string(token))}, signer)
			value.Status = "recovered"
		}
	}
	if err == nil {
		value.Result = &result
	}
	return finish(err)
}

type certificateStatusReader interface {
	Snapshot(context.Context) (pki.RotationSnapshot, error)
}

func validCertificateStatusOptions(o certificateOptions) bool {
	return o.HTTPStatus && !o.Enabled && o.Action == "" && o.SensorID == "" && o.CertificateFile == "" && o.CSRFile == "" && o.KeyFile == "" && o.TokenFile == "" && o.ExpectedRevision == 0 && o.Lifetime == 0 && o.Overlap == 0 && o.TokenTTL == 0 && o.IdempotencyKey == "" && flag.NArg() == 0
}

func sameCertificateStore(o certificateOptions, directory string, limits storage.Limits) bool {
	first, err := filepath.Abs(o.StateDir)
	if err != nil {
		return false
	}
	second, err := filepath.Abs(directory)
	return err == nil && first == second && o.Limits == limits
}

func validCertificateActionFlags(action string) bool {
	common := map[string]bool{"rotate-certificates": true, "rotation-state-dir": true, "rotation-issuer-file": true, "rotation-max-operations": true, "rotation-max-bytes": true, "rotation-max-manifest-bytes": true, "rotation-max-sensors": true, "rotation-max-lifetime-seconds": true, "rotation-max-overlap-seconds": true, "rotation-max-recovery-ttl-seconds": true, "rotation-action": true}
	actions := map[string][]string{
		"status":      {},
		"register":    {"rotation-sensor", "rotation-certificate-file", "rotation-idempotency-key"},
		"rotate":      {"rotation-sensor", "rotation-csr-file", "rotation-key-file", "rotation-expected-revision", "rotation-lifetime-seconds", "rotation-overlap-seconds", "rotation-idempotency-key"},
		"recover":     {"rotation-sensor", "rotation-csr-file", "rotation-key-file", "rotation-expected-revision", "rotation-lifetime-seconds", "rotation-token-file", "rotation-idempotency-key"},
		"issue-token": {"rotation-sensor", "rotation-token-file", "rotation-token-ttl-seconds"},
	}
	for _, name := range actions[action] {
		common[name] = true
	}
	valid := true
	flag.Visit(func(f *flag.Flag) {
		if !common[f.Name] {
			valid = false
		}
	})
	return valid
}
