package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var ErrRetired = errors.New("pki: certificate retired by rotation")
var ErrRotationConflict = errors.New("pki: certificate rotation conflicts with durable state")
var ErrRotationBusy = errors.New("pki: certificate overlap is still active")
var ErrRecoveryToken = errors.New("pki: recovery token is missing, expired or outside sensor scope")
var ErrRecoveryTokenUsed = errors.New("pki: recovery token already consumed")
var ErrSigner = errors.New("pki: certificate signer unavailable or mismatched")

type RotationOptions struct {
	IssuerCertificatePEM string
	MaxSensors           int
	MaxLifetime          time.Duration
	MaxOverlap           time.Duration
	MaxRecoveryTTL       time.Duration
	Clock                func() time.Time
}

type Rotator struct {
	store             *storage.Store
	issuer            *x509.Certificate
	issuerFingerprint string
	options           RotationOptions
}

type RegisterCertificate struct {
	SensorID       string
	CertificatePEM string
	IdempotencyKey string
}

type RotateCertificate struct {
	SensorID         string
	ExpectedRevision uint64
	CSRPEM           string
	Lifetime         time.Duration
	Overlap          time.Duration
	IdempotencyKey   string
}

type RecoverCertificate struct {
	RotateCertificate
	Token string
}

type CertificateResult struct {
	SensorID       string          `json:"sensor_id"`
	Revision       uint64          `json:"revision"`
	Fingerprint    string          `json:"fingerprint"`
	CertificatePEM string          `json:"certificate_pem"`
	AcceptedAt     string          `json:"accepted_at"`
	OverlapUntil   string          `json:"overlap_until,omitempty"`
	NotAfter       string          `json:"not_after"`
	Replayed       bool            `json:"replayed"`
	Receipt        storage.Receipt `json:"receipt"`
}

type CertificateStatus struct {
	SensorID            string `json:"sensor_id"`
	Revision            uint64 `json:"revision"`
	Fingerprint         string `json:"fingerprint"`
	PreviousFingerprint string `json:"previous_fingerprint,omitempty"`
	OverlapUntil        string `json:"overlap_until,omitempty"`
	NotAfter            string `json:"not_after"`
	Status              string `json:"status"`
	RecoveryAvailable   bool   `json:"recovery_available"`
}

type RotationSnapshot struct {
	SchemaVersion     string              `json:"schema_version"`
	IssuerFingerprint string              `json:"issuer_fingerprint"`
	ObservedAt        string              `json:"observed_at"`
	Sensors           []CertificateStatus `json:"sensors"`
}

type rotationVersion struct {
	record      contracts.CertificateRotationRecord
	certificate *x509.Certificate
}

type rotationToken struct {
	issue contracts.EnrollmentRecord
	used  bool
}

type rotationState struct {
	sensors    map[string]rotationVersion
	identities map[string]string
	keys       map[string]bool
	serials    map[string]bool
	operations map[string]storage.Record
	tokens     map[string]rotationToken
	last       time.Time
}

func validRotationTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1000 && at.Year() <= 9999
}
func wholeSeconds(d time.Duration) bool { return d > 0 && d%time.Second == 0 }
func rotationKey(key string) bool {
	return utf8.ValidString(key) && utf8.RuneCountInString(key) >= 16 && utf8.RuneCountInString(key) <= 128 && strings.TrimSpace(key) != ""
}
func rotationOperationID(key string) string { return "certificate/" + key }
func rotationPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func NewRotator(ctx context.Context, store *storage.Store, options RotationOptions) (*Rotator, error) {
	if ctx == nil || store == nil || options.Clock == nil || options.MaxSensors <= 0 || !wholeSeconds(options.MaxLifetime) || !wholeSeconds(options.MaxOverlap) || options.MaxOverlap >= options.MaxLifetime || !wholeSeconds(options.MaxRecoveryTTL) {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options.IssuerCertificatePEM) > 8192 || !strings.HasPrefix(strings.TrimSpace(options.IssuerCertificatePEM), "-----BEGIN CERTIFICATE-----") {
		return nil, ErrInvalidInput
	}
	issuer, err := parseCertificatePEM(options.IssuerCertificatePEM)
	if err != nil || !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 || issuer.CheckSignatureFrom(issuer) != nil {
		return nil, ErrInvalidInput
	}
	r := &Rotator{store: store, issuer: issuer, issuerFingerprint: fingerprintOf(issuer.Raw), options: options}
	if _, err := r.Snapshot(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) certificate(der []byte, at time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 159 || !bytes.Equal(cert.RawIssuer, r.issuer.RawSubject) || cert.CheckSignatureFrom(r.issuer) != nil || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || cert.NotAfter.After(r.issuer.NotAfter) || !validRotationPublicKey(cert.PublicKey) {
		return nil, ErrInvalidInput
	}
	pool := x509.NewCertPool()
	pool.AddCert(r.issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || !at.Before(cert.NotAfter) {
		return nil, ErrInvalidInput
	}
	return cert, nil
}

func validRotationPublicKey(key any) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case *rsa.PublicKey:
		return k.N != nil && k.N.BitLen() >= 2048 && k.N.BitLen() <= 4096 && k.E >= 3 && k.E%2 == 1
	default:
		return false
	}
}

func rotationCSR(der []byte, sensorID string) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || len(der) > 4096 || csr.CheckSignature() != nil || !validRotationPublicKey(csr.PublicKey) || len(csr.Extensions) != 0 || len(csr.Subject.Names) != 1 || !csr.Subject.Names[0].Type.Equal([]int{2, 5, 4, 3}) || csr.Subject.CommonName != sensorID {
		return nil, ErrInvalidInput
	}
	return csr, nil
}

func (r *Rotator) state(ctx context.Context, records []storage.Record) (rotationState, error) {
	s := rotationState{sensors: map[string]rotationVersion{}, identities: map[string]string{}, keys: map[string]bool{}, serials: map[string]bool{}, operations: map[string]storage.Record{}, tokens: map[string]rotationToken{}}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return s, err
		}
		if record.Enrollment != nil {
			e := *record.Enrollment
			token, exists := s.tokens[e.TokenHash]
			switch e.Kind {
			case contracts.EnrollmentIssue:
				if exists || record.Receipt.OperationID != "enrollment/issue/"+e.TokenHash {
					return s, storage.ErrRecovery
				}
				s.tokens[e.TokenHash] = rotationToken{issue: e}
			case contracts.EnrollmentConsume:
				if !exists || token.used || record.Receipt.OperationID != "enrollment/consume/"+e.TokenHash || e.SensorID != token.issue.SensorID || e.IssuedAt != token.issue.IssuedAt || e.ExpiresAt != token.issue.ExpiresAt {
					return s, storage.ErrRecovery
				}
				token.used = true
				s.tokens[e.TokenHash] = token
			default:
				return s, storage.ErrRecovery
			}
		}
		if record.Rotation == nil {
			if strings.HasPrefix(record.Receipt.OperationID, "certificate/") {
				return s, storage.ErrRecovery
			}
			continue
		}
		op, err := contracts.DecodeCertificateRotation(ctx, record.Input)
		if err != nil || record.Receipt.OperationID != rotationOperationID(op.KeyDigest) || op.IssuerFingerprint != r.issuerFingerprint {
			return s, storage.ErrRecovery
		}
		if _, duplicate := s.operations[op.KeyDigest]; duplicate {
			return s, storage.ErrRecovery
		}
		at, _ := time.Parse(time.RFC3339Nano, op.AcceptedAt)
		if at.Before(s.last) {
			return s, storage.ErrRecovery
		}
		cert, err := r.certificate(op.CertificateDER, at)
		if err != nil {
			return s, storage.ErrRecovery
		}
		fp := fingerprintOf(cert.Raw)
		key := fingerprintOf(cert.RawSubjectPublicKeyInfo)
		if _, exists := s.identities[fp]; exists || s.keys[key] || s.serials[serialText(cert.SerialNumber)] {
			return s, storage.ErrRecovery
		}
		previous, exists := s.sensors[op.SensorID]
		if op.Kind == contracts.CertificateRegister {
			if exists {
				return s, storage.ErrRecovery
			}
		} else {
			if !exists || op.Revision != previous.record.Revision+1 || op.PreviousFingerprint != fingerprintOf(previous.certificate.Raw) {
				return s, storage.ErrRecovery
			}
			csr, err := rotationCSR(op.CSRDER, op.SensorID)
			if err != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) || cert.Subject.CommonName != op.SensorID || cert.NotAfter.Sub(cert.NotBefore) > time.Duration(op.LifetimeSeconds)*time.Second {
				return s, storage.ErrRecovery
			}
			deadline, _ := time.Parse(time.RFC3339Nano, op.OverlapUntil)
			if !deadline.Before(cert.NotAfter) {
				return s, storage.ErrRecovery
			}
			if op.Kind == contracts.CertificateRotate {
				if previous.record.OverlapUntil != "" {
					oldDeadline, _ := time.Parse(time.RFC3339Nano, previous.record.OverlapUntil)
					if at.Before(oldDeadline) {
						return s, storage.ErrRecovery
					}
				}
				if deadline.After(previous.certificate.NotAfter) {
					return s, storage.ErrRecovery
				}
			} else {
				if !recoveryAvailable(previous, at) {
					return s, storage.ErrRecovery
				}
				token, ok := s.tokens[op.TokenHash]
				if !ok || token.used || token.issue.SensorID != op.SensorID || !validRecoveryAt(token.issue, at) {
					return s, storage.ErrRecovery
				}
				token.used = true
				s.tokens[op.TokenHash] = token
			}
		}
		s.sensors[op.SensorID] = rotationVersion{op, cert}
		s.identities[fp] = op.SensorID
		s.keys[key] = true
		s.serials[serialText(cert.SerialNumber)] = true
		s.operations[op.KeyDigest] = record
		s.last = at
		if len(s.sensors) > r.options.MaxSensors {
			return s, storage.ErrQuota
		}
	}
	return s, nil
}

func recoveryAvailable(v rotationVersion, now time.Time) bool {
	if !now.Before(v.certificate.NotAfter) {
		return true
	}
	if v.record.OverlapUntil == "" {
		return false
	}
	end, _ := time.Parse(time.RFC3339Nano, v.record.OverlapUntil)
	return !now.Before(end)
}

func validRecoveryAt(issue contracts.EnrollmentRecord, now time.Time) bool {
	start, _ := time.Parse(time.RFC3339Nano, issue.IssuedAt)
	end, _ := time.Parse(time.RFC3339Nano, issue.ExpiresAt)
	return !now.Before(start) && now.Before(end)
}

func (r *Rotator) Snapshot(ctx context.Context) (RotationSnapshot, error) {
	if r == nil || ctx == nil {
		return RotationSnapshot{}, ErrInvalidInput
	}
	records, err := r.store.Records(ctx)
	if err != nil {
		return RotationSnapshot{}, err
	}
	s, err := r.state(ctx, records)
	if err != nil {
		return RotationSnapshot{}, err
	}
	now := r.options.Clock().UTC()
	if !validRotationTime(now) || now.Before(s.last) {
		return RotationSnapshot{}, ErrInvalidInput
	}
	result := RotationSnapshot{SchemaVersion: contracts.SchemaVersion, IssuerFingerprint: r.issuerFingerprint, ObservedAt: now.Format(time.RFC3339Nano), Sensors: []CertificateStatus{}}
	for sensor, v := range s.sensors {
		status := "current"
		if !now.Before(v.certificate.NotAfter) {
			status = "expired"
		} else if v.record.OverlapUntil != "" {
			end, _ := time.Parse(time.RFC3339Nano, v.record.OverlapUntil)
			if now.Before(end) {
				status = "overlap"
			}
		}
		result.Sensors = append(result.Sensors, CertificateStatus{SensorID: sensor, Revision: v.record.Revision, Fingerprint: fingerprintOf(v.certificate.Raw), PreviousFingerprint: v.record.PreviousFingerprint, OverlapUntil: v.record.OverlapUntil, NotAfter: v.certificate.NotAfter.UTC().Format(time.RFC3339Nano), Status: status, RecoveryAvailable: recoveryAvailable(v, now)})
	}
	sort.Slice(result.Sensors, func(i, j int) bool { return result.Sensors[i].SensorID < result.Sensors[j].SensorID })
	raw, _ := json.Marshal(result)
	if len(raw) > 1048576 {
		return RotationSnapshot{}, storage.ErrQuota
	}
	return result, nil
}

func (r *Rotator) authorize(fp string, now time.Time) ([]string, bool, error) {
	ctx := context.Background()
	records, err := r.store.Records(ctx)
	if err != nil {
		return nil, false, err
	}
	s, err := r.state(ctx, records)
	if err != nil {
		return nil, false, err
	}
	if !validRotationTime(now) || now.Before(s.last) {
		return nil, false, ErrInvalidInput
	}
	sensor, managed := s.identities[fp]
	if !managed {
		return nil, false, nil
	}
	v := s.sensors[sensor]
	if fp == fingerprintOf(v.certificate.Raw) {
		if !now.Before(v.certificate.NotAfter) {
			return nil, true, ErrExpired
		}
		return []string{sensor}, true, nil
	}
	if fp == v.record.PreviousFingerprint && v.record.Kind == contracts.CertificateRotate {
		end, _ := time.Parse(time.RFC3339Nano, v.record.OverlapUntil)
		if now.Before(end) {
			return []string{sensor}, true, nil
		}
	}
	return nil, true, ErrRetired
}

func (r *Rotator) Register(ctx context.Context, request RegisterCertificate) (CertificateResult, error) {
	if r == nil || ctx == nil || !contracts.ValidSensorID(request.SensorID) || !rotationKey(request.IdempotencyKey) || len(request.CertificatePEM) > 8192 || !strings.HasPrefix(strings.TrimSpace(request.CertificatePEM), "-----BEGIN CERTIFICATE-----") {
		return CertificateResult{}, ErrInvalidInput
	}
	cert, err := parseCertificatePEM(request.CertificatePEM)
	if err != nil {
		return CertificateResult{}, ErrInvalidInput
	}
	op := contracts.CertificateRotationRecord{SchemaVersion: contracts.SchemaVersion, Kind: contracts.CertificateRegister, SensorID: request.SensorID, Revision: 1, IssuerFingerprint: r.issuerFingerprint, CertificateDER: cert.Raw, KeyDigest: fingerprintOf([]byte(request.IdempotencyKey))}
	op.RequestDigest = contracts.CertificateIntentDigest(op)
	return r.commit(ctx, op, nil, nil)
}

func (r *Rotator) Rotate(ctx context.Context, request RotateCertificate, signer crypto.Signer) (CertificateResult, error) {
	return r.renew(ctx, request, "", contracts.CertificateRotate, signer)
}

func (r *Rotator) Recover(ctx context.Context, request RecoverCertificate, signer crypto.Signer) (CertificateResult, error) {
	return r.renew(ctx, request.RotateCertificate, request.Token, contracts.CertificateRecover, signer)
}

func (r *Rotator) renew(ctx context.Context, request RotateCertificate, token, kind string, signer crypto.Signer) (CertificateResult, error) {
	if r == nil || ctx == nil || !contracts.ValidSensorID(request.SensorID) || !rotationKey(request.IdempotencyKey) || request.ExpectedRevision < 1 || request.ExpectedRevision >= contracts.MaxCertificateRevision || !wholeSeconds(request.Lifetime) || request.Lifetime > r.options.MaxLifetime || len(request.CSRPEM) > 8192 || !strings.HasPrefix(strings.TrimSpace(request.CSRPEM), "-----BEGIN CERTIFICATE REQUEST-----") {
		return CertificateResult{}, ErrInvalidInput
	}
	if kind == contracts.CertificateRotate && (!wholeSeconds(request.Overlap) || request.Overlap > r.options.MaxOverlap || request.Overlap >= request.Lifetime) || kind == contracts.CertificateRecover && request.Overlap != 0 {
		return CertificateResult{}, ErrInvalidInput
	}
	block, rest := pem.Decode([]byte(request.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return CertificateResult{}, ErrInvalidInput
	}
	csr, err := rotationCSR(block.Bytes, request.SensorID)
	if err != nil {
		return CertificateResult{}, err
	}
	op := contracts.CertificateRotationRecord{SchemaVersion: contracts.SchemaVersion, Kind: kind, SensorID: request.SensorID, Revision: request.ExpectedRevision + 1, IssuerFingerprint: r.issuerFingerprint, CSRDER: csr.Raw, LifetimeSeconds: int64(request.Lifetime / time.Second), OverlapSeconds: int64(request.Overlap / time.Second), KeyDigest: fingerprintOf([]byte(request.IdempotencyKey))}
	if kind == contracts.CertificateRecover {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
		if err != nil || len(raw) != 32 || len(token) != 43 {
			return CertificateResult{}, ErrRecoveryToken
		}
		op.TokenHash = fingerprintOf([]byte(token))
	}
	op.RequestDigest = contracts.CertificateIntentDigest(op)
	return r.commit(ctx, op, csr, signer)
}

func (r *Rotator) commit(ctx context.Context, op contracts.CertificateRotationRecord, csr *x509.CertificateRequest, signer crypto.Signer) (CertificateResult, error) {
	var committed contracts.CertificateRotationRecord
	replayed := false
	receipt, err := r.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		s, err := r.state(ctx, records)
		if err != nil {
			return "", nil, err
		}
		now := r.options.Clock().UTC()
		if !validRotationTime(now) || now.Before(s.last) {
			return "", nil, ErrInvalidInput
		}
		if existing, ok := s.operations[op.KeyDigest]; ok {
			if existing.Rotation.RequestDigest != op.RequestDigest {
				return "", nil, ErrRotationConflict
			}
			committed = *existing.Rotation
			replayed = true
			return existing.Receipt.OperationID, existing.Input, nil
		}
		previous, exists := s.sensors[op.SensorID]
		if op.Kind == contracts.CertificateRegister {
			if exists {
				return "", nil, ErrRotationConflict
			}
			if len(s.sensors) >= r.options.MaxSensors {
				return "", nil, storage.ErrQuota
			}
		} else {
			if !exists || op.Revision != previous.record.Revision+1 {
				return "", nil, ErrRotationConflict
			}
			if op.Kind == contracts.CertificateRecover {
				token, ok := s.tokens[op.TokenHash]
				if ok && token.used {
					return "", nil, ErrRecoveryTokenUsed
				}
				issued, _ := time.Parse(time.RFC3339Nano, token.issue.IssuedAt)
				expires, _ := time.Parse(time.RFC3339Nano, token.issue.ExpiresAt)
				if !ok || token.issue.SensorID != op.SensorID || !validRecoveryAt(token.issue, now) || expires.Sub(issued) > r.options.MaxRecoveryTTL {
					return "", nil, ErrRecoveryToken
				}
				if !recoveryAvailable(previous, now) {
					return "", nil, ErrRotationBusy
				}
			} else if previous.record.OverlapUntil != "" {
				end, _ := time.Parse(time.RFC3339Nano, previous.record.OverlapUntil)
				if now.Before(end) {
					return "", nil, ErrRotationBusy
				}
			}
			if signer == nil {
				return "", nil, ErrSigner
			}
			public, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil || !bytes.Equal(public, r.issuer.RawSubjectPublicKeyInfo) {
				return "", nil, ErrSigner
			}
			if s.keys[fingerprintOf(csr.RawSubjectPublicKeyInfo)] {
				return "", nil, ErrRotationConflict
			}
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil || serial.Sign() == 0 {
				return "", nil, ErrSigner
			}
			template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: op.SensorID}, NotBefore: now.Truncate(time.Second), NotAfter: now.Add(time.Duration(op.LifetimeSeconds) * time.Second).Truncate(time.Second), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, r.issuer, csr.PublicKey, signer)
			if err != nil {
				return "", nil, ErrSigner
			}
			op.CertificateDER = der
			op.PreviousFingerprint = fingerprintOf(previous.certificate.Raw)
		}
		checked := r.options.Clock().UTC()
		if !validRotationTime(checked) || checked.Before(now) {
			return "", nil, ErrInvalidInput
		}
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		op.AcceptedAt = checked.Format(time.RFC3339Nano)
		cert, err := r.certificate(op.CertificateDER, checked)
		if err != nil {
			return "", nil, ErrInvalidInput
		}
		if _, exists := s.identities[fingerprintOf(cert.Raw)]; exists || s.keys[fingerprintOf(cert.RawSubjectPublicKeyInfo)] || s.serials[serialText(cert.SerialNumber)] {
			return "", nil, ErrRotationConflict
		}
		if op.Kind != contracts.CertificateRegister {
			deadline := checked.Add(time.Duration(op.OverlapSeconds) * time.Second)
			if !validRotationTime(deadline) || !deadline.Before(cert.NotAfter) || op.Kind == contracts.CertificateRotate && deadline.After(previous.certificate.NotAfter) {
				return "", nil, ErrInvalidInput
			}
			if op.Kind == contracts.CertificateRecover && !validRecoveryAt(s.tokens[op.TokenHash].issue, checked) {
				return "", nil, ErrRecoveryToken
			}
			op.OverlapUntil = deadline.Format(time.RFC3339Nano)
		}
		raw, _ := json.Marshal(op)
		if len(raw) > contracts.MaxInputBytes {
			return "", nil, storage.ErrQuota
		}
		if _, err := contracts.DecodeCertificateRotation(ctx, raw); err != nil {
			return "", nil, ErrInvalidInput
		}
		committed = op
		return rotationOperationID(op.KeyDigest), raw, nil
	})
	if err != nil {
		return CertificateResult{}, err
	}
	cert, err := x509.ParseCertificate(committed.CertificateDER)
	if err != nil {
		return CertificateResult{}, storage.ErrRecovery
	}
	return CertificateResult{SensorID: committed.SensorID, Revision: committed.Revision, Fingerprint: fingerprintOf(cert.Raw), CertificatePEM: rotationPEM(cert.Raw), AcceptedAt: committed.AcceptedAt, OverlapUntil: committed.OverlapUntil, NotAfter: cert.NotAfter.UTC().Format(time.RFC3339Nano), Replayed: replayed, Receipt: receipt}, nil
}
