package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidInput = errors.New("invalid update input")
	ErrSignature    = errors.New("untrusted update signature")
	ErrExpired      = errors.New("update metadata expired or not yet valid")
	ErrStale        = errors.New("stale update authority")
	ErrConflict     = errors.New("update authority conflict")
	ErrRevoked      = errors.New("update version revoked")
	ErrRollback     = errors.New("update rollback requires recovery authority")
	ErrRecovery     = errors.New("invalid or consumed update recovery authority")
	ErrArtifact     = errors.New("update artifact does not match signed evidence")
	ErrEvidence     = errors.New("update release evidence unavailable")
)

type Release struct {
	Version uint64 `json:"version"`
	SHA256  string `json:"sha256"`
	Length  int64  `json:"length"`
}

type Metadata struct {
	SchemaVersion   string    `json:"schema_version"`
	Kind            string    `json:"kind"`
	SensorID        string    `json:"sensor_id"`
	Revision        uint64    `json:"revision"`
	Platform        string    `json:"platform"`
	IssuedAt        string    `json:"issued_at"`
	ExpiresAt       string    `json:"expires_at"`
	Releases        []Release `json:"releases"`
	RevokedVersions []uint64  `json:"revoked_versions"`
}

type RecoveryGrant struct {
	SchemaVersion    string `json:"schema_version"`
	Kind             string `json:"kind"`
	ID               string `json:"id"`
	SensorID         string `json:"sensor_id"`
	MetadataRevision uint64 `json:"metadata_revision"`
	Platform         string `json:"platform"`
	FromVersion      uint64 `json:"from_version"`
	ToVersion        uint64 `json:"to_version"`
	SHA256           string `json:"sha256"`
	Length           int64  `json:"length"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	Reason           string `json:"reason"`
}

type Options struct {
	PublisherKey     ed25519.PublicKey
	RecoveryKey      ed25519.PublicKey
	Platform         string
	MaxSensors       int
	MaxArtifactBytes int64
	MaxMetadataTTL   time.Duration
	MaxRecoveryTTL   time.Duration
	Clock            func() time.Time
}

type Verifier struct {
	store   *storage.Store
	options Options
}

type MetadataResult struct {
	SensorID  string          `json:"sensor_id"`
	Revision  uint64          `json:"revision"`
	ExpiresAt string          `json:"expires_at"`
	Replayed  bool            `json:"replayed"`
	Receipt   storage.Receipt `json:"receipt"`
}

type Request struct {
	SensorID          string
	Version           uint64
	Artifact          io.Reader
	RecoveryPayload   []byte
	RecoverySignature []byte
}

type Result struct {
	SensorID         string          `json:"sensor_id"`
	MetadataRevision uint64          `json:"metadata_revision"`
	Version          uint64          `json:"version"`
	HighWaterVersion uint64          `json:"high_water_version"`
	SHA256           string          `json:"sha256"`
	Length           int64           `json:"length"`
	VerifiedAt       string          `json:"verified_at"`
	Recovery         bool            `json:"recovery"`
	Replayed         bool            `json:"replayed"`
	Receipt          storage.Receipt `json:"receipt"`
}

type SensorStatus struct {
	IssuedAt         string    `json:"issued_at"`
	SensorID         string    `json:"sensor_id"`
	Revision         uint64    `json:"revision"`
	ExpiresAt        string    `json:"expires_at"`
	MetadataDigest   string    `json:"metadata_digest"`
	RevokedVersions  []uint64  `json:"revoked_versions"`
	Releases         []Release `json:"releases"`
	Version          uint64    `json:"version"`
	HighWaterVersion uint64    `json:"high_water_version"`
	VerifiedRevision uint64    `json:"verified_revision"`
	VerifiedAt       string    `json:"verified_at,omitempty"`
	Recovery         bool      `json:"recovery"`
	Status           string    `json:"status"`
}

type Snapshot struct {
	SchemaVersion        string         `json:"schema_version"`
	Platform             string         `json:"platform"`
	PublisherFingerprint string         `json:"publisher_fingerprint"`
	RecoveryFingerprint  string         `json:"recovery_fingerprint"`
	ObservedAt           string         `json:"observed_at"`
	Sensors              []SensorStatus `json:"sensors"`
}

type state struct {
	document  Metadata
	authority storage.Record
	last      storage.Record
	high      uint64
	releases  map[uint64]Release
	grants    map[string]bool
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var platformPattern = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9]{1,16}$`)
var grantPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func hash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func version(n uint64) bool  { return n > 0 && n <= uint64(contracts.MaxSequence) }
func instant(raw string) (time.Time, bool) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	return at, err == nil && at.Year() >= 1000 && at.UTC().Format(time.RFC3339Nano) == raw
}
func validNow(at time.Time) bool { return at.Year() >= 1000 && at.Year() <= 9999 }
func canonical(raw []byte, out any, limit int) bool {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || json.Unmarshal(raw, out) != nil {
		return false
	}
	expected, _ := json.Marshal(out)
	return bytes.Equal(raw, expected)
}
func window(issued, expires string, at time.Time, maxTTL time.Duration) bool {
	start, ok := instant(issued)
	end, valid := instant(expires)
	return ok && valid && validNow(at) && end.After(start) && end.Sub(start) <= maxTTL && !at.Before(start) && at.Before(end)
}
func operation(sensor, kind string, revision uint64) string {
	return "update/" + hash([]byte(sensor)) + "/" + kind + "/" + strconv.FormatUint(revision, 10)
}

func New(ctx context.Context, store *storage.Store, options Options) (*Verifier, error) {
	if ctx == nil || store == nil || len(options.PublisherKey) != ed25519.PublicKeySize || len(options.RecoveryKey) != ed25519.PublicKeySize || bytes.Equal(options.PublisherKey, options.RecoveryKey) || !platformPattern.MatchString(options.Platform) || options.MaxSensors < 1 || options.MaxSensors > 8192 || options.MaxArtifactBytes < 1 || options.MaxArtifactBytes > 67108864 || options.MaxMetadataTTL <= 0 || options.MaxRecoveryTTL <= 0 || options.MaxRecoveryTTL > options.MaxMetadataTTL || options.Clock == nil {
		return nil, ErrInvalidInput
	}
	options.PublisherKey = append(ed25519.PublicKey(nil), options.PublisherKey...)
	options.RecoveryKey = append(ed25519.PublicKey(nil), options.RecoveryKey...)
	v := &Verifier{store, options}
	records, err := store.Records(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = v.project(ctx, records); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) metadata(raw, sig []byte, at time.Time) (Metadata, error) {
	if len(sig) != ed25519.SignatureSize || len(raw) > contracts.MaxInputBytes || !ed25519.Verify(v.options.PublisherKey, raw, sig) {
		return Metadata{}, ErrSignature
	}
	var doc Metadata
	if !canonical(raw, &doc, contracts.MaxInputBytes) || doc.SchemaVersion != "1" || doc.Kind != "sensor-update-metadata" || !contracts.ValidSensorID(doc.SensorID) || !version(doc.Revision) || doc.Platform != v.options.Platform || doc.Releases == nil || len(doc.Releases) > 16 || doc.RevokedVersions == nil || len(doc.RevokedVersions) > 64 {
		return Metadata{}, ErrInvalidInput
	}
	if !window(doc.IssuedAt, doc.ExpiresAt, at, v.options.MaxMetadataTTL) {
		return Metadata{}, ErrExpired
	}
	seen := map[uint64]bool{}
	for _, r := range doc.Releases {
		if !version(r.Version) || seen[r.Version] || !digestPattern.MatchString(r.SHA256) || r.Length < 1 || r.Length > v.options.MaxArtifactBytes {
			return Metadata{}, ErrInvalidInput
		}
		seen[r.Version] = true
	}
	seen = map[uint64]bool{}
	for _, n := range doc.RevokedVersions {
		if !version(n) || seen[n] {
			return Metadata{}, ErrInvalidInput
		}
		seen[n] = true
	}
	return doc, nil
}

func revoked(doc Metadata, n uint64) bool {
	for _, x := range doc.RevokedVersions {
		if x == n {
			return true
		}
	}
	return false
}
func release(doc Metadata, n uint64) (Release, bool) {
	for _, r := range doc.Releases {
		if r.Version == n {
			return r, true
		}
	}
	return Release{}, false
}

func (v *Verifier) advance(s *state, doc Metadata) error {
	if s.document.Revision > 0 {
		if doc.Revision <= s.document.Revision {
			return ErrStale
		}
		start, _ := instant(doc.IssuedAt)
		prior, _ := instant(s.document.IssuedAt)
		if start.Before(prior) {
			return ErrStale
		}
		for _, n := range s.document.RevokedVersions {
			if !revoked(doc, n) {
				return ErrRevoked
			}
		}
	}
	for _, r := range doc.Releases {
		if old, ok := s.releases[r.Version]; ok && old != r {
			return ErrConflict
		}
	}
	for _, r := range doc.Releases {
		s.releases[r.Version] = r
	}
	s.document = doc
	return nil
}

func (v *Verifier) grant(s *state, r contracts.UpdateRecord, at time.Time) error {
	var g RecoveryGrant
	if len(r.RecoverySignature) != ed25519.SignatureSize || !ed25519.Verify(v.options.RecoveryKey, r.RecoveryPayload, r.RecoverySignature) || !canonical(r.RecoveryPayload, &g, 2048) || g.SchemaVersion != "1" || g.Kind != "sensor-update-recovery" || !grantPattern.MatchString(g.ID) || s.grants[g.ID] || g.SensorID != r.SensorID || g.MetadataRevision != s.document.Revision || g.Platform != v.options.Platform || g.FromVersion != s.last.Update.Version || g.ToVersion != r.Version || g.SHA256 != r.ArtifactDigest || g.Length != r.ArtifactLength || !window(g.IssuedAt, g.ExpiresAt, at, v.options.MaxRecoveryTTL) || len(g.Reason) == 0 || utf8.RuneCountInString(g.Reason) > 256 {
		return ErrRecovery
	}
	for _, c := range g.Reason {
		if unicode.IsControl(c) {
			return ErrRecovery
		}
	}
	return nil
}

func (v *Verifier) candidate(s *state, r contracts.UpdateRecord, at time.Time) error {
	if s == nil || s.document.Revision == 0 {
		return ErrEvidence
	}
	if _, err := v.metadata(s.authority.Update.Payload, s.authority.Update.Signature, at); err != nil {
		return err
	}
	if r.MetadataRevision != s.document.Revision || r.MetadataDigest != hash(s.authority.Update.Payload) {
		return ErrStale
	}
	if revoked(s.document, r.Version) {
		return ErrRevoked
	}
	target, ok := release(s.document, r.Version)
	if !ok {
		return ErrEvidence
	}
	if target.SHA256 != r.ArtifactDigest || target.Length != r.ArtifactLength {
		return ErrArtifact
	}
	if r.Version < s.high {
		if len(r.RecoveryPayload) == 0 {
			return ErrRollback
		}
		if s.last.Update == nil {
			return ErrRecovery
		}
		return v.grant(s, r, at)
	}
	if len(r.RecoveryPayload) != 0 || len(r.RecoverySignature) != 0 {
		return ErrRecovery
	}
	return nil
}

func (v *Verifier) project(ctx context.Context, records []storage.Record) (map[string]*state, error) {
	states := map[string]*state{}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := record.Update
		if r == nil {
			continue
		}
		s := states[r.SensorID]
		if s == nil {
			s = &state{releases: map[uint64]Release{}, grants: map[string]bool{}}
			states[r.SensorID] = s
			if len(states) > v.options.MaxSensors {
				return nil, storage.ErrRecovery
			}
		}
		at, _ := instant(r.AcceptedAt)
		if r.Kind == contracts.UpdateMetadata {
			doc, err := v.metadata(r.Payload, r.Signature, at)
			if err != nil || doc.SensorID != r.SensorID || record.Receipt.OperationID != operation(r.SensorID, "metadata", doc.Revision) {
				return nil, storage.ErrRecovery
			}
			if err := v.advance(s, doc); err != nil {
				return nil, storage.ErrRecovery
			}
			s.authority = record
		} else {
			previous := uint64(0)
			if s.last.Update != nil {
				previous = s.last.Update.VerificationRevision
			}
			if r.VerificationRevision != previous+1 || record.Receipt.OperationID != decisionID(*r) || v.candidate(s, *r, at) != nil {
				return nil, storage.ErrRecovery
			}
			if len(r.RecoveryPayload) > 0 {
				var g RecoveryGrant
				json.Unmarshal(r.RecoveryPayload, &g)
				s.grants[g.ID] = true
			}
			s.high = max(s.high, r.Version)
			s.last = record
		}
	}
	return states, nil
}

func (v *Verifier) Accept(ctx context.Context, payload, signature []byte) (MetadataResult, error) {
	if v == nil || ctx == nil {
		return MetadataResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return MetadataResult{}, err
	}
	payload = append([]byte(nil), payload...)
	signature = append([]byte(nil), signature...)
	if _, err := v.metadata(payload, signature, v.options.Clock()); err != nil {
		return MetadataResult{}, err
	}
	var result MetadataResult
	receipt, err := v.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		all, err := v.project(ctx, records)
		if err != nil {
			return "", nil, err
		}
		at := v.options.Clock().UTC()
		doc, err := v.metadata(payload, signature, at)
		if err != nil {
			return "", nil, err
		}
		s := all[doc.SensorID]
		if s != nil && doc.Revision == s.document.Revision {
			if !bytes.Equal(payload, s.authority.Update.Payload) || !bytes.Equal(signature, s.authority.Update.Signature) {
				return "", nil, ErrConflict
			}
			result = MetadataResult{SensorID: doc.SensorID, Revision: doc.Revision, ExpiresAt: doc.ExpiresAt, Replayed: true}
			return s.authority.Receipt.OperationID, s.authority.Input, nil
		}
		if s == nil {
			if len(all) >= v.options.MaxSensors {
				return "", nil, storage.ErrQuota
			}
			s = &state{releases: map[uint64]Release{}}
		}
		if err := v.advance(s, doc); err != nil {
			return "", nil, err
		}
		raw, _ := json.Marshal(contracts.UpdateRecord{SchemaVersion: "1", Kind: contracts.UpdateMetadata, SensorID: doc.SensorID, AcceptedAt: at.Format(time.RFC3339Nano), Payload: payload, Signature: signature})
		result = MetadataResult{SensorID: doc.SensorID, Revision: doc.Revision, ExpiresAt: doc.ExpiresAt}
		return operation(doc.SensorID, "metadata", doc.Revision), raw, nil
	})
	if err != nil {
		return MetadataResult{}, err
	}
	result.Receipt = receipt
	return result, nil
}

func sameDecision(a, b contracts.UpdateRecord) bool {
	a.AcceptedAt = ""
	b.AcceptedAt = ""
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func decisionID(r contracts.UpdateRecord) string {
	return operation(r.SensorID, "candidate", r.VerificationRevision)
}

func (v *Verifier) artifact(ctx context.Context, reader io.Reader) (string, int64, error) {
	h := sha256.New()
	limit := io.LimitReader(reader, v.options.MaxArtifactBytes+1)
	buffer := make([]byte, 32768)
	total := int64(0)
	empty := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, err := limit.Read(buffer)
		if n < 0 || n > len(buffer) {
			return "", 0, ErrArtifact
		}
		total += int64(n)
		if total > v.options.MaxArtifactBytes {
			return "", 0, ErrArtifact
		}
		h.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, ErrArtifact
		}
		if n == 0 {
			empty++
			if empty > 100 {
				return "", 0, ErrArtifact
			}
		} else {
			empty = 0
		}
	}
	if total == 0 {
		return "", 0, ErrArtifact
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

func result(record storage.Record, high uint64, replayed bool) Result {
	r := record.Update
	return Result{SensorID: r.SensorID, MetadataRevision: r.MetadataRevision, Version: r.Version, HighWaterVersion: high, SHA256: r.ArtifactDigest, Length: r.ArtifactLength, VerifiedAt: r.AcceptedAt, Recovery: len(r.RecoveryPayload) > 0, Replayed: replayed, Receipt: record.Receipt}
}

func (v *Verifier) Verify(ctx context.Context, request Request) (Result, error) {
	if v == nil || ctx == nil || !contracts.ValidSensorID(request.SensorID) || !version(request.Version) || request.Artifact == nil || len(request.RecoveryPayload) > 2048 || len(request.RecoverySignature) > ed25519.SignatureSize {
		return Result{}, ErrInvalidInput
	}
	request.RecoveryPayload = append([]byte(nil), request.RecoveryPayload...)
	request.RecoverySignature = append([]byte(nil), request.RecoverySignature...)
	digest, length, err := v.artifact(ctx, request.Artifact)
	if err != nil {
		return Result{}, err
	}
	var chosen storage.Record
	var high uint64
	var replayed bool
	receipt, err := v.store.Update(ctx, func(records []storage.Record) (string, []byte, error) {
		all, err := v.project(ctx, records)
		if err != nil {
			return "", nil, err
		}
		s := all[request.SensorID]
		if s == nil {
			return "", nil, ErrEvidence
		}
		at := v.options.Clock().UTC()
		r := contracts.UpdateRecord{SchemaVersion: "1", Kind: contracts.UpdateVerified, SensorID: request.SensorID, AcceptedAt: at.Format(time.RFC3339Nano), MetadataRevision: s.document.Revision, MetadataDigest: hash(s.authority.Update.Payload), Version: request.Version, ArtifactDigest: digest, ArtifactLength: length, RecoveryPayload: request.RecoveryPayload, RecoverySignature: request.RecoverySignature}
		if s.last.Update != nil {
			r.VerificationRevision = s.last.Update.VerificationRevision
		}
		if s.last.Update != nil && sameDecision(r, *s.last.Update) {
			if _, err := v.metadata(s.authority.Update.Payload, s.authority.Update.Signature, at); err != nil {
				return "", nil, err
			}
			if revoked(s.document, r.Version) {
				return "", nil, ErrRevoked
			}
			if len(r.RecoveryPayload) > 0 {
				var g RecoveryGrant
				if json.Unmarshal(r.RecoveryPayload, &g) != nil || !window(g.IssuedAt, g.ExpiresAt, at, v.options.MaxRecoveryTTL) {
					return "", nil, ErrRecovery
				}
			}
			chosen = s.last
			high = s.high
			replayed = true
			return chosen.Receipt.OperationID, chosen.Input, nil
		}
		if err := v.candidate(s, r, at); err != nil {
			return "", nil, err
		}
		r.VerificationRevision++
		if !version(r.VerificationRevision) {
			return "", nil, storage.ErrQuota
		}
		raw, _ := json.Marshal(r)
		chosen = storage.Record{Input: raw, Update: &r}
		high = max(s.high, r.Version)
		return decisionID(r), raw, nil
	})
	if err != nil {
		return Result{}, err
	}
	chosen.Receipt = receipt
	return result(chosen, high, replayed), nil
}

func (v *Verifier) Snapshot(ctx context.Context) (Snapshot, error) {
	if v == nil || ctx == nil {
		return Snapshot{}, ErrInvalidInput
	}
	records, err := v.store.Records(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	all, err := v.project(ctx, records)
	if err != nil {
		return Snapshot{}, err
	}
	at := v.options.Clock().UTC()
	if !validNow(at) {
		return Snapshot{}, ErrInvalidInput
	}
	snapshot := Snapshot{SchemaVersion: "1", Platform: v.options.Platform, PublisherFingerprint: hash(v.options.PublisherKey), RecoveryFingerprint: hash(v.options.RecoveryKey), ObservedAt: at.Format(time.RFC3339Nano), Sensors: []SensorStatus{}}
	for id, s := range all {
		doc := s.document
		status := SensorStatus{SensorID: id, Revision: doc.Revision, IssuedAt: doc.IssuedAt, ExpiresAt: doc.ExpiresAt, MetadataDigest: hash(s.authority.Update.Payload), RevokedVersions: append([]uint64{}, doc.RevokedVersions...), Releases: append([]Release{}, doc.Releases...), HighWaterVersion: s.high, Status: "no_candidate"}
		if last := s.last.Update; last != nil {
			status.Version = last.Version
			status.VerifiedRevision = last.MetadataRevision
			status.VerifiedAt = last.AcceptedAt
			status.Recovery = len(last.RecoveryPayload) > 0
			status.Status = "verified"
			if last.MetadataRevision != doc.Revision {
				status.Status = "authority_changed"
			}
			if revoked(doc, last.Version) {
				status.Status = "revoked"
			}
		}
		if _, err := v.metadata(s.authority.Update.Payload, s.authority.Update.Signature, at); err != nil {
			status.Status = "expired"
		}
		snapshot.Sensors = append(snapshot.Sensors, status)
	}
	sort.Slice(snapshot.Sensors, func(i, j int) bool { return snapshot.Sensors[i].SensorID < snapshot.Sensors[j].SensorID })
	raw, _ := json.Marshal(snapshot)
	if len(raw) > 1048576 {
		return Snapshot{}, storage.ErrQuota
	}
	return snapshot, nil
}
