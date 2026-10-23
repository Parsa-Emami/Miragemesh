// Package enrollment implements internal local enrollment, not certificate issuance.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var (
	ErrInvalidInput = errors.New("invalid enrollment input")
	ErrInvalidTTL   = errors.New("invalid enrollment TTL")
	ErrInvalidToken = errors.New("invalid enrollment token")
	ErrExpired      = errors.New("enrollment token expired")
	ErrReplay       = errors.New("enrollment token already consumed")
	ErrScope        = errors.New("enrollment sensor scope mismatch")
)

type Service struct {
	store  *storage.Store
	maxTTL time.Duration
	now    func() time.Time
}
type IssuedToken struct {
	Token     string    `json:"-"`
	SensorID  string    `json:"sensor_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Enrollment struct {
	SensorID   string          `json:"sensor_id"`
	ConsumedAt time.Time       `json:"consumed_at"`
	Receipt    storage.Receipt `json:"receipt"`
}

// New requires trusted in-process dependencies; production callers pass time.Now.
func New(store *storage.Store, maxTTL time.Duration, now func() time.Time) (*Service, error) {
	if store == nil || maxTTL <= 0 || now == nil {
		return nil, ErrInvalidInput
	}
	return &Service{store: store, maxTTL: maxTTL, now: now}, nil
}
func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }

func (s *Service) Issue(ctx context.Context, sensorID string, ttl time.Duration) (IssuedToken, error) {
	if err := ctx.Err(); err != nil {
		return IssuedToken{}, err
	}
	if !contracts.ValidSensorID(sensorID) {
		return IssuedToken{}, ErrInvalidInput
	}
	if ttl <= 0 || ttl > s.maxTTL {
		return IssuedToken{}, ErrInvalidTTL
	}
	now := s.now().UTC()
	expires := now.Add(ttl)
	if !validTime(now) || !validTime(expires) {
		return IssuedToken{}, ErrInvalidInput
	}
	random := make([]byte, 32)
	rand.Read(random)
	token := base64.RawURLEncoding.EncodeToString(random)
	record := contracts.EnrollmentRecord{SchemaVersion: contracts.SchemaVersion, Kind: contracts.EnrollmentIssue, SensorID: sensorID, TokenHash: hash(token), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(record)
	_, err := s.store.CommitOnceChecked(ctx, "enrollment/issue/"+record.TokenHash, raw, func(r storage.Record) error {
		if r.Receipt.Generation == 0 {
			checked := s.now().UTC()
			if !validTime(checked) || checked.Before(now) {
				return ErrInvalidInput
			}
			if !checked.Before(expires) {
				return ErrExpired
			}
		}
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: token, SensorID: sensorID, ExpiresAt: expires}, nil
}

func (s *Service) Consume(ctx context.Context, token, sensorID string) (Enrollment, error) {
	if err := ctx.Err(); err != nil {
		return Enrollment{}, err
	}
	if !contracts.ValidSensorID(sensorID) {
		return Enrollment{}, ErrInvalidInput
	}
	if len(token) != 43 {
		return Enrollment{}, ErrInvalidToken
	}
	rawToken, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(rawToken) != 32 {
		return Enrollment{}, ErrInvalidToken
	}
	tokenHash := hash(token)
	issueID := "enrollment/issue/" + tokenHash
	stored, err := s.store.Read(ctx, issueID)
	if errors.Is(err, storage.ErrNotFound) {
		return Enrollment{}, ErrInvalidToken
	}
	if err != nil {
		return Enrollment{}, err
	}
	if stored.Enrollment == nil || stored.Enrollment.Kind != contracts.EnrollmentIssue || stored.Enrollment.TokenHash != tokenHash {
		return Enrollment{}, storage.ErrRecovery
	}
	issue := *stored.Enrollment
	if issue.SensorID != sensorID {
		return Enrollment{}, ErrScope
	}
	issued, _ := time.Parse(time.RFC3339Nano, issue.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, issue.ExpiresAt)
	now := s.now().UTC()
	if !validTime(now) || now.Before(issued) {
		return Enrollment{}, ErrInvalidInput
	}
	if !now.Before(expires) {
		return Enrollment{}, ErrExpired
	}
	consumed := issue
	consumed.Kind = contracts.EnrollmentConsume
	consumed.ConsumedAt = now.Format(time.RFC3339Nano)
	raw, _ := json.Marshal(consumed)
	seenIssue := false
	receipt, err := s.store.CommitOnceChecked(ctx, "enrollment/consume/"+tokenHash, raw, func(r storage.Record) error {
		if r.Receipt.Generation != 0 {
			if r.Rotation != nil && r.Rotation.TokenHash == tokenHash {
				return ErrReplay
			}
			if r.Receipt.OperationID == issueID {
				if r.Enrollment == nil || *r.Enrollment != issue {
					return storage.ErrRecovery
				}
				seenIssue = true
			}
			return nil
		}
		if !seenIssue {
			return ErrInvalidToken
		}
		// Recheck expiry after acquiring the writer lock, before filesystem effects.
		checked := s.now().UTC()
		if !validTime(checked) || checked.Before(issued) {
			return ErrInvalidInput
		}
		if !checked.Before(expires) {
			return ErrExpired
		}
		return nil
	})
	if errors.Is(err, storage.ErrConflict) {
		return Enrollment{}, ErrReplay
	}
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{SensorID: sensorID, ConsumedAt: now, Receipt: receipt}, nil
}
