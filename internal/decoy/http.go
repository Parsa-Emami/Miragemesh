// Package decoy implements a limited metadata-only HTTP decoy.
//
// The decoy records one bounded observation per accepted request and nothing
// else. It never executes a command, never opens a file, never contacts a
// remote service and never echoes request content back to the caller: the only
// observed request field is the request path. The observation is the existing
// version 1 sensor event, so the event contract, the sequence rules and the
// durable store stay unchanged.
//
// A request is accepted only inside the explicit bounds of the deployment: an
// allowed method, a path inside the path bound and a body inside the request
// bound. Every other request fails with a typed status and a fixed body that
// contains nothing from the request. An unavailable store fails the same way;
// the decoy never reports a success it did not durably record.
//
// This package is a component, not a published surface. It opens no listener,
// runs no container and proves no isolation: egress denial and the runtime
// limits belong to the C13 isolation work.
package decoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

// ErrInvalidInput reports an incomplete or contradictory local configuration.
var ErrInvalidInput = errors.New("invalid decoy input")

// The observation kind is the version 1 event contract kind for an HTTP
// request. The decoy does not introduce a second event format.
const observationKind = "http.request"

// The response bodies are fixed. They carry no request-derived value, so a
// caller can never read back what it sent.
const (
	bodyAccepted    = `{"status":"ok"}`
	bodyInvalid     = `{"error":"invalid_request"}`
	bodyNotAllowed  = `{"error":"method_not_allowed"}`
	bodyTooLarge    = `{"error":"request_too_large"}`
	bodyUnavailable = `{"error":"unavailable"}`
	allowedGet      = http.MethodGet
	allowedHead     = http.MethodHead
	allowedPost     = http.MethodPost
	allowedMethods  = allowedGet + ", " + allowedHead + ", " + allowedPost
	contentType     = "application/json"
)

// Options is the trusted local configuration of one decoy. The engine ships no
// default: a deployment states the identity of the decoy and the accepted
// bounds of every request it exposes.
type Options struct {
	// SensorID is the identity the observations are recorded under. It is
	// separate from a device identity so that decoy observations never share
	// the sequence space of the reported sensor events.
	SensorID string
	// MaxRequestBytes is the largest accepted request body in bytes.
	MaxRequestBytes int64
	// MaxPathBytes is the largest accepted and recorded path in bytes.
	MaxPathBytes int
	// Clock is the authoritative local clock of the observation timestamp.
	Clock func() time.Time
}

// Service is one metadata-only HTTP decoy bound to one durable store.
type Service struct {
	store   *storage.Store
	options Options
	mu      sync.Mutex
	next    int64
}

// New validates the trusted local configuration and recovers the observation
// sequence from the durable history, so a restarted decoy continues the
// sequence of the accepted observations instead of reusing one.
func New(ctx context.Context, store *storage.Store, options Options) (*Service, error) {
	if store == nil || options.Clock == nil || !contracts.ValidSensorID(options.SensorID) ||
		options.MaxRequestBytes <= 0 || options.MaxRequestBytes > contracts.MaxInputBytes ||
		options.MaxPathBytes <= 0 || options.MaxPathBytes > contracts.MaxInputBytes {
		return nil, ErrInvalidInput
	}
	next, err := recoverSequence(ctx, store, options.SensorID)
	if err != nil {
		return nil, err
	}
	return &Service{store: store, options: options, next: next}, nil
}

// recoverSequence returns the next observation sequence of one identity. A
// history that is not contiguous fails closed instead of being renumbered.
func recoverSequence(ctx context.Context, store *storage.Store, sensorID string) (int64, error) {
	records, err := store.Records(ctx)
	if err != nil {
		return 0, err
	}
	var last int64
	for _, record := range records {
		if record.Event.SensorID != sensorID {
			continue
		}
		if record.Event.Sequence != last+1 {
			return 0, storage.ErrRecovery
		}
		last = record.Event.Sequence
	}
	return last + 1, nil
}

// ServeHTTP answers one request. Only the path of an accepted request is
// observed; the query, the headers and the body are discarded and never
// recorded or echoed.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.store == nil || r == nil {
		write(w, "", http.StatusServiceUnavailable, bodyUnavailable, "")
		return
	}
	if !allowedMethod(r.Method) {
		write(w, r.Method, http.StatusMethodNotAllowed, bodyNotAllowed, allowedMethods)
		return
	}
	if r.ContentLength > s.options.MaxRequestBytes {
		write(w, r.Method, http.StatusRequestEntityTooLarge, bodyTooLarge, "")
		return
	}
	if r.Body != nil {
		// The body is read only to enforce the bound and is discarded at once.
		r.Body = http.MaxBytesReader(w, r.Body, s.options.MaxRequestBytes)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			write(w, r.Method, http.StatusRequestEntityTooLarge, bodyTooLarge, "")
			return
		}
	}
	if !validPath(r.URL.Path, s.options.MaxPathBytes) {
		write(w, r.Method, http.StatusBadRequest, bodyInvalid, "")
		return
	}
	if _, err := s.observe(r.Context(), r.URL.Path); err != nil {
		write(w, r.Method, http.StatusServiceUnavailable, bodyUnavailable, "")
		return
	}
	write(w, r.Method, http.StatusOK, bodyAccepted, "")
}

// observe records one observation and returns its durable receipt. The
// sequence advances only after the store accepted the record, so a failed
// observation leaves no gap in the accepted history.
func (s *Service) observe(ctx context.Context, path string) (storage.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.options.Clock().UTC()
	if now.IsZero() || now.Year() < 1000 || now.Year() > 9999 {
		return storage.Receipt{}, ErrInvalidInput
	}
	event := contracts.Event{
		SchemaVersion: contracts.SchemaVersion,
		SensorID:      s.options.SensorID,
		EventID:       eventID(s.options.SensorID, s.next),
		Sequence:      s.next,
		ObservedAt:    now.Format(time.RFC3339Nano),
		Kind:          observationKind,
		Metadata:      contracts.HTTPMetadata{Path: path},
	}
	raw, err := json.Marshal(event)
	if err != nil || len(raw) > contracts.MaxInputBytes {
		return storage.Receipt{}, ErrInvalidInput
	}
	receipt, err := sensor.Accept(ctx, s.store, raw)
	if err != nil {
		return storage.Receipt{}, err
	}
	s.next++
	return receipt, nil
}

// eventID derives a stable identifier from the identity and the sequence of
// one observation. The identity never enters a file path and the sequence
// keeps the identifier unique inside one decoy.
func eventID(sensorID string, sequence int64) string {
	sum := sha256.Sum256([]byte("decoy-observation|" + sensorID + "|" + strconv.FormatInt(sequence, 10)))
	return "decoy-" + hex.EncodeToString(sum[:16])
}

// allowedMethod reports whether one method is inside the decoy surface.
func allowedMethod(method string) bool {
	return method == allowedGet || method == allowedHead || method == allowedPost
}

// validPath reports whether one path can be observed. The recorded path is
// never resolved against a file, a command or a remote service.
func validPath(path string, max int) bool {
	if path == "" || len(path) > max || !utf8.ValidString(path) {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// write answers with a fixed body and the fixed response headers. A HEAD
// request is answered with the status and the headers only.
func write(w http.ResponseWriter, method string, status int, body, allow string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
	w.WriteHeader(status)
	if method == allowedHead {
		return
	}
	io.WriteString(w, body)
}
