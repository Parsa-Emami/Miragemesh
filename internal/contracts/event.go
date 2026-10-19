// Package contracts defines local validation, not sensor identity or event acceptance.
package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion           = "1"
	MaxInputBytes           = 8192
	MaxSequence       int64 = 9007199254740991
	ValidationTimeout       = 2 * time.Second
)

type ErrorCode string

const (
	InvalidJSON        ErrorCode = "INVALID_JSON"
	UnsupportedVersion ErrorCode = "UNSUPPORTED_VERSION"
	InvalidInput       ErrorCode = "INVALID_INPUT"
	InputTooLarge      ErrorCode = "INPUT_TOO_LARGE"
	InputReadFailed    ErrorCode = "INPUT_READ_FAILED"
	Cancelled          ErrorCode = "CANCELLED"
	Timeout            ErrorCode = "TIMEOUT"
)

type ValidationError struct {
	Code  ErrorCode `json:"code"`
	Field string    `json:"field,omitempty"`
}

func (e *ValidationError) Error() string { return string(e.Code) }

type HTTPMetadata struct {
	Path string `json:"path"`
}

type Event struct {
	SchemaVersion string       `json:"schema_version"`
	SensorID      string       `json:"sensor_id"`
	EventID       string       `json:"event_id"`
	Sequence      int64        `json:"sequence"`
	ObservedAt    string       `json:"observed_at"`
	Kind          string       `json:"kind"`
	Metadata      HTTPMetadata `json:"metadata"`
}

type Outcome struct {
	Valid    bool             `json:"valid"`
	SensorID string           `json:"sensor_id,omitempty"`
	EventID  string           `json:"event_id,omitempty"`
	Sequence *int64           `json:"sequence,omitempty"`
	Error    *ValidationError `json:"error,omitempty"`
}

type Result struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	InputDigest   *string  `json:"input_digest"`
	EngineVersion string   `json:"engine_version"`
	Result        Outcome  `json:"result"`
	Warnings      []string `json:"warnings"`
}

func contextError(ctx context.Context) *ValidationError {
	if ctx.Err() == context.DeadlineExceeded {
		return &ValidationError{Code: Timeout}
	}
	if ctx.Err() != nil {
		return &ValidationError{Code: Cancelled}
	}
	return nil
}

// Decode object members before assigning Go fields: encoding/json alone accepts
// duplicate members and case-insensitive matches, which would change the contract.
func object(ctx context.Context, raw []byte, allowed []string, scope string) (map[string]json.RawMessage, *ValidationError) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, &ValidationError{Code: InvalidJSON}
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		if failure := contextError(ctx); failure != nil {
			return nil, failure
		}
		key, err := decoder.Token()
		if err != nil {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		name := key.(string)
		if _, exists := fields[name]; exists {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		known := false
		for _, field := range allowed {
			if name == field {
				known = true
				break
			}
		}
		if !known {
			return nil, &ValidationError{Code: InvalidInput, Field: scope}
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, &ValidationError{Code: InvalidJSON}
	}
	return fields, nil
}

// Use exact arithmetic before converting to the shared safe-integer range.
func sequence(raw []byte) (int64, bool) {
	number := strings.TrimSpace(string(raw))
	if number == "" || !(number[0] == '-' || number[0] >= '0' && number[0] <= '9') {
		return 0, false
	}
	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(number), "e")
	if strings.Trim(mantissa, "-0.") == "" {
		return 0, true
	}
	if hasExponent {
		power, err := strconv.Atoi(exponent)
		if err != nil || power < -MaxInputBytes || power > MaxInputBytes {
			return 0, false
		}
	}
	value, ok := new(big.Rat).SetString(number)
	if !ok || !value.IsInt() || !value.Num().IsInt64() {
		return 0, false
	}
	n := value.Num().Int64()
	return n, n >= 0 && n <= MaxSequence
}

var timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD; reject them
// before decoding so distinct malformed sensor IDs cannot become one value.
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		unit, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func DecodeEvent(ctx context.Context, data []byte) (Event, *ValidationError) {
	var event Event
	if failure := contextError(ctx); failure != nil {
		return event, failure
	}
	if len(data) > MaxInputBytes {
		return event, &ValidationError{Code: InputTooLarge}
	}
	if !utf8.Valid(data) || !json.Valid(data) || !validEscapes(data) {
		return event, &ValidationError{Code: InvalidJSON}
	}
	fields, failure := object(ctx, data, []string{"schema_version", "sensor_id", "event_id", "sequence", "observed_at", "kind", "metadata"}, "")
	if failure != nil {
		return event, failure
	}
	if json.Unmarshal(fields["schema_version"], &event.SchemaVersion) != nil || event.SchemaVersion != SchemaVersion {
		return Event{}, &ValidationError{Code: UnsupportedVersion, Field: "schema_version"}
	}
	for _, field := range []string{"sensor_id", "event_id", "sequence", "observed_at", "kind", "metadata"} {
		if _, exists := fields[field]; !exists {
			return Event{}, &ValidationError{Code: InvalidInput, Field: field}
		}
	}
	for _, field := range []struct {
		name   string
		target *string
	}{{"sensor_id", &event.SensorID}, {"event_id", &event.EventID}, {"observed_at", &event.ObservedAt}, {"kind", &event.Kind}} {
		if json.Unmarshal(fields[field.name], field.target) != nil {
			return Event{}, &ValidationError{Code: InvalidInput, Field: field.name}
		}
	}
	for _, field := range []struct{ name, value string }{{"sensor_id", event.SensorID}, {"event_id", event.EventID}} {
		if length := utf8.RuneCountInString(field.value); length < 1 || length > 128 {
			return Event{}, &ValidationError{Code: InvalidInput, Field: field.name}
		}
	}
	n, ok := sequence(fields["sequence"])
	if !ok {
		return Event{}, &ValidationError{Code: InvalidInput, Field: "sequence"}
	}
	event.Sequence = n
	if _, err := time.Parse(time.RFC3339Nano, event.ObservedAt); err != nil || !timestamp.MatchString(event.ObservedAt) {
		return Event{}, &ValidationError{Code: InvalidInput, Field: "observed_at"}
	}
	if event.Kind != "http.request" {
		return Event{}, &ValidationError{Code: InvalidInput, Field: "kind"}
	}
	if !bytes.HasPrefix(bytes.TrimSpace(fields["metadata"]), []byte("{")) {
		return Event{}, &ValidationError{Code: InvalidInput, Field: "metadata"}
	}
	metadata, failure := object(ctx, fields["metadata"], []string{"path"}, "metadata")
	if failure != nil {
		return Event{}, failure
	}
	if json.Unmarshal(metadata["path"], &event.Metadata.Path) != nil || event.Metadata.Path == "" {
		return Event{}, &ValidationError{Code: InvalidInput, Field: "metadata"}
	}
	if failure := contextError(ctx); failure != nil {
		return Event{}, failure
	}
	return event, nil
}

// Validate owns and closes input, including on cancellation. Use DecodeEvent
// instead when a future storage adapter owns already-bounded bytes.
func Validate(ctx context.Context, input io.ReadCloser, engineVersion string) Result {
	defer input.Close()
	result := Result{SchemaVersion: SchemaVersion, Status: "failed", EngineVersion: engineVersion, Warnings: []string{}}
	if failure := contextError(ctx); failure != nil {
		result.Result.Error = failure
		return result
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1)); read <- readResult{data, err} }()
	select {
	case <-ctx.Done():
		result.Result.Error = contextError(ctx)
	case bytes := <-read:
		if failure := contextError(ctx); failure != nil {
			result.Result.Error = failure
			break
		}
		if len(bytes.data) > MaxInputBytes {
			result.Result.Error = &ValidationError{Code: InputTooLarge}
			break
		}
		if bytes.err != nil {
			result.Result.Error = &ValidationError{Code: InputReadFailed}
			break
		}
		hash := sha256.Sum256(bytes.data)
		digest := hex.EncodeToString(hash[:])
		result.InputDigest = &digest
		event, failure := DecodeEvent(ctx, bytes.data)
		if failure != nil {
			result.Result.Error = failure
			if failure.Code == Cancelled || failure.Code == Timeout {
				result.InputDigest = nil
			}
			break
		}
		result.Status = "unverified"
		result.Result = Outcome{Valid: true, SensorID: event.SensorID, EventID: event.EventID, Sequence: &event.Sequence}
	}
	return result
}
