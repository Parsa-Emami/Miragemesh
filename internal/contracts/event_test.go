package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "miragemesh", "C04", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestValidAndIncompatibleFixtures(t *testing.T) {
	data := fixture(t, "valid-event.txt")
	event, err := DecodeEvent(context.Background(), data)
	if err != nil || event.SensorID != "sensor-01" || event.Metadata.Path != "/health" || event.Sequence != 1 {
		t.Fatalf("%+v %v", event, err)
	}
	result := Validate(context.Background(), io.NopCloser(strings.NewReader(string(data))), "0.0.1")
	hash := sha256.Sum256(data)
	if result.Status != "unverified" || !result.Result.Valid || result.InputDigest == nil || *result.InputDigest != hex.EncodeToString(hash[:]) {
		t.Fatalf("%+v", result)
	}
	var negative struct {
		Cases []struct {
			Name  string
			Input json.RawMessage
			Raw   *string
			Code  string
		}
	}
	if err := json.Unmarshal(fixture(t, "invalid.json"), &negative); err != nil {
		t.Fatal(err)
	}
	for _, item := range negative.Cases {
		t.Run(item.Name, func(t *testing.T) {
			bytes := []byte(item.Input)
			if item.Raw != nil {
				bytes = []byte(*item.Raw)
			}
			_, failure := DecodeEvent(context.Background(), bytes)
			if failure == nil || string(failure.Code) != item.Code {
				t.Fatalf("expected %s, got %v", item.Code, failure)
			}
		})
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("synthetic-private-sentinel") }
func (brokenReader) Close() error             { return nil }

func TestReadFailureCancellationAndDeadline(t *testing.T) {
	failed := Validate(context.Background(), brokenReader{}, "0.0.1")
	if failed.Result.Error == nil || failed.Result.Error.Code != InputReadFailed || failed.InputDigest != nil {
		t.Fatalf("%+v", failed)
	}
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		reader, writer := io.Pipe()
		result := Validate(ctx, reader, "0.0.1")
		cancel()
		writer.Close()
		want := Cancelled
		if deadline {
			want = Timeout
		}
		if result.Result.Error == nil || result.Result.Error.Code != want || result.InputDigest != nil {
			t.Fatalf("%+v", result)
		}
	}
}

func TestExactNumbersAndBounds(t *testing.T) {
	data := string(fixture(t, "valid-event.txt"))
	for _, number := range []string{"0", "9007199254740991", "1.0", "1e0", "0e99999999999999999999999"} {
		if _, err := DecodeEvent(context.Background(), []byte(strings.Replace(data, `"sequence":1`, `"sequence":`+number, 1))); err != nil {
			t.Fatalf("%s: %v", number, err)
		}
	}
	for _, number := range []string{"9007199254740992", "9007199254740990.5", "1e999999999999999999", "1e-999999999999999999"} {
		if _, err := DecodeEvent(context.Background(), []byte(strings.Replace(data, `"sequence":1`, `"sequence":`+number, 1))); err == nil || err.Code != InvalidInput {
			t.Fatalf("%s: %v", number, err)
		}
	}
	_, err := DecodeEvent(context.Background(), []byte(strings.Repeat(" ", 8193)))
	if err == nil || err.Code != InputTooLarge {
		t.Fatal(err)
	}
}

func FuzzDecodeEvent(f *testing.F) {
	f.Add([]byte(`{"schema_version":"1","sensor_id":"s","event_id":"e","sequence":0,"observed_at":"2026-01-01T00:00:00Z","kind":"http.request","metadata":{"path":"/"}}`))
	f.Add([]byte(`{"metadata":{"path":"/","path":"duplicate"}}`))
	f.Add([]byte{0xff, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		event, failure := DecodeEvent(context.Background(), data)
		if failure == nil && (len(data) > MaxInputBytes || event.Kind != "http.request" || event.Metadata.Path == "" || event.Sequence < 0 || event.Sequence > MaxSequence) {
			t.Fatal("invalid event accepted")
		}
	})
}
