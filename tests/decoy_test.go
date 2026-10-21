package tests

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/decoy"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

type c12Request struct {
	Name       string            `json:"name"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Status     int               `json:"expected_status"`
	Response   string            `json:"expected_body"`
	Recorded   string            `json:"expected_recorded_path"`
	Sequence   int64             `json:"expected_sequence"`
	Declared   int64             `json:"declared_bytes"`
	BodyBytes  int               `json:"body_bytes"`
	PathLength int               `json:"path_length"`
	Unknown    bool              `json:"unknown_length"`
	Empty      bool              `json:"empty_path"`
	Control    bool              `json:"control_character_path"`
	Kind       string            `json:"kind"`
	Field      string            `json:"field"`
	Value      int64             `json:"value"`
	Error      string            `json:"expected_error"`
}

type c12Positive struct {
	FixtureVersion int    `json:"fixture_version"`
	License        string `json:"license"`
	Provenance     string `json:"provenance"`
	Now            string `json:"now"`
	SensorID       string `json:"sensor_id"`
	Marker         string `json:"sensitive_marker"`
	Options        struct {
		MaxRequestBytes int64 `json:"max_request_bytes"`
		MaxPathBytes    int   `json:"max_path_bytes"`
	} `json:"options"`
	StorageLimits storage.Limits `json:"storage_limits"`
	Requests      []c12Request   `json:"requests"`
}

type c12Expected struct {
	FixtureVersion int               `json:"fixture_version"`
	License        string            `json:"license"`
	Provenance     string            `json:"provenance"`
	Accepted       int               `json:"accepted_interactions"`
	Sequences      []int64           `json:"accepted_sequences"`
	Kind           string            `json:"recorded_kind"`
	Paths          []string          `json:"recorded_paths"`
	Rejected       int               `json:"rejected_cases"`
	Responses      map[string]string `json:"response_bodies"`
}

func c12Files(t *testing.T) (*c12Positive, []c12Request, *c12Expected) {
	t.Helper()
	var positive c12Positive
	var invalid struct {
		FixtureVersion int          `json:"fixture_version"`
		License        string       `json:"license"`
		Provenance     string       `json:"provenance"`
		Cases          []c12Request `json:"cases"`
	}
	var expected c12Expected
	for name, target := range map[string]any{"positive": &positive, "invalid": &invalid, "expected-output": &expected} {
		raw, err := os.ReadFile("fixtures/miragemesh/C12/" + name + ".json")
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("missing or malformed C12 fixture %s: %v", name, err)
		}
	}
	if positive.FixtureVersion != 1 || invalid.FixtureVersion != 1 || expected.FixtureVersion != 1 ||
		positive.License != "Apache-2.0" || invalid.License != "Apache-2.0" || expected.License != "Apache-2.0" ||
		positive.Provenance == "" || invalid.Provenance == "" || expected.Provenance == "" {
		t.Fatal("invalid C12 fixture metadata")
	}
	if len(positive.Requests) == 0 || len(invalid.Cases) == 0 {
		t.Fatal("C12 fixtures carry no cases")
	}
	if expected.Accepted != len(positive.Requests) || expected.Rejected != len(invalid.Cases) {
		t.Fatalf("C12 expected counts %d/%d do not match the fixtures %d/%d", expected.Accepted, expected.Rejected, len(positive.Requests), len(invalid.Cases))
	}
	return &positive, invalid.Cases, &expected
}

func c12Service(t *testing.T, s *storage.Store, f *c12Positive) *decoy.Service {
	t.Helper()
	now, err := time.Parse(time.RFC3339Nano, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := decoy.New(context.Background(), s, decoy.Options{
		SensorID:        f.SensorID,
		MaxRequestBytes: f.Options.MaxRequestBytes,
		MaxPathBytes:    f.Options.MaxPathBytes,
		Clock:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func c12Serve(t *testing.T, service *decoy.Service, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, request)
	return recorder
}

// c12BodyKey maps a rejected request status to its fixed response body key.
func c12BodyKey(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	return ""
}

func c12RequestFor(t *testing.T, test c12Request) *http.Request {
	t.Helper()
	var request *http.Request
	switch {
	case test.Empty:
		request = httptest.NewRequest(test.Method, "/", nil)
		request.URL = &url.URL{Path: ""}
	case test.Control:
		request = httptest.NewRequest(test.Method, "/control", nil)
		request.URL = &url.URL{Path: "/bad\x01path"}
	case test.PathLength > 0:
		request = httptest.NewRequest(test.Method, "/"+strings.Repeat("a", test.PathLength), nil)
	case test.BodyBytes > 0:
		request = httptest.NewRequest(test.Method, test.Path, strings.NewReader(strings.Repeat("x", test.BodyBytes)))
		if test.Unknown {
			request.ContentLength = -1
		}
	default:
		request = httptest.NewRequest(test.Method, test.Path, nil)
	}
	if test.Declared > 0 {
		request.ContentLength = test.Declared
	}
	return request
}

func TestDecoyRecordsMetadataOnlyInteraction(t *testing.T) {
	f, _, expected := c12Files(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	service := c12Service(t, s, f)
	for _, test := range f.Requests {
		request := httptest.NewRequest(test.Method, test.Path+test.Query, strings.NewReader(test.Body))
		for name, value := range test.Headers {
			request.Header.Set(name, value)
		}
		recorder := c12Serve(t, service, request)
		if recorder.Code != test.Status {
			t.Fatalf("%s status %d, want %d", test.Name, recorder.Code, test.Status)
		}
		if recorder.Body.String() != test.Response {
			t.Fatalf("%s body %q, want %q", test.Name, recorder.Body.String(), test.Response)
		}
		if recorder.Header().Get("X-Content-Type-Options") != "nosniff" || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s response headers %v", test.Name, recorder.Header())
		}
		if strings.Contains(recorder.Body.String(), f.Marker) {
			t.Fatalf("%s echoed request content", test.Name)
		}
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(f.Requests) {
		t.Fatalf("recorded %d observations, want %d", len(records), len(f.Requests))
	}
	for i, record := range records {
		if record.Event.SensorID != f.SensorID || record.Event.Sequence != expected.Sequences[i] {
			t.Fatalf("observation %d identity %+v", i, record.Event)
		}
		if record.Event.Kind != expected.Kind || record.Event.Metadata.Path != expected.Paths[i] {
			t.Fatalf("observation %d %+v", i, record.Event)
		}
		if record.Event.EventID == "" || !strings.Contains(string(record.Input), expected.Paths[i]) {
			t.Fatalf("observation %d input %q", i, string(record.Input))
		}
		if strings.Contains(string(record.Input), f.Marker) {
			t.Fatalf("observation %d kept request content", i)
		}
	}
}

func TestDecoyNeverEchoesRequestContent(t *testing.T) {
	f, _, expected := c12Files(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	service := c12Service(t, s, f)
	request := httptest.NewRequest(http.MethodPost, "/login?token="+f.Marker, strings.NewReader("password="+f.Marker))
	request.Header.Set("Authorization", "Bearer "+f.Marker)
	request.Header.Set("X-Synthetic", f.Marker)
	recorder := c12Serve(t, service, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if recorder.Body.String() != expected.Responses["accepted"] {
		t.Fatalf("body %q", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), f.Marker) || strings.Contains(recorder.Header().Get("Location"), f.Marker) {
		t.Fatal("response echoed request content")
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("recorded %d observations, want 1", len(records))
	}
	if strings.Contains(string(records[0].Input), f.Marker) {
		t.Fatalf("stored observation kept request content: %q", string(records[0].Input))
	}
	if records[0].Event.Metadata.Path != "/login" {
		t.Fatalf("recorded path %q", records[0].Event.Metadata.Path)
	}
}

func TestDecoyBoundsRequestSize(t *testing.T) {
	f, _, expected := c12Files(t)
	s := openStore(t, storePath(t), f.StorageLimits)
	service := c12Service(t, s, f)
	declared := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x"))
	declared.ContentLength = f.Options.MaxRequestBytes + 1
	if recorder := c12Serve(t, service, declared); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared length status %d", recorder.Code)
	}
	body := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", int(f.Options.MaxRequestBytes)+1)))
	body.ContentLength = -1
	if recorder := c12Serve(t, service, body); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status %d", recorder.Code)
	}
	atLimit := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", int(f.Options.MaxRequestBytes))))
	recorder := c12Serve(t, service, atLimit)
	if recorder.Code != http.StatusOK || recorder.Body.String() != expected.Responses["accepted"] {
		t.Fatalf("bounded body status %d body %q", recorder.Code, recorder.Body.String())
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("recorded %d observations, want 1", len(records))
	}
}

func TestDecoyRejectsUnsupportedMethodAndInvalidPath(t *testing.T) {
	f, cases, expected := c12Files(t)
	for _, test := range cases {
		if test.Kind != "request" {
			continue
		}
		s := openStore(t, storePath(t), f.StorageLimits)
		service := c12Service(t, s, f)
		recorder := c12Serve(t, service, c12RequestFor(t, test))
		if recorder.Code != test.Status {
			t.Errorf("%s status %d, want %d", test.Name, recorder.Code, test.Status)
		}
		if recorder.Body.String() != expected.Responses[c12BodyKey(test.Status)] {
			t.Errorf("%s body %q", test.Name, recorder.Body.String())
		}
		records, err := s.Records(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 0 {
			t.Errorf("%s recorded %d observations", test.Name, len(records))
		}
	}
}

func TestDecoyFailsClosedOnMissingPrerequisites(t *testing.T) {
	f, cases, expected := c12Files(t)
	now, err := time.Parse(time.RFC3339Nano, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	valid := decoy.Options{SensorID: f.SensorID, MaxRequestBytes: f.Options.MaxRequestBytes, MaxPathBytes: f.Options.MaxPathBytes, Clock: func() time.Time { return now }}
	for _, test := range cases {
		if test.Kind != "construction" {
			continue
		}
		options := valid
		var store *storage.Store
		switch test.Field {
		case "store":
			store = nil
		case "clock":
			options.Clock = nil
		case "sensor_id":
			options.SensorID = ""
		case "max_request_bytes":
			options.MaxRequestBytes = test.Value
		case "max_path_bytes":
			options.MaxPathBytes = int(test.Value)
		default:
			t.Fatalf("unknown construction field %q", test.Field)
		}
		if test.Field != "store" {
			store = openStore(t, storePath(t), f.StorageLimits)
		}
		_, err := decoy.New(context.Background(), store, options)
		if !errors.Is(err, decoy.ErrInvalidInput) {
			t.Errorf("%s error %v, want %v", test.Name, err, decoy.ErrInvalidInput)
		}
		if test.Error != decoy.ErrInvalidInput.Error() {
			t.Errorf("%s expected error %q", test.Name, test.Error)
		}
	}
	s := openStore(t, storePath(t), f.StorageLimits)
	service := c12Service(t, s, f)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := c12Serve(t, service, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != expected.Responses["unavailable"] {
		t.Fatalf("unavailable store status %d body %q", recorder.Code, recorder.Body.String())
	}
}

func TestDecoyObservationsSurviveRestart(t *testing.T) {
	f, _, expected := c12Files(t)
	path := storePath(t)
	s := openStore(t, path, f.StorageLimits)
	service := c12Service(t, s, f)
	events, _, _ := sensorEvents(t)
	if _, err := sensor.Accept(context.Background(), s, events[0]); err != nil {
		t.Fatal(err)
	}
	if recorder := c12Serve(t, service, httptest.NewRequest(http.MethodGet, "/health", nil)); recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, f.StorageLimits)
	service = c12Service(t, s, f)
	if recorder := c12Serve(t, service, httptest.NewRequest(http.MethodGet, "/ready", nil)); recorder.Code != http.StatusOK {
		t.Fatalf("status after restart %d", recorder.Code)
	}
	records, err := s.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("recorded %d observations, want 3", len(records))
	}
	if records[0].Event.SensorID != "sensor-01" || records[0].Event.Sequence != 1 {
		t.Fatalf("sensor observation %+v", records[0].Event)
	}
	for i, record := range records[1:] {
		if record.Event.SensorID != f.SensorID || record.Event.Sequence != int64(i+1) {
			t.Fatalf("decoy observation %d %+v", i, record.Event)
		}
	}
	if records[1].Event.Sequence != expected.Sequences[0] {
		t.Fatalf("decoy sequence %d, want %d", records[1].Event.Sequence, expected.Sequences[0])
	}
}

// c12DecoySources returns every Go file of the decoy package. The whole
// package is checked: a second file could hide an aliased import.
func c12DecoySources(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("../internal/decoy")
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		sources = append(sources, filepath.Join("../internal/decoy", entry.Name()))
	}
	if len(sources) == 0 {
		t.Fatal("the decoy package has no source file")
	}
	sort.Strings(sources)
	return sources
}

func TestDecoyNeverExecutesCommandsOrEgresses(t *testing.T) {
	allowedImports := []string{
		"context",
		"crypto/sha256",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"io",
		"net/http",
		"strconv",
		"strings",
		"sync",
		"time",
		"unicode/utf8",
		"github.com/Parsa-Emami/Miragemesh/internal/contracts",
		"github.com/Parsa-Emami/Miragemesh/internal/sensor",
		"github.com/Parsa-Emami/Miragemesh/internal/storage",
	}
	permitted := make(map[string]bool, len(allowedImports))
	for _, path := range allowedImports {
		permitted[path] = true
	}
	// Only the handler API may be named. A client call such as
	// http.DefaultClient.Do names a client identifier and is rejected.
	allowedHTTP := map[string]bool{
		"Handler":                     true,
		"HandlerFunc":                 true,
		"ResponseWriter":              true,
		"Request":                     true,
		"MethodGet":                   true,
		"MethodHead":                  true,
		"MethodPost":                  true,
		"MaxBytesReader":              true,
		"StatusOK":                    true,
		"StatusBadRequest":            true,
		"StatusMethodNotAllowed":      true,
		"StatusRequestEntityTooLarge": true,
		"StatusServiceUnavailable":    true,
	}
	union := make(map[string]bool)
	for _, source := range c12DecoySources(t) {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"os/exec", "exec.Command", "exec.LookPath", "net.Dial", "http.Get", "http.Post", "http.NewRequest", "os.Open", "os.Create", "os.WriteFile", "os.ReadFile"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("%s uses %s", source, forbidden)
			}
		}
		fileset := token.NewFileSet()
		file, err := parser.ParseFile(fileset, source, data, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		// The local name of the net/http import is resolved from the import
		// declaration, so an alias cannot hide a client call. A dot import is
		// rejected because its identifiers cannot be attributed to a package.
		httpName := ""
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !permitted[path] {
				t.Errorf("%s imports %s", source, path)
			}
			union[path] = true
			if path != "net/http" {
				continue
			}
			if spec.Name == nil {
				httpName = "http"
				continue
			}
			if spec.Name.Name == "." {
				t.Fatalf("%s dot-imports net/http", source)
			}
			httpName = spec.Name.Name
		}
		full, err := parser.ParseFile(fileset, source, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(full, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || httpName == "" || pkg.Name != httpName {
				return true
			}
			if !allowedHTTP[selector.Sel.Name] {
				t.Errorf("%s names the net/http identifier %s, which is not a handler API", source, selector.Sel.Name)
			}
			return true
		})
	}
	for _, path := range allowedImports {
		if !union[path] {
			t.Errorf("the decoy package no longer imports %s", path)
		}
	}
	if len(union) != len(allowedImports) {
		t.Errorf("the decoy package imports %v", union)
	}
}
