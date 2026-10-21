package events

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

func recoveryLimits() Limits {
	return Limits{MaxSegments: 8, MaxRecordsPerSegment: 2, MaxBytesPerSegment: contracts.MaxInputBytes + 1}
}

func recoveryEvent(sequence int) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":"1","sensor_id":"sensor-01","event_id":"event-%02d","sequence":%d,"observed_at":"2026-01-01T00:00:%02dZ","kind":"http.request","metadata":{"path":"/crash/%d"}}`, sequence, sequence, sequence%60, sequence))
}

func recoveryAppend(t *testing.T, w *Writer, sequence int) {
	t.Helper()
	if _, err := w.Append(context.Background(), recoveryEvent(sequence)); err != nil {
		t.Fatalf("append sequence %d: %v", sequence, err)
	}
}

func recoveryOpen(t *testing.T, directory string, limits Limits) *Writer {
	t.Helper()
	w, err := Open(directory, limits)
	if err != nil {
		t.Fatalf("open segments: %v", err)
	}
	return w
}

func recoverySegments(t *testing.T, w *Writer) []Segment {
	t.Helper()
	segments, err := w.Segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	return segments
}

func recoveryRecords(segments []Segment) int64 {
	var total int64
	for _, segment := range segments {
		total += segment.Records
	}
	return total
}

func recoveryIncomplete(segments []Segment) *Incomplete {
	for _, segment := range segments {
		if segment.Incomplete != nil {
			incomplete := *segment.Incomplete
			return &incomplete
		}
	}
	return nil
}

func activeSegmentPath(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, segmentPrefix) && strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".sealed.jsonl") && !strings.HasSuffix(name, ".incomplete.jsonl") {
			if found != "" {
				t.Fatalf("multiple active segments: %s and %s", found, name)
			}
			found = filepath.Join(directory, name)
		}
	}
	if found == "" {
		t.Fatal("missing active segment")
	}
	return found
}

func incompleteSegmentPath(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".incomplete.jsonl") {
			if found != "" {
				t.Fatalf("multiple incomplete segments: %s and %s", found, entry.Name())
			}
			found = filepath.Join(directory, entry.Name())
		}
	}
	if found == "" {
		t.Fatal("missing incomplete segment")
	}
	return found
}

func TestSegmentsIncompleteTailKeepsRawBytesAndOffset(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "segments")
	limits := recoveryLimits()
	limits.MaxRecordsPerSegment = 3
	w := recoveryOpen(t, directory, limits)
	recoveryAppend(t, w, 1)
	recoveryAppend(t, w, 2)
	recoveryAppend(t, w, 3)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	active := activeSegmentPath(t, directory)
	raw, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	firstEnd := bytes.IndexByte(raw, '\n') + 1
	secondEnd := firstEnd + bytes.IndexByte(raw[firstEnd:], '\n') + 1
	cut := firstEnd + (secondEnd-firstEnd)/2
	tail := append([]byte(nil), raw[firstEnd:cut]...)
	if err := os.Truncate(active, int64(cut)); err != nil {
		t.Fatal(err)
	}

	w = recoveryOpen(t, directory, limits)
	segments := recoverySegments(t, w)
	if len(segments) != 1 || segments[0].Records != 1 {
		t.Fatalf("segments = %+v, want one record", segments)
	}
	incomplete := segments[0].Incomplete
	if incomplete == nil || incomplete.Offset != int64(firstEnd) || incomplete.Bytes != int64(len(tail)) || incomplete.Digest != digest(tail) {
		t.Fatalf("incomplete = %+v, want offset %d bytes %d digest %s", incomplete, firstEnd, len(tail), digest(tail))
	}
	if got, err := os.ReadFile(incompleteSegmentPath(t, directory)); err != nil || !bytes.Equal(got, raw[:cut]) {
		t.Fatalf("preserved bytes changed: err=%v equal=%v", err, err == nil && bytes.Equal(got, raw[:cut]))
	}
	recoveryAppend(t, w, 4)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w = recoveryOpen(t, directory, limits)
	segments = recoverySegments(t, w)
	if recoveryRecords(segments) != 2 || recoveryIncomplete(segments) == nil {
		t.Fatalf("resume state = %+v", segments)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSegmentsRecoverIncompleteFinalRecord(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "segments")
	limits := recoveryLimits()
	w := recoveryOpen(t, directory, limits)
	recoveryAppend(t, w, 1)
	recoveryAppend(t, w, 2)
	recoveryAppend(t, w, 3)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	active := activeSegmentPath(t, directory)
	raw, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	const cut = 7
	tail := append([]byte(nil), raw[:cut]...)
	if err := os.Truncate(active, cut); err != nil {
		t.Fatal(err)
	}

	w = recoveryOpen(t, directory, limits)
	segments := recoverySegments(t, w)
	if recoveryRecords(segments) != 2 {
		t.Fatalf("valid records = %d, want 2: %+v", recoveryRecords(segments), segments)
	}
	incomplete := recoveryIncomplete(segments)
	if incomplete == nil || incomplete.Offset != 0 || incomplete.Bytes != cut || incomplete.Digest != digest(tail) {
		t.Fatalf("incomplete = %+v, want offset 0 bytes %d digest %s", incomplete, cut, digest(tail))
	}
	recoveryAppend(t, w, 4)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w = recoveryOpen(t, directory, limits)
	segments = recoverySegments(t, w)
	if recoveryRecords(segments) != 3 {
		t.Fatalf("records after resume = %d, want 3", recoveryRecords(segments))
	}
	incomplete = recoveryIncomplete(segments)
	if incomplete == nil || incomplete.Digest != digest(tail) {
		t.Fatalf("incomplete did not survive restart: %+v", incomplete)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSegmentsCrashHelper(t *testing.T) {
	phase := os.Getenv("MIRAGEMESH_C17_CRASH_PHASE")
	if phase == "" {
		return
	}
	directory := os.Getenv("MIRAGEMESH_C17_CRASH_DIR")
	if directory == "" {
		t.Fatal("missing crash directory")
	}
	limits := recoveryLimits()

	stop := func() {
		fmt.Fprintln(os.Stdout, "C17_BOUNDARY")
		_ = os.Stdout.Sync()
		time.Sleep(10 * time.Minute)
	}

	var w *Writer
	var err error
	if phase == "before_incomplete_rename" {
		w, err = openWithOps(directory, limits, func(w *Writer) {
			base := w.ops.rename
			w.ops.rename = func(oldName, newName string) error {
				stop()
				return base(oldName, newName)
			}
		})
	} else {
		w, err = Open(directory, limits)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	switch phase {
	case "before_seal_rename":
		base := w.ops.rename
		w.ops.rename = func(oldName, newName string) error {
			stop()
			return base(oldName, newName)
		}
		recoveryAppend(t, w, 3)
	case "after_seal_rename":
		base := w.ops.rename
		w.ops.rename = func(oldName, newName string) error {
			if err := base(oldName, newName); err != nil {
				return err
			}
			stop()
			return nil
		}
		recoveryAppend(t, w, 3)
	case "after_next_create":
		base := w.ops.create
		w.ops.create = func(name string) (*os.File, error) {
			f, err := base(name)
			if err != nil {
				return nil, err
			}
			stop()
			return f, nil
		}
		recoveryAppend(t, w, 3)
	case "torn_first_record":
		base := w.ops.write
		w.ops.write = func(f *os.File, data []byte) (int, error) {
			n, err := base(f, data[:len(data)/2])
			if err != nil {
				return n, err
			}
			stop()
			return n, nil
		}
		recoveryAppend(t, w, 3)
	case "before_incomplete_rename":
		t.Fatal("unreachable")
	default:
		t.Fatalf("unknown crash phase %q", phase)
	}
}

type crashScan struct {
	found bool
	err   error
}

func runCrashProcess(t *testing.T, phase, directory string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSegmentsCrashHelper$", "-test.v")
	command.Env = append(os.Environ(),
		"MIRAGEMESH_C17_CRASH_PHASE="+phase,
		"MIRAGEMESH_C17_CRASH_DIR="+directory,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	result := make(chan crashScan, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "C17_BOUNDARY" {
				result <- crashScan{found: true}
				return
			}
		}
		result <- crashScan{err: scanner.Err()}
	}()
	select {
	case scan := <-result:
		if !scan.found {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("child did not reach boundary: %v stderr=%s", scan.err, stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("child timed out before boundary: stderr=%s", stderr.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	if err := command.Wait(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("wait child: %v", err)
		}
	}
}

func TestSegmentsSIGKILLAtRotationBoundaries(t *testing.T) {
	phases := []string{"before_seal_rename", "after_seal_rename", "after_next_create", "torn_first_record", "before_incomplete_rename"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "segments")
			limits := recoveryLimits()
			w := recoveryOpen(t, directory, limits)
			recoveryAppend(t, w, 1)
			recoveryAppend(t, w, 2)
			if phase == "before_incomplete_rename" {
				recoveryAppend(t, w, 3)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if phase == "before_incomplete_rename" {
				active := activeSegmentPath(t, directory)
				if err := os.Truncate(active, 7); err != nil {
					t.Fatal(err)
				}
			}

			runCrashProcess(t, phase, directory)

			w = recoveryOpen(t, directory, limits)
			segments := recoverySegments(t, w)
			if got := recoveryRecords(segments); got != 2 {
				t.Fatalf("records after crash = %d, want 2: %+v", got, segments)
			}
			incomplete := recoveryIncomplete(segments)
			expectIncomplete := phase == "torn_first_record" || phase == "before_incomplete_rename"
			if expectIncomplete != (incomplete != nil) {
				t.Fatalf("incomplete = %+v, want present=%v: %+v", incomplete, expectIncomplete, segments)
			}
			if incomplete != nil && (incomplete.Bytes <= 0 || incomplete.Digest == "") {
				t.Fatalf("incomplete metadata is not explicit: %+v", incomplete)
			}
			recoveryAppend(t, w, 4)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			w = recoveryOpen(t, directory, limits)
			segments = recoverySegments(t, w)
			if got := recoveryRecords(segments); got != 3 {
				t.Fatalf("records after resume = %d, want 3: %+v", got, segments)
			}
			incomplete = recoveryIncomplete(segments)
			if expectIncomplete != (incomplete != nil) {
				t.Fatalf("incomplete marker changed after restart: %+v", segments)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSegmentsSyscallFailuresPreserveRecoverableState(t *testing.T) {
	rotate := recoveryLimits()
	rotate.MaxRecordsPerSegment = 1
	appendOnly := recoveryLimits()
	appendOnly.MaxRecordsPerSegment = 100

	type failureCase struct {
		name           string
		limits         Limits
		configure      func(*Writer)
		wantRecords    int64
		wantIncomplete bool
	}
	cases := []failureCase{
		{
			name:   "create",
			limits: rotate,
			configure: func(w *Writer) {
				w.ops.create = func(string) (*os.File, error) {
					return nil, errors.New("injected create failure")
				}
			},
			wantRecords: 1,
		},
		{
			name:   "rename",
			limits: rotate,
			configure: func(w *Writer) {
				w.ops.rename = func(string, string) error {
					return errors.New("injected rename failure")
				}
			},
			wantRecords: 1,
		},
		{
			name:   "directory_sync",
			limits: rotate,
			configure: func(w *Writer) {
				base := w.ops.sync
				w.ops.sync = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if info.IsDir() {
						return errors.New("injected directory sync failure")
					}
					return base(f)
				}
			},
			wantRecords: 1,
		},
		{
			name:   "write_error",
			limits: appendOnly,
			configure: func(w *Writer) {
				w.ops.write = func(*os.File, []byte) (int, error) {
					return 0, errors.New("injected write failure")
				}
			},
			wantRecords: 1,
		},
		{
			name:   "short_write",
			limits: appendOnly,
			configure: func(w *Writer) {
				base := w.ops.write
				w.ops.write = func(f *os.File, data []byte) (int, error) {
					return base(f, data[:len(data)/2])
				}
			},
			wantRecords:    1,
			wantIncomplete: true,
		},
		{
			name:   "file_sync",
			limits: appendOnly,
			configure: func(w *Writer) {
				base := w.ops.sync
				w.ops.sync = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if !info.IsDir() {
						return errors.New("injected file sync failure")
					}
					return base(f)
				}
			},
			wantRecords: 2,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "segments")
			w := recoveryOpen(t, directory, testCase.limits)
			recoveryAppend(t, w, 1)
			testCase.configure(w)
			if _, err := w.Append(context.Background(), recoveryEvent(2)); !errors.Is(err, ErrIO) {
				t.Fatalf("append after injected failure = %v, want I/O failure", err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			w = recoveryOpen(t, directory, testCase.limits)
			segments := recoverySegments(t, w)
			if got := recoveryRecords(segments); got != testCase.wantRecords {
				t.Fatalf("records after recovery = %d, want %d: %+v", got, testCase.wantRecords, segments)
			}
			incomplete := recoveryIncomplete(segments)
			if testCase.wantIncomplete != (incomplete != nil) {
				t.Fatalf("incomplete = %+v, want present=%v", incomplete, testCase.wantIncomplete)
			}
			recoveryAppend(t, w, 3)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			w = recoveryOpen(t, directory, testCase.limits)
			segments = recoverySegments(t, w)
			if got := recoveryRecords(segments); got != testCase.wantRecords+1 {
				t.Fatalf("records after resume = %d, want %d: %+v", got, testCase.wantRecords+1, segments)
			}
			if testCase.wantIncomplete != (recoveryIncomplete(segments) != nil) {
				t.Fatalf("incomplete marker changed after resume: %+v", segments)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
