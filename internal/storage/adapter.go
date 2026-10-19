// Package storage provides bounded local persistence, not collector acceptance.
package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

var (
	ErrLocked       = errors.New("storage locked")
	ErrConflict     = errors.New("storage conflict")
	ErrQuota        = errors.New("storage quota exceeded")
	ErrRecovery     = errors.New("storage recovery required")
	ErrInvalidInput = errors.New("invalid storage input")
	ErrIO           = errors.New("storage I/O failed")
	ErrClosed       = errors.New("storage closed")
	ErrNotFound     = errors.New("storage operation not found")
)

type Limits struct {
	MaxOperations    int   `json:"max_operations"`
	MaxBytes         int64 `json:"max_bytes"`
	MaxManifestBytes int64 `json:"max_manifest_bytes"`
}
type Receipt struct {
	OperationID string `json:"operation_id"`
	InputDigest string `json:"input_digest"`
	Generation  uint64 `json:"generation"`
}
type Record struct {
	Receipt Receipt
	Input   []byte
	Event   contracts.Event
}

type entry struct {
	Receipt Receipt `json:"receipt"`
	Size    int64   `json:"size"`
}
type manifest struct {
	SchemaVersion string  `json:"schema_version"`
	Generation    uint64  `json:"generation"`
	Operations    []entry `json:"operations"`
}

// These are filesystem operations, kept replaceable for syscall-failure tests.
type fileOps struct {
	write  func(*os.File, []byte) (int, error)
	sync   func(*os.File) error
	rename func(string, string) error
}
type Store struct {
	mu       sync.Mutex
	root     *os.Root
	lock     *os.File
	limits   Limits
	state    manifest
	ops      fileOps
	closed   bool
	poisoned bool
}

func validID(id string) bool {
	return utf8.ValidString(id) && utf8.RuneCountInString(id) > 0 && utf8.RuneCountInString(id) <= 128
}
func digest(data []byte) string     { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func objectName(hash string) string { return "object-" + hash + ".json" }
func hexName(text string, n int) bool {
	if len(text) != n {
		return false
	}
	for _, c := range text {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func private(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode() == mode && (info.IsDir() || stat.Nlink == 1)
}
func (s *Store) openFile(name string, flags int) (*os.File, error) {
	f, err := s.root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrIO
	}
	info, err := f.Stat()
	if err != nil || !private(info, 0600) {
		f.Close()
		return nil, ErrRecovery
	}
	return f, nil
}
func (s *Store) readFile(name string, limit int64) ([]byte, error) {
	f, err := s.openFile(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, ErrIO
	}
	if int64(len(data)) > limit {
		return nil, ErrRecovery
	}
	return data, nil
}
func (s *Store) syncDirectory() error {
	f, err := s.root.Open(".")
	if err != nil {
		return ErrIO
	}
	defer f.Close()
	if s.ops.sync(f) != nil {
		return ErrIO
	}
	return nil
}
func (s *Store) names() ([]string, error) {
	f, err := s.root.Open(".")
	if err != nil {
		return nil, ErrIO
	}
	defer f.Close()
	names, err := f.Readdirnames(s.limits.MaxOperations + 5)
	if err != nil && err != io.EOF {
		return nil, ErrIO
	}
	if len(names) > s.limits.MaxOperations+4 {
		return nil, ErrRecovery
	}
	return names, nil
}
func (s *Store) inspect(names []string) error {
	for _, name := range names {
		object := strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && hexName(strings.TrimSuffix(strings.TrimPrefix(name, "object-"), ".json"), 64)
		stage := strings.HasPrefix(name, ".stage-") && hexName(strings.TrimPrefix(name, ".stage-"), 32)
		if name != ".lock" && name != "manifest.json" && !object && !stage {
			return ErrRecovery
		}
		info, err := s.root.Lstat(name)
		if err != nil || !private(info, 0600) {
			return ErrRecovery
		}
		bound := max(s.limits.MaxManifestBytes, int64(contracts.MaxInputBytes))
		if object {
			bound = contracts.MaxInputBytes
		}
		if name == ".lock" {
			bound = 0
		}
		if info.Size() > bound {
			return ErrRecovery
		}
	}
	return nil
}
func Open(directory string, limits Limits) (*Store, error) {
	if limits.MaxOperations <= 0 || limits.MaxOperations > math.MaxInt-5 || limits.MaxBytes <= 0 || limits.MaxBytes == math.MaxInt64 || limits.MaxManifestBytes <= 0 || limits.MaxManifestBytes == math.MaxInt64 {
		return nil, ErrInvalidInput
	}
	absolute, err := filepath.Abs(directory)
	if err != nil || directory == "" {
		return nil, ErrInvalidInput
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Dir(absolute) {
		return nil, ErrRecovery
	}
	if err = os.Mkdir(absolute, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrIO
	}
	info, err := os.Lstat(absolute)
	if err != nil || !private(info, os.ModeDir|0700) {
		return nil, ErrRecovery
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, ErrIO
	}
	s := &Store{root: root, limits: limits}
	s.ops = fileOps{write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }, rename: root.Rename}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	s.lock, err = s.openFile(".lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, ErrIO
	}
	names, err := s.names()
	if err != nil {
		return nil, err
	}
	if err = s.inspect(names); err != nil {
		return nil, err
	}
	_, err = root.Lstat("manifest.json")
	if errors.Is(err, os.ErrNotExist) {
		for _, name := range names {
			if strings.HasPrefix(name, "object-") {
				return nil, ErrRecovery
			}
		}
		s.state = manifest{SchemaVersion: "1", Operations: []entry{}}
		raw, _ := json.Marshal(s.state)
		if int64(len(raw)) > limits.MaxManifestBytes {
			return nil, ErrQuota
		}
		if err = s.publish(context.Background(), raw); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, ErrRecovery
	} else {
		raw, failure := s.readFile("manifest.json", limits.MaxManifestBytes)
		if failure != nil {
			return nil, ErrRecovery
		}
		if json.Unmarshal(raw, &s.state) != nil {
			return nil, ErrRecovery
		}
		canonical, _ := json.Marshal(s.state)
		// Disk manifests are canonical bytes written by this adapter, never user JSON.
		if !bytes.Equal(raw, canonical) || s.state.SchemaVersion != "1" || s.state.Operations == nil || s.state.Generation != uint64(len(s.state.Operations)) || len(s.state.Operations) > limits.MaxOperations {
			return nil, ErrRecovery
		}
	}
	used := int64(0)
	ids := make(map[string]bool)
	references := make(map[string]bool)
	for i, item := range s.state.Operations {
		r := item.Receipt
		if !validID(r.OperationID) || ids[r.OperationID] || !hexName(r.InputDigest, 64) || r.Generation != uint64(i+1) || item.Size < 1 || item.Size > contracts.MaxInputBytes || item.Size > limits.MaxBytes-used {
			return nil, ErrRecovery
		}
		ids[r.OperationID] = true
		used += item.Size
		if _, failure := s.load(context.Background(), item); failure != nil {
			return nil, ErrRecovery
		}
		references[objectName(r.InputDigest)] = true
	}
	// Validate everything before deleting only recognized unreferenced objects/staging.
	names, err = s.names()
	if err != nil {
		return nil, err
	}
	if err = s.inspect(names); err != nil {
		return nil, err
	}
	for _, name := range names {
		if strings.HasPrefix(name, "object-") && !references[name] {
			data, failure := s.readFile(name, contracts.MaxInputBytes)
			if failure != nil || name != objectName(digest(data)) {
				return nil, ErrRecovery
			}
			if _, failure := contracts.DecodeEvent(context.Background(), data); failure != nil {
				return nil, ErrRecovery
			}
		}
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".stage-") || strings.HasPrefix(name, "object-") && !references[name] {
			if root.Remove(name) != nil {
				return nil, ErrIO
			}
		}
	}
	if err = s.syncDirectory(); err != nil {
		return nil, err
	}
	// Reopen also flushes the parent: an interrupted initialization may have
	// created the store directory before its parent entry was made durable.
	f, failure := os.Open(parent)
	if failure != nil {
		return nil, ErrIO
	}
	failure = f.Sync()
	closeFailure := f.Close()
	if failure != nil || closeFailure != nil {
		return nil, ErrIO
	}

	success = true
	return s, nil
}
func (s *Store) staged(data []byte) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", ErrIO
	}
	name := ".stage-" + hex.EncodeToString(random)
	f, err := s.openFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR)
	if err != nil {
		return "", err
	}
	defer f.Close()
	n, err := s.ops.write(f, data)
	if err != nil || n != len(data) {
		return "", ErrIO
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", ErrIO
	}
	copied, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil || !bytes.Equal(copied, data) {
		return "", ErrIO
	}
	if s.ops.sync(f) != nil {
		return "", ErrIO
	}
	if f.Close() != nil {
		return "", ErrIO
	}
	return name, nil
}

func (s *Store) publish(ctx context.Context, raw []byte) error {
	name, err := s.staged(raw)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.ops.rename(name, "manifest.json") != nil {
		return ErrIO
	}
	// Cancellation cannot retract publication; finish the directory flush.
	if s.syncDirectory() != nil {
		return ErrRecovery
	}
	return nil
}
func (s *Store) available(ctx context.Context) error {
	if s.closed {
		return ErrClosed
	}
	if s.poisoned {
		return ErrRecovery
	}
	return ctx.Err()
}
func (s *Store) load(ctx context.Context, item entry) (Record, error) {
	raw, err := s.readFile(objectName(item.Receipt.InputDigest), contracts.MaxInputBytes)
	if err != nil || int64(len(raw)) != item.Size || digest(raw) != item.Receipt.InputDigest {
		return Record{}, ErrRecovery
	}
	event, failure := contracts.DecodeEvent(ctx, raw)
	if failure != nil {
		if ctx.Err() != nil {
			return Record{}, ctx.Err()
		}
		return Record{}, ErrRecovery
	}
	return Record{Receipt: item.Receipt, Input: raw, Event: event}, nil
}
func (s *Store) Read(ctx context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(ctx); err != nil {
		return Record{}, err
	}
	if !validID(id) {
		return Record{}, ErrInvalidInput
	}
	for _, item := range s.state.Operations {
		if item.Receipt.OperationID == id {
			record, err := s.load(ctx, item)
			if errors.Is(err, ErrRecovery) {
				s.poisoned = true
			}
			return record, err
		}
	}
	return Record{}, ErrNotFound
}
func (s *Store) Commit(ctx context.Context, id string, input []byte) (receipt Receipt, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.available(ctx); err != nil {
		return Receipt{}, err
	}
	if !validID(id) {
		return Receipt{}, ErrInvalidInput
	}
	if _, failure := contracts.DecodeEvent(ctx, input); failure != nil {
		if ctx.Err() != nil {
			return Receipt{}, ctx.Err()
		}
		return Receipt{}, ErrInvalidInput
	}
	hash := digest(input)
	used := int64(0)
	for _, item := range s.state.Operations {
		if item.Receipt.OperationID == id {
			if item.Receipt.InputDigest != hash {
				return Receipt{}, ErrConflict
			}
			record, failure := s.load(ctx, item)
			if failure != nil {
				if errors.Is(failure, ErrRecovery) {
					s.poisoned = true
				}
				return Receipt{}, failure
			}
			if !bytes.Equal(input, record.Input) {
				return Receipt{}, ErrConflict
			}
			return item.Receipt, nil
		}
		used += item.Size
	}
	if len(s.state.Operations) >= s.limits.MaxOperations || int64(len(input)) > s.limits.MaxBytes-used {
		return Receipt{}, ErrQuota
	}
	receipt = Receipt{OperationID: id, InputDigest: hash, Generation: s.state.Generation + 1}
	next := manifest{SchemaVersion: "1", Generation: receipt.Generation, Operations: append(append([]entry{}, s.state.Operations...), entry{Receipt: receipt, Size: int64(len(input))})}
	raw, _ := json.Marshal(next)
	if int64(len(raw)) > s.limits.MaxManifestBytes {
		return Receipt{}, ErrQuota
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	// After filesystem work begins, any failure requires reopen before another write.
	defer func() {
		if err != nil {
			s.poisoned = true
			receipt = Receipt{}
		}
	}()
	name, err := s.staged(input)
	if err != nil {
		return Receipt{}, err
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	object := objectName(hash)
	if _, failure := s.root.Lstat(object); failure == nil {
		existing, failure := s.readFile(object, contracts.MaxInputBytes)
		if failure != nil || !bytes.Equal(input, existing) {
			return Receipt{}, ErrRecovery
		}
		if s.root.Remove(name) != nil {
			return Receipt{}, ErrIO
		}
	} else if !errors.Is(failure, os.ErrNotExist) {
		return Receipt{}, ErrIO
	} else if s.ops.rename(name, object) != nil {
		return Receipt{}, ErrIO
	}
	if s.syncDirectory() != nil {
		return Receipt{}, ErrIO
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err = s.publish(ctx, raw); err != nil {
		return Receipt{}, err
	}

	s.state = next
	return receipt, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var failure bool
	if s.lock != nil {
		failure = s.lock.Close() != nil
	}
	if s.root != nil {
		failure = s.root.Close() != nil || failure
	}
	if failure {
		return ErrIO
	}
	return nil
}
