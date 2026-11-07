package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type privateDirectory struct {
	path string
	root *os.Root
	lock *os.File
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func owned(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode() == mode && (info.IsDir() || stat.Nlink == 1)
}

func openPrivateDirectory(path string) (*privateDirectory, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("state directory must be a clean absolute path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("state parent must exist without symbolic links")
	}
	if err := os.Mkdir(path, 0700); err == nil {
		p, err := os.Open(parent)
		if err != nil {
			return nil, err
		}
		if err := errors.Join(p.Sync(), p.Close()); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !owned(info, os.ModeDir|0700) {
		return nil, errors.New("state directory must be owned by the service account with mode 0700")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	dir := &privateDirectory{path: path, root: root}
	if dir.lock, err = root.OpenFile(".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600); err != nil {
		root.Close()
		return nil, err
	}
	lockInfo, err := dir.lock.Stat()
	if err != nil || !owned(lockInfo, 0600) {
		dir.close()
		return nil, errors.New("unsafe state lock")
	}
	if err := syscall.Flock(int(dir.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		dir.close()
		return nil, fmt.Errorf("state directory lock: %w", err)
	}
	return dir, nil
}

func (d *privateDirectory) close() error {
	return errors.Join(d.lock.Close(), d.root.Close())
}

func (d *privateDirectory) sync() error {
	return d.syncAt(".")
}

func (d *privateDirectory) syncAt(name string) error {
	f, err := d.root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func (d *privateDirectory) read(name string, limit int64) ([]byte, error) {
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !owned(info, 0600) {
		return nil, errors.New("unsafe state file")
	}
	return readLimit(f, limit)
}

func (d *privateDirectory) replace(name string, data []byte) error {
	stage := ".stage"
	f, err := d.root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer d.root.Remove(stage)
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		f.Close()
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := d.root.Rename(stage, name); err != nil {
		return err
	}
	return d.sync()
}

func readLimit(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("input limit exceeded")
	}
	return b, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
