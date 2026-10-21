package storage

import "os"

// TestFileOps exposes the existing syscall seam only to the external test suite,
// which exercises the real sensor applier without a production fault-control API.
type TestFileOps struct {
	Write  func(*os.File, []byte) (int, error)
	Sync   func(*os.File) error
	Rename func(string, string) error
}

func (s *Store) FileOpsForTest() TestFileOps {
	return TestFileOps{s.ops.write, s.ops.sync, s.ops.rename}
}
func (s *Store) SetFileOpsForTest(ops TestFileOps) { s.ops = fileOps{ops.Write, ops.Sync, ops.Rename} }
