//go:build linux

package telemetry

import (
	"errors"
	"os"
	"syscall"
)

// Open flags, from the build target's own values: O_NOFOLLOW differs between
// amd64 and arm64.
const (
	oCreat    = syscall.O_CREAT
	oExcl     = syscall.O_EXCL
	oNofollow = syscall.O_NOFOLLOW
)

func inodeOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no inode")
	}
	return st.Ino, nil
}
