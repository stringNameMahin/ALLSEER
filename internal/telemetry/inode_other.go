//go:build !linux

package telemetry

import "errors"

func inodeOf(string) (uint64, error) { return 0, errors.New("inodes are only read on Linux") }

// Bits no record carries off Linux, so the exactness rules never fire there.
const (
	oCreat    = 1 << 28
	oExcl     = 1 << 29
	oNofollow = 1 << 30
)
