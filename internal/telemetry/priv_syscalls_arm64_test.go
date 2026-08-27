//go:build linux && ebpf && arm64

package telemetry

// The arm64 numbers for the two syscalls Go's syscall package does not define.
// See priv_syscalls_amd64_test.go for why these are per-architecture constants.
const (
	sysSetns   = 268
	sysSeccomp = 277
)
