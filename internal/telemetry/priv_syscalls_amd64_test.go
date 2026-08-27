//go:build linux && ebpf && amd64

package telemetry

// The two syscall numbers the tests need and Go's syscall package does not
// define. Per architecture, because they differ: this file covers x86-64 and
// priv_syscalls_arm64_test.go covers the other target the Makefile builds for.
//
// A constant rather than a runtime lookup, so a third architecture fails to
// compile with a missing identifier rather than skipping the tests at runtime
// and reading as a pass.
const (
	sysSetns   = 308
	sysSeccomp = 317
)
