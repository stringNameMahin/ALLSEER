//go:build windows

// Package ebpf will acquire Windows telemetry through eBPF for Windows.
//
// Empty by design, and reserved rather than committed to.
//
// eBPF for Windows is a separate runtime from Linux eBPF: a different loader, a
// much smaller and differently shaped set of hooks, and its own installation
// and driver-signing requirements. It therefore cannot reuse the libbpfgo
// loader in internal/telemetry, and is kept apart from it here rather than
// sharing a package with code that would never run on this platform.
//
// Whether ALLSEER uses it at all, and for which capabilities, is open. The
// package reserves a location; it is not a decision.
package ebpf
