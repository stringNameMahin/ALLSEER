//go:build windows

// Package windows is the root of ALLSEER's Windows telemetry implementation.
//
// Nothing here acquires telemetry yet. The package exists to fix one decision --
// where Windows-specific telemetry code lives -- so that the mechanism research
// and design stages that follow have somewhere to land that is not the
// platform-neutral core.
//
// # The boundary
//
// The contract with the rest of ALLSEER is event.Source, exactly as it is for
// Linux. Windows mechanisms differ from Linux ones all the way down, but what
// they must produce does not: pkg/event.Event values, classified with the same
// pkg/capability.Kind vocabulary, consumed by the same pipeline. Anything that
// would need a second event model or a second pipeline is a design question,
// not something to settle by adding a directory here.
//
// # Why a subpackage per mechanism
//
// Windows telemetry is expected to be mechanism-plural, rather than backed by
// one facility the way bpf/allseer.bpf.c backs Linux today. A subpackage per
// mechanism keeps each one's dependencies to itself, so a mechanism that is
// unavailable on a host -- or simply not written yet -- is a package that
// contributes nothing, rather than a build that fails or a collector that comes
// up half-initialized.
//
// Which mechanisms ALLSEER will actually use is open, and is deliberately not
// answered here. In particular nothing in this tree should be read as deciding
// that Windows eBPF is the primary mechanism.
//
// # What is deliberately absent
//
// There is no collector, no mechanism selection, and no registry. Their
// requirements come from the mechanisms, and no mechanism exists yet; writing
// them now would be guessing at an interface rather than deriving one.
package windows
