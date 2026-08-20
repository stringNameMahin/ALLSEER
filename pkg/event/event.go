// Package event defines the canonical representation of a kernel-observed
// action.
//
// Events originate in eBPF programs as fixed-size C structs, cross into user
// space through a ring buffer, and are decoded into the types here. Everything
// downstream consumes this type and nothing else, which means the eBPF layer
// can be rewritten, replaced, or swapped for a replay source without any other
// module noticing.
//
// Three constraints shaped the type:
//
//  1. The kernel side must stay cheap. Probes emit small flat records with
//     minimal string work; enrichment happens in user space where it is safe to
//     be slow.
//  2. Events are immutable once decoded. Enrichment produces a new value rather
//     than mutating in place, so a stage that panics cannot corrupt the record.
//  3. Every event must be independently interpretable. Correlation IDs ride on
//     the event itself, so an audit log line needs no external state to be
//     understood months later.
package event

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// Event is a single kernel-observed action attributed to a governed process.
//
// Field grouping follows the enrichment pipeline: raw kernel fields first, then
// process identity, then domain-specific payload, then user-space enrichment.
type Event struct {
	// --- Identity -----------------------------------------------------------

	// ID is assigned in user space on decode.
	ID string `json:"id"`

	// SessionID ties the event to the governed session, and so to the ECE it is
	// validated against.
	SessionID string `json:"session_id"`

	// Sequence is a monotonic per-session counter assigned at decode time. It
	// gives a total order when timestamps collide, and a gap in it is direct
	// evidence of ring buffer loss.
	Sequence uint64 `json:"sequence"`

	// --- Time ---------------------------------------------------------------

	// KernelTimestamp is the raw ktime from the probe: monotonic nanoseconds
	// since boot. Authoritative for ordering.
	KernelTimestamp uint64 `json:"kernel_timestamp"`

	// WallClock is KernelTimestamp translated using the measured boot time.
	// Convenient for humans but subject to clock adjustment, so never order
	// events by it.
	WallClock time.Time `json:"wall_clock"`

	// --- Classification -----------------------------------------------------

	// Capability is what the validator matches against the ECE.
	Capability capability.Kind `json:"capability"`

	// Domain mirrors the capability's domain, denormalized for cheap filtering.
	Domain capability.Domain `json:"domain"`

	// Syscall is the kernel entry point, e.g. "openat2". Kept for forensics and
	// probe debugging; matching uses Capability.
	Syscall string `json:"syscall,omitempty"`

	// Result is the syscall return. A failed action is still a governance
	// signal: an agent repeatedly failing to open /etc/shadow is more alarming
	// than one that succeeds once.
	Result Result `json:"result"`

	// --- Actor --------------------------------------------------------------

	Process Process `json:"process"`

	// --- Payload ------------------------------------------------------------
	// Exactly one payload is populated, selected by Domain. Pointers keep the
	// struct small and make "not applicable" distinct from "zero value".

	File    *FilePayload    `json:"file,omitempty"`
	Network *NetworkPayload `json:"network,omitempty"`
	Exec    *ExecPayload    `json:"exec,omitempty"`
	Privil  *PrivPayload    `json:"privilege,omitempty"`

	// --- Enrichment ---------------------------------------------------------

	// Observation is the normalized, selector-matchable form produced by the
	// resolver. The validator uses this rather than reaching into payload
	// structs, which is what keeps it payload-agnostic.
	Observation capability.Observation `json:"observation"`

	// Dropped reports ring buffer records lost before this one. Non-zero means
	// the stream has a hole, and any "the agent never did X" conclusion drawn
	// across that hole is unsound. Policy may treat loss as fail-closed.
	Dropped uint64 `json:"dropped,omitempty"`
}

// Result captures how the kernel answered the syscall.
type Result struct {
	// ReturnCode is the raw syscall return. Negative values are -errno.
	ReturnCode int64 `json:"return_code"`

	// Errno is the symbolic error name when ReturnCode indicates failure.
	Errno string `json:"errno,omitempty"`

	Succeeded bool `json:"succeeded"`
}

// Process identifies the actor. Captured in the kernel at event time, because
// reading /proc afterwards races with process exit and yields nothing for
// short-lived processes, which are exactly the ones worth watching.
type Process struct {
	PID  int32 `json:"pid"`
	TID  int32 `json:"tid"`
	PPID int32 `json:"ppid"`

	UID int32 `json:"uid"`
	GID int32 `json:"gid"`

	// Comm is the kernel's 16-byte truncated process name. Cheap but lossy.
	Comm string `json:"comm"`

	// Executable is the full resolved binary path, enriched in user space.
	Executable string `json:"executable,omitempty"`

	// CgroupID is the primary attribution key: PIDs are reused, cgroup IDs
	// within a boot are not.
	CgroupID uint64 `json:"cgroup_id,omitempty"`

	// StartTime disambiguates recycled PIDs. The pair (PID, StartTime) is
	// unique for a boot; PID alone is not.
	StartTime uint64 `json:"start_time,omitempty"`

	// AncestryDepth is how many process generations separate this process from
	// the session's supervised root. Depth is a governance signal on its own:
	// an agent shelling out three levels deep to reach the network behaves
	// differently from one that connects directly.
	AncestryDepth int `json:"ancestry_depth,omitempty"`
}

// FilePayload carries filesystem event detail.
type FilePayload struct {
	// Path as passed to the syscall. May be relative, may contain symlinks.
	Path string `json:"path"`

	// ResolvedPath is the absolute, symlink-resolved path. Selector matching
	// must use this field; matching on Path allows a trivial symlink escape
	// from any granted directory.
	ResolvedPath string `json:"resolved_path,omitempty"`

	Flags int32  `json:"flags,omitempty"`
	Mode  uint32 `json:"mode,omitempty"`

	// Inode and Device identify the file independent of its name, which is how
	// rename-and-swap tricks are detected.
	Inode  uint64 `json:"inode,omitempty"`
	Device uint64 `json:"device,omitempty"`

	// NewPath is the destination for rename and link operations.
	NewPath string `json:"new_path,omitempty"`

	// BytesTransferred supports volume-based signals such as bulk exfiltration.
	BytesTransferred int64 `json:"bytes_transferred,omitempty"`
}

// NetworkPayload carries network event detail.
type NetworkPayload struct {
	Protocol string `json:"protocol"`

	SourceAddr string `json:"source_addr,omitempty"`
	SourcePort int    `json:"source_port,omitempty"`
	DestAddr   string `json:"dest_addr,omitempty"`
	DestPort   int    `json:"dest_port,omitempty"`

	AddressFamily string `json:"address_family,omitempty"`
	SocketType    string `json:"socket_type,omitempty"`

	// Hostname is the name the destination IP was reached by, recovered in user
	// space by correlating against observed DNS answers. Best-effort: a grant
	// for "api.github.com" only matches if correlation succeeded, so a failure
	// here must widen scrutiny rather than silently allow.
	Hostname string `json:"hostname,omitempty"`

	BytesSent     int64 `json:"bytes_sent,omitempty"`
	BytesReceived int64 `json:"bytes_received,omitempty"`
}

// ExecPayload carries process execution detail.
type ExecPayload struct {
	Filename string   `json:"filename"`
	Argv     []string `json:"argv,omitempty"`

	// EnvKeys lists environment variable names only. Values are never
	// captured: they routinely hold credentials, and an audit log is the last
	// place those should land.
	EnvKeys []string `json:"env_keys,omitempty"`

	// Interpreter is set when the binary is a script runner (sh, python, node),
	// since the meaningful action is the script, not the interpreter.
	Interpreter string `json:"interpreter,omitempty"`

	// BinaryHash is the SHA-256 of the executed file, computed lazily in user
	// space. Expensive, so it is gated by configuration.
	BinaryHash string `json:"binary_hash,omitempty"`
}

// PrivPayload carries privilege and credential change detail.
type PrivPayload struct {
	Operation string `json:"operation"`

	OldUID int32 `json:"old_uid,omitempty"`
	NewUID int32 `json:"new_uid,omitempty"`

	// CapabilitiesAdded lists Linux capabilities gained, e.g. "CAP_SYS_ADMIN".
	CapabilitiesAdded []string `json:"capabilities_added,omitempty"`

	NamespaceType string `json:"namespace_type,omitempty"`
}

// Source produces events for the pipeline.
//
// The interface is narrow so the eBPF collector, a replay reader, and a
// synthetic generator are freely interchangeable. Nothing downstream should be
// able to tell which one it is attached to.
type Source interface {
	// Events returns the stream. The channel closes when the source is
	// exhausted or Close is called. Implementations must not block the kernel
	// ring buffer reader on a slow consumer; buffer and count drops instead,
	// reporting them via Stats and the Dropped field.
	Events() <-chan Event

	// Start begins collection. Returns an error if probes cannot be attached.
	Start(ctx context.Context) error

	// Close detaches probes and releases resources. Safe to call more than once.
	Close() error

	// Stats reports collection health. Rising DroppedEvents is a correctness
	// problem, not a performance one.
	Stats() SourceStats
}

// SourceStats reports the health of an event source.
type SourceStats struct {
	EventsReceived  uint64        `json:"events_received"`
	DroppedEvents   uint64        `json:"dropped_events"`
	DecodeErrors    uint64        `json:"decode_errors"`
	RingBufferUsage float64       `json:"ring_buffer_usage"`
	Uptime          time.Duration `json:"uptime"`
}

// Resolver turns a decoded event into a matchable Observation.
//
// This is where the raw kernel world meets the capability vocabulary: path
// resolution, IP-to-hostname correlation, interpreter unwrapping. Isolating it
// behind an interface keeps that platform-specific logic out of the validator.
type Resolver interface {
	Resolve(ctx context.Context, e *Event) (capability.Observation, error)
}

// Filter decides whether an event is worth carrying further.
//
// Filters run early to shed volume that would otherwise dominate the pipeline,
// such as an agent's editor reading its own config. A filter is a performance
// tool and must not be used to suppress security-relevant events: anything
// dropped here is invisible to validation, which is the same as deciding it was
// allowed.
type Filter interface {
	Allow(e *Event) bool
}

// Done: the Go view of the C struct layout is generated, by
// internal/telemetry/abigen into internal/telemetry/abi, so kernel and user
// space cannot drift without a test failing. It stops at the ABI shape and
// produces no Event; turning a decoded record into this type is
// telemetry.Decoder's job, which is where the capability catalog lives.
// TODO(event): decide the boot-time offset strategy for WallClock. Sampling
// once at startup drifts under suspend; re-sampling periodically is more work.
// TODO(event): specify backpressure policy. Leaning toward a bounded channel
// with newest-wins and an explicit drop counter, since stalling the ring buffer
// reader loses events anyway, just without counting them.
