// Package containment gives each governed session a dedicated cgroup v2 and
// acts on it as a whole.
//
// The cgroup is the session boundary: every process the agent spawns inherits
// it, its ID is what the kernel probes filter and attribute on, and an
// unprivileged process cannot leave it, because migrating needs write access
// to cgroup.procs of the common ancestor, which is root-owned.
//
// What it can do is freeze, thaw and kill the whole tree atomically. That is
// containment after detection, not prevention: tracepoints report a syscall
// after it completed, so the action that triggered a freeze or kill has
// already happened.
package containment

import (
	"errors"
	"regexp"
)

// Errors reported by the manager.
var (
	ErrUnsupported = errors.New("containment: cgroup v2 containment is not available on this host")
	ErrBadSession  = errors.New("containment: session ID is not a safe cgroup name")
	ErrExists      = errors.New("containment: session cgroup already exists")
	// ErrBaseInUse means another daemon holds the base's lock.
	ErrBaseInUse = errors.New("containment: another daemon is governing this cgroup base")
	// ErrNotLocked means an operation that acts on groups it does not own was
	// attempted without holding the base's lock.
	ErrNotLocked = errors.New("containment: the cgroup base is not locked by this daemon")
)

var sessionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidSessionName reports whether id can name a session cgroup.
func ValidSessionName(id string) bool { return sessionName.MatchString(id) }

// SweepResult reports what a startup sweep found under the base.
type SweepResult struct {
	// Removed names the empty session cgroups that were cleaned up.
	Removed []string `json:"removed"`
	// Populated names the leftover session cgroups that still hold processes.
	// Each one is a tree no session is governing any more.
	Populated []string `json:"populated"`
	// Frozen names the populated leftovers the sweep froze, or found already
	// frozen. A populated name missing here could not be frozen.
	Frozen []string `json:"frozen"`
}

// Capabilities reports which whole-tree operations the host supports.
type Capabilities struct {
	Freeze bool `json:"freeze"`
	Kill   bool `json:"kill"`
}
