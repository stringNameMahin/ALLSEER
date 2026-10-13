package telemetry

import (
	"errors"
	"sort"
	"sync"
)

// ErrProcessTracked is returned when a (PID, StartTime) pair is already owned
// by a different session.
var ErrProcessTracked = errors.New("telemetry: process is already tracked by another session")

// procKey identifies a process for one boot. PID alone is reused; the pair is
// not.
type procKey struct {
	pid   int32
	start uint64
}

type procEntry struct {
	session    string
	depth      int
	executable string
}

// ProcTracker implements ProcessTracker keyed on (PID, StartTime).
//
// Session membership comes from the cgroup, so the tracker never decides which
// session an event belongs to. It answers ancestry: how deep a process sits
// below the session root, and which processes a session currently has.
type ProcTracker struct {
	mu    sync.RWMutex
	procs map[procKey]procEntry
	// live maps a PID to the process currently holding it, so a child's PPID
	// resolves to the right parent even after the number has been recycled.
	live map[int32]procKey
	// roots holds a root PID registered before its start time was known.
	roots map[int32]string
}

var _ ProcessTracker = (*ProcTracker)(nil)

// NewProcTracker returns an empty tracker.
func NewProcTracker() *ProcTracker {
	return &ProcTracker{
		procs: make(map[procKey]procEntry),
		live:  make(map[int32]procKey),
		roots: make(map[int32]string),
	}
}

// TrackRoot registers a session's root PID before its start time is known.
// The first observation of that PID in the session fixes the pair at depth 0.
func (t *ProcTracker) TrackRoot(sessionID string, pid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roots[pid] = sessionID
}

// Track registers a process as a session root (depth 0).
func (t *ProcTracker) Track(sessionID string, pid int32, startTime uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.trackLocked(sessionID, procKey{pid, startTime}, 0)
}

func (t *ProcTracker) trackLocked(sessionID string, k procKey, depth int) error {
	if cur, ok := t.procs[k]; ok {
		if cur.session != sessionID {
			return ErrProcessTracked
		}
		return nil
	}
	t.procs[k] = procEntry{session: sessionID, depth: depth}
	t.live[k.pid] = k
	return nil
}

// Observe records a process seen in a session's event stream and returns its
// depth. An unknown process is placed one level below its parent when the
// parent is tracked in the same session, and at depth 1 otherwise: it is in
// the session's cgroup, so it is not the root.
func (t *ProcTracker) Observe(sessionID string, pid int32, startTime uint64, ppid int32) int {
	k := procKey{pid, startTime}

	t.mu.RLock()
	e, ok := t.procs[k]
	t.mu.RUnlock()
	if ok && e.session == sessionID {
		return e.depth
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.procs[k]; ok && e.session == sessionID {
		return e.depth
	}
	depth := 1
	exe := ""
	if sid, ok := t.roots[pid]; ok && sid == sessionID {
		depth = 0
		delete(t.roots, pid)
	} else if pk, ok := t.live[ppid]; ok {
		if pe, ok := t.procs[pk]; ok && pe.session == sessionID {
			// A forked child runs its parent's image until it execs.
			depth, exe = pe.depth+1, pe.executable
		}
	}
	_ = t.trackLocked(sessionID, k, depth)
	if exe != "" {
		e := t.procs[k]
		e.executable = exe
		t.procs[k] = e
	}
	return depth
}

// SetExecutable records the resolved image of a process after an exec.
func (t *ProcTracker) SetExecutable(pid int32, startTime uint64, exe string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := procKey{pid, startTime}
	if e, ok := t.procs[k]; ok {
		e.executable = exe
		t.procs[k] = e
	}
}

// Executable returns the last image recorded for a process.
func (t *ProcTracker) Executable(pid int32, startTime uint64) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.procs[procKey{pid, startTime}].executable
}

// Untrack removes a process on exit.
func (t *ProcTracker) Untrack(pid int32, startTime uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := procKey{pid, startTime}
	delete(t.procs, k)
	if t.live[pid] == k {
		delete(t.live, pid)
	}
	return nil
}

// SessionFor returns the session owning a process.
func (t *ProcTracker) SessionFor(pid int32, startTime uint64) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.procs[procKey{pid, startTime}]
	return e.session, ok
}

// Descendants returns the PIDs currently tracked for a session, sorted.
func (t *ProcTracker) Descendants(sessionID string) []int32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []int32
	for k, e := range t.procs {
		if e.session == sessionID {
			out = append(out, k.pid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Depth returns a process's generation distance from the session root, or -1
// when the process is not tracked.
func (t *ProcTracker) Depth(pid int32, startTime uint64) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.procs[procKey{pid, startTime}]
	if !ok {
		return -1
	}
	return e.depth
}

// ForgetSession drops every process and pending root of a session.
func (t *ProcTracker) ForgetSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.procs {
		if e.session == sessionID {
			delete(t.procs, k)
			if t.live[k.pid] == k {
				delete(t.live, k.pid)
			}
		}
	}
	for pid, sid := range t.roots {
		if sid == sessionID {
			delete(t.roots, pid)
		}
	}
}
