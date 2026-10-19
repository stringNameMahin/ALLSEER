//go:build linux

package containment

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const settleTimeout = 5 * time.Second

// Manager creates session cgroups under one root-owned base directory.
type Manager struct {
	base string
}

// NewManager returns a manager rooted at base, creating it if needed. An empty
// base uses "allseer" under the cgroup2 mount.
func NewManager(base string) (*Manager, error) {
	if base == "" {
		mnt, err := cgroup2Mount()
		if err != nil {
			return nil, err
		}
		base = filepath.Join(mnt, "allseer")
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("containment: creating %s: %w", base, err)
	}
	return &Manager{base: base}, nil
}

// Base returns the directory session cgroups are created in.
func (m *Manager) Base() string { return m.base }

// Capabilities probes the base for cgroup.freeze and cgroup.kill.
func (m *Manager) Capabilities() Capabilities {
	probe, err := os.MkdirTemp(m.base, ".probe-")
	if err != nil {
		return Capabilities{}
	}
	defer os.Remove(probe)
	_, ferr := os.Stat(filepath.Join(probe, "cgroup.freeze"))
	_, kerr := os.Stat(filepath.Join(probe, "cgroup.kill"))
	return Capabilities{Freeze: ferr == nil, Kill: kerr == nil}
}

// Sweep removes the empty session cgroups left under the base and reports the
// ones that still hold processes.
//
// A leftover group means a daemon exited without finishing its sessions. The
// empty ones are pure garbage. The populated ones are not killed here: the
// base can be shared with another running daemon, and killing a live session
// that belongs to somebody else would be worse than reporting it.
func (m *Manager) Sweep() (SweepResult, error) {
	var out SweepResult
	groups, err := m.List()
	if err != nil {
		return out, err
	}
	for _, g := range groups {
		pop, err := g.Populated()
		if err != nil || pop {
			out.Populated = append(out.Populated, g.Session)
			continue
		}
		if err := g.Remove(); err != nil {
			out.Populated = append(out.Populated, g.Session)
			continue
		}
		out.Removed = append(out.Removed, g.Session)
	}
	return out, nil
}

// List returns the session cgroups that currently exist under the base.
func (m *Manager) List() ([]*Group, error) {
	entries, err := os.ReadDir(m.base)
	if err != nil {
		return nil, fmt.Errorf("containment: reading %s: %w", m.base, err)
	}
	var out []*Group
	for _, e := range entries {
		if !e.IsDir() || !ValidSessionName(e.Name()) {
			continue
		}
		g, err := m.Open(e.Name())
		if err != nil {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

// Governed reports whether pid sits inside a session cgroup under this base,
// and the session whose cgroup holds it. The session is "" for a process in
// the base itself.
//
// An unreadable or vanished process is an error, never a false. A caller the
// daemon cannot place must not be treated as ungoverned.
func (m *Manager) Governed(pid int) (string, bool, error) {
	rel, err := procCgroup(pid)
	if err != nil {
		return "", false, err
	}
	mnt, err := cgroup2Mount()
	if err != nil {
		return "", false, err
	}
	base := filepath.Clean(m.base)
	p := filepath.Join(mnt, rel)
	if p == base {
		return "", true, nil
	}
	rest, ok := strings.CutPrefix(p, base+string(filepath.Separator))
	if !ok {
		return "", false, nil
	}
	sid, _, _ := strings.Cut(rest, string(filepath.Separator))
	return sid, true, nil
}

// procCgroup returns pid's cgroup v2 path, relative to the cgroup2 mount.
func procCgroup(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		// The unified hierarchy is the line with no controller name.
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("containment: pid %d has no cgroup2 entry", pid)
}

// Group is one session's cgroup.
type Group struct {
	Session string `json:"session"`
	Path    string `json:"path"`
	ID      uint64 `json:"id"`
}

// Create makes the session's cgroup. It fails if one already exists, so two
// sessions can never share a cgroup.
func (m *Manager) Create(sessionID string) (*Group, error) {
	if !ValidSessionName(sessionID) {
		return nil, fmt.Errorf("%w: %q", ErrBadSession, sessionID)
	}
	p := filepath.Join(m.base, sessionID)
	if err := os.Mkdir(p, 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrExists, p)
		}
		return nil, fmt.Errorf("containment: creating %s: %w", p, err)
	}
	id, err := inode(p)
	if err != nil {
		_ = os.Remove(p)
		return nil, err
	}
	return &Group{Session: sessionID, Path: p, ID: id}, nil
}

// Open returns the existing cgroup of a session.
func (m *Manager) Open(sessionID string) (*Group, error) {
	if !ValidSessionName(sessionID) {
		return nil, fmt.Errorf("%w: %q", ErrBadSession, sessionID)
	}
	p := filepath.Join(m.base, sessionID)
	id, err := inode(p)
	if err != nil {
		return nil, err
	}
	return &Group{Session: sessionID, Path: p, ID: id}, nil
}

// Adopt moves a process into the group. Its future children are born inside.
func (g *Group) Adopt(pid int) error {
	return g.write("cgroup.procs", strconv.Itoa(pid))
}

// Pids lists the processes in the group.
func (g *Group) Pids() ([]int, error) {
	b, err := os.ReadFile(filepath.Join(g.Path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// Freeze stops every process in the group and waits until the kernel reports
// the group frozen.
func (g *Group) Freeze(ctx context.Context) error {
	if err := g.write("cgroup.freeze", "1"); err != nil {
		return err
	}
	return g.waitEvent(ctx, "frozen", "1")
}

// Thaw resumes a frozen group.
func (g *Group) Thaw(ctx context.Context) error {
	if err := g.write("cgroup.freeze", "0"); err != nil {
		return err
	}
	return g.waitEvent(ctx, "frozen", "0")
}

// Frozen reports whether the group is frozen.
func (g *Group) Frozen() (bool, error) {
	v, err := g.event("frozen")
	return v == "1", err
}

// Kill sends SIGKILL to every process in the group, including ones forked
// while the kill is in progress, and waits until the group is empty.
func (g *Group) Kill(ctx context.Context) error {
	if err := g.write("cgroup.kill", "1"); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		// Pre-5.14 kernel: freeze so nothing can fork, signal, then thaw so the
		// signals are delivered.
		_ = g.Freeze(ctx)
		pids, _ := g.Pids()
		for _, p := range pids {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
		_ = g.Thaw(ctx)
	}
	return g.WaitEmpty(ctx)
}

// Populated reports whether any process is in the group.
func (g *Group) Populated() (bool, error) {
	v, err := g.event("populated")
	return v == "1", err
}

// WaitEmpty waits until no process is left in the group.
func (g *Group) WaitEmpty(ctx context.Context) error {
	return g.waitEvent(ctx, "populated", "0")
}

// Remove deletes the group. It must be empty.
func (g *Group) Remove() error {
	if err := os.Remove(g.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("containment: removing %s: %w", g.Path, err)
	}
	return nil
}

func (g *Group) write(file, value string) error {
	f, err := os.OpenFile(filepath.Join(g.Path, file), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("containment: %s: %w", file, err)
	}
	defer f.Close()
	if _, err := f.WriteString(value); err != nil {
		return fmt.Errorf("containment: writing %q to %s: %w", value, file, err)
	}
	return nil
}

func (g *Group) event(key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(g.Path, "cgroup.events"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, key+" "); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("containment: cgroup.events has no %q", key)
}

func (g *Group) waitEvent(ctx context.Context, key, want string) error {
	ctx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()
	for {
		v, err := g.event(key)
		if err != nil {
			return err
		}
		if v == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("containment: %s did not reach %s=%s: %w", g.Path, key, want, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func inode(p string) (uint64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, fmt.Errorf("containment: stat %s: %w", p, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("containment: stat %s: no inode", p)
	}
	return st.Ino, nil
}

func cgroup2Mount() (string, error) {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "cgroup2" {
			return f[1], nil
		}
	}
	return "", ErrUnsupported
}
