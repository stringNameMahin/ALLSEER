package telemetry

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

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Path resolution (ABI v3).
//
// The kernel decides the directory; user space follows symlinks below it.
//
//   - An absolute path is walked from the host root. The record's directory is
//     ignored for it.
//   - A relative path is joined to the directory openat_enter captured from the
//     kernel (the cwd for AT_FDCWD, otherwise the dirfd's file), and only when
//     that walk reached the namespace root. Truncated, unavailable or deleted
//     directories leave the path unresolved.
//   - A path the kernel flagged as truncated or unreadable is never resolved.
//   - The walk follows symlinks and ".." the way the kernel does, and rewrites
//     /proc/self to the actor.
//   - For a successful open the record carries the opened file's inode. The
//     resolved path must still name that inode; if it does not, or a component
//     no longer exists, the path changed after the syscall and is left
//     unresolved. A failed open opened nothing, so a missing tail is appended
//     lexically, except a tail containing "..", which is ambiguous.
//
// What remains: symlinks are still read after the syscall, so a failed open
// through a symlink that is swapped before enrichment reports the new target;
// and absolute paths are resolved in the daemon's mount namespace, not a chroot
// or a different namespace of the actor.

// ErrUnresolvable means enrichment could not establish a resolved path.
var ErrUnresolvable = errors.New("telemetry: path cannot be resolved")

const maxSymlinkHops = 40

// PathEnricher fills FilePayload.ResolvedPath.
type PathEnricher struct {
	// HostRoot is prefixed to every lookup. Empty means "/". Tests point it at
	// a temporary tree.
	HostRoot string
}

var _ Enricher = (*PathEnricher)(nil)

// Name identifies the enricher.
func (*PathEnricher) Name() string { return "path" }

// Enrich resolves the event's file path in place. On error it leaves the event
// as it found it.
func (p *PathEnricher) Enrich(_ context.Context, e *event.Event) error {
	if e == nil || e.File == nil || e.File.ResolvedPath != "" {
		return nil
	}
	f := e.File
	switch {
	case f.Truncated:
		return fmt.Errorf("%w: the kernel reported the path as truncated or unreadable", ErrUnresolvable)
	case f.Path == "":
		return fmt.Errorf("%w: the record carries no path", ErrUnresolvable)
	}

	full := f.Path
	if !filepath.IsAbs(full) {
		if f.DirStatus != "complete" || !filepath.IsAbs(f.Dir) {
			status := f.DirStatus
			if status == "" {
				status = "not captured"
			}
			return fmt.Errorf("%w: relative path %q: base directory (%s) is %s", ErrUnresolvable, f.Path, f.DirSource, status)
		}
		full = f.Dir + "/" + f.Path
	}

	// The kernel's directory is canonical, and these flags make it refuse a
	// symlink as the final component, so one name inside it is exact without
	// any lookup, even if both have since been removed.
	if !filepath.IsAbs(f.Path) && !strings.Contains(f.Path, "/") && noFinalSymlink(f.Flags) {
		f.ResolvedPath = filepath.Clean(full)
		return nil
	}

	w, err := p.walk(full, e.Process.PID, e.Process.TID)
	if err != nil {
		return err
	}
	opened := e.Result.Succeeded && e.Result.ReturnCode >= 0 && isOpenKind(e.Capability)

	if len(w.missing) > 0 {
		for _, c := range w.missing {
			if c == ".." {
				return fmt.Errorf("%w: %q: \"..\" after a component that no longer exists is ambiguous", ErrUnresolvable, full)
			}
		}
		if opened && !finalNameIsExact(f.Flags, w, e.Process.PID) {
			return fmt.Errorf("%w: %q no longer exists; the path changed after the open", ErrUnresolvable, full)
		}
	} else if opened && f.Inode != 0 {
		ino, err := p.inode(w.path)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrUnresolvable, w.path, err)
		}
		if ino != f.Inode {
			return fmt.Errorf("%w: %s is inode %d but the open returned inode %d; the path changed after the open",
				ErrUnresolvable, w.path, ino, f.Inode)
		}
	}
	f.ResolvedPath = w.resolved()
	return nil
}

func (p *PathEnricher) inode(path string) (uint64, error) { return inodeOf(p.host(path)) }

// procLinks are /proc/<pid> entries that are or contain magic links, which
// resolve somewhere else entirely and so cannot be named lexically.
var procLinks = map[string]bool{"root": true, "cwd": true, "exe": true, "fd": true, "task": true, "ns": true, "map_files": true}

// finalNameIsExact reports whether a successful open whose last component no
// longer exists still named exactly that component when it ran:
//
//   - O_NOFOLLOW or O_CREAT|O_EXCL made the kernel refuse a symlink there, and
//     every earlier component still exists;
//   - /proc/<pid>/<entry> of the actor itself, which procfs resolved to the
//     actor and which disappeared when it exited, unless the entry is a magic
//     link.
func noFinalSymlink(flags int32) bool {
	return flags&oNofollow != 0 || flags&(oCreat|oExcl) == oCreat|oExcl
}

func finalNameIsExact(flags int32, w walkResult, pid int32) bool {
	if len(w.missing) == 1 && noFinalSymlink(flags) {
		return true
	}
	if pid <= 0 {
		return false
	}
	self := strconv.Itoa(int(pid))
	switch {
	case w.path == "/proc" && len(w.missing) == 2 && w.missing[0] == self:
		// The actor exited, taking /proc/<pid> with it.
		return !procLinks[w.missing[1]]
	case w.path == "/proc/"+self && len(w.missing) == 1:
		return !procLinks[w.missing[0]]
	}
	return false
}

// walkResult is a path resolved as far as the filesystem allows: path exists,
// and missing are the components after the first one that does not.
type walkResult struct {
	path    string
	missing []string
}

func (w walkResult) resolved() string {
	if len(w.missing) == 0 {
		return w.path
	}
	return filepath.Clean(filepath.Join(append([]string{w.path}, w.missing...)...))
}

// Resolve follows an absolute path to the file it names, as seen from the
// host root. A missing component ends the walk and the remainder is appended
// lexically, since a name that does not exist cannot be a symlink.
func (p *PathEnricher) Resolve(path string, pid, tid int32) (string, error) {
	w, err := p.walk(path, pid, tid)
	if err != nil {
		return "", err
	}
	return w.resolved(), nil
}

func (p *PathEnricher) walk(path string, pid, tid int32) (walkResult, error) {
	if !filepath.IsAbs(path) {
		return walkResult{}, fmt.Errorf("%w: %q is not absolute", ErrUnresolvable, path)
	}
	resolved := "/"
	rest := components(path)
	hops := 0

	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}

		next := rewriteSelf(filepath.Join(resolved, c), pid, tid)
		fi, err := os.Lstat(p.host(next))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				// next, not c: /proc/self has already been rewritten.
				missing := []string{filepath.Base(next)}
				for _, m := range rest {
					if m != "" && m != "." {
						missing = append(missing, m)
					}
				}
				return walkResult{path: filepath.Dir(next), missing: missing}, nil
			}
			return walkResult{}, fmt.Errorf("%w: %s: %v", ErrUnresolvable, next, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return walkResult{}, fmt.Errorf("%w: too many symlinks in %q", ErrUnresolvable, path)
		}
		target, err := os.Readlink(p.host(next))
		if err != nil {
			return walkResult{}, fmt.Errorf("%w: readlink %s: %v", ErrUnresolvable, next, err)
		}
		if !filepath.IsAbs(target) {
			if strings.Contains(target, ":[") {
				// A /proc fd link to a socket, pipe or anon inode. The proc path
				// is the most specific name there is.
				resolved = next
				continue
			}
			rest = append(components(target), rest...)
			continue
		}
		resolved = "/"
		rest = append(components(target), rest...)
	}
	return walkResult{path: resolved}, nil
}

func (p *PathEnricher) host(path string) string {
	if p.HostRoot == "" || p.HostRoot == "/" {
		return path
	}
	return filepath.Join(p.HostRoot, path)
}

func isOpenKind(k capability.Kind) bool {
	return k == capability.KindFileRead || k == capability.KindFileWrite || k == capability.KindFileCreate
}

func components(path string) []string {
	return strings.Split(strings.Trim(path, "/"), "/")
}

func rewriteSelf(path string, pid, tid int32) string {
	switch {
	case path == "/proc/self" && pid > 0:
		return "/proc/" + strconv.Itoa(int(pid))
	case path == "/proc/thread-self" && pid > 0 && tid > 0:
		return "/proc/" + strconv.Itoa(int(pid)) + "/task/" + strconv.Itoa(int(tid))
	}
	return path
}

// ExecEnricher fills Process.Executable on exec records from /proc/<pid>/exe,
// falling back to resolving an absolute filename.
type ExecEnricher struct {
	Paths    *PathEnricher
	ProcRoot string
}

var _ Enricher = (*ExecEnricher)(nil)

// Name identifies the enricher.
func (*ExecEnricher) Name() string { return "exec" }

// Enrich resolves the executed image in place.
func (x *ExecEnricher) Enrich(_ context.Context, e *event.Event) error {
	if e == nil || e.Capability != capability.KindProcessExec || e.Process.Executable != "" {
		return nil
	}
	root := x.ProcRoot
	if root == "" {
		root = "/proc"
	}
	if exe, err := os.Readlink(filepath.Join(root, strconv.Itoa(int(e.Process.PID)), "exe")); err == nil &&
		filepath.IsAbs(exe) && !strings.HasSuffix(exe, " (deleted)") {
		e.Process.Executable = exe
		return nil
	}
	if e.Exec != nil && filepath.IsAbs(e.Exec.Filename) {
		paths := x.Paths
		if paths == nil {
			paths = &PathEnricher{}
		}
		resolved, err := paths.Resolve(e.Exec.Filename, e.Process.PID, e.Process.TID)
		if err != nil {
			return err
		}
		e.Process.Executable = resolved
		return nil
	}
	return fmt.Errorf("%w: executable of pid %d", ErrUnresolvable, e.Process.PID)
}
