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

// Path resolution strategy (M6): user space, never a guess.
//
//   - An absolute path is resolved component by component against the host
//     root, following symlinks the way the kernel would. /proc/self and
//     /proc/thread-self are rewritten to the acting process, because resolving
//     them in the daemon would name the daemon.
//   - A relative path is resolved only for a successful open, from the opened
//     descriptor's /proc link, and only when that link agrees with the name the
//     process asked for. The record carries no dirfd, so a cwd join on its own
//     would be a guess.
//   - Anything else returns an error and leaves ResolvedPath empty, which the
//     validator reports as unresolvable (indeterminate), never as covered.
//
// Known race: a rename or symlink swap between the syscall and this lookup can
// change the answer. Resolving in the kernel would avoid it at the cost of
// verifier-bounded dentry walks; that trade is recorded in devdocs.

// ErrUnresolvable means enrichment could not establish a resolved path.
var ErrUnresolvable = errors.New("telemetry: path cannot be resolved")

const maxSymlinkHops = 40

// PathEnricher fills FilePayload.ResolvedPath.
type PathEnricher struct {
	// HostRoot is prefixed to every lookup. Empty means "/". Tests point it at
	// a temporary tree.
	HostRoot string
	// ProcRoot is where per-process links are read. Empty means "/proc".
	ProcRoot string
}

var _ Enricher = (*PathEnricher)(nil)

// Name identifies the enricher.
func (*PathEnricher) Name() string { return "path" }

// Enrich resolves the event's file path in place.
func (p *PathEnricher) Enrich(_ context.Context, e *event.Event) error {
	if e == nil || e.File == nil || e.File.ResolvedPath != "" {
		return nil
	}
	path := e.File.Path
	if path == "" {
		return fmt.Errorf("%w: the record carries no path", ErrUnresolvable)
	}

	var (
		resolved string
		err      error
	)
	if filepath.IsAbs(path) {
		resolved, err = p.Resolve(path, e.Process.PID, e.Process.TID)
	} else {
		resolved, err = p.resolveRelative(e)
	}
	if err != nil {
		return err
	}
	e.File.ResolvedPath = resolved
	return nil
}

// Resolve follows an absolute path to the file it names, as seen from the
// host root. A missing component ends the walk and the remainder is appended
// lexically, since a name that does not exist cannot be a symlink.
func (p *PathEnricher) Resolve(path string, pid, tid int32) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrUnresolvable, path)
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
				return filepath.Clean(filepath.Join(append([]string{next}, rest...)...)), nil
			}
			return "", fmt.Errorf("%w: %s: %v", ErrUnresolvable, next, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("%w: too many symlinks in %q", ErrUnresolvable, path)
		}
		target, err := os.Readlink(p.host(next))
		if err != nil {
			return "", fmt.Errorf("%w: readlink %s: %v", ErrUnresolvable, next, err)
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
	return resolved, nil
}

// resolveRelative handles a relative name from a successful open.
func (p *PathEnricher) resolveRelative(e *event.Event) (string, error) {
	if !isOpenKind(e.Capability) || !e.Result.Succeeded || e.Result.ReturnCode < 0 {
		return "", fmt.Errorf("%w: relative path %q from a record with no open descriptor", ErrUnresolvable, e.File.Path)
	}
	pid := e.Process.PID
	link, err := os.Readlink(filepath.Join(p.proc(), strconv.Itoa(int(pid)), "fd", strconv.FormatInt(e.Result.ReturnCode, 10)))
	if err != nil {
		return "", fmt.Errorf("%w: descriptor link: %v", ErrUnresolvable, err)
	}
	if !filepath.IsAbs(link) || strings.HasSuffix(link, " (deleted)") {
		return "", fmt.Errorf("%w: descriptor link %q is not a live path", ErrUnresolvable, link)
	}

	rel := filepath.Clean(e.File.Path)
	if rel != ".." && !strings.HasPrefix(rel, "../") && strings.HasSuffix(link, "/"+rel) {
		return link, nil
	}

	// The name may cross a symlink or "..". Accept the link only if the
	// process's cwd joined with the name resolves to the same file.
	cwd, err := os.Readlink(filepath.Join(p.proc(), strconv.Itoa(int(pid)), "cwd"))
	if err == nil && filepath.IsAbs(cwd) {
		if cand, err := p.Resolve(filepath.Join(cwd, e.File.Path), pid, e.Process.TID); err == nil && cand == link {
			return link, nil
		}
	}
	return "", fmt.Errorf("%w: descriptor link %q does not match %q", ErrUnresolvable, link, e.File.Path)
}

func (p *PathEnricher) host(path string) string {
	if p.HostRoot == "" || p.HostRoot == "/" {
		return path
	}
	return filepath.Join(p.HostRoot, path)
}

func (p *PathEnricher) proc() string {
	if p.ProcRoot == "" {
		return "/proc"
	}
	return p.ProcRoot
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
