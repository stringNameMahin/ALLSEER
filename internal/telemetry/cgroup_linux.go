//go:build linux

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CgroupPathOfPID returns the absolute cgroup v2 directory a process is in.
func CgroupPathOfPID(pid int32) (string, error) {
	root, err := requireCgroupV2()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "cgroup"))
	if err != nil {
		return "", fmt.Errorf("telemetry: reading cgroup of pid %d: %w", pid, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(root, rel), nil
		}
	}
	return "", fmt.Errorf("telemetry: pid %d is not in a cgroup v2 hierarchy", pid)
}

// CgroupIDOfPath returns the cgroup ID bpf_get_current_cgroup_id() reports for
// processes in the directory: its inode number in the unified hierarchy.
func CgroupIDOfPath(dir string) (uint64, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("telemetry: stat cgroup %s: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("telemetry: stat cgroup %s: no inode", dir)
	}
	return st.Ino, nil
}

// CgroupIDOfPID returns the cgroup ID of the cgroup a process is in.
func CgroupIDOfPID(pid int32) (uint64, error) {
	dir, err := CgroupPathOfPID(pid)
	if err != nil {
		return 0, err
	}
	return CgroupIDOfPath(dir)
}
