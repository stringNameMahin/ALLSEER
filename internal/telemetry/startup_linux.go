//go:build linux

package telemetry

// The one startup check that is not portable, and why it is kept apart.
//
// startup.go states that its checks live outside the `linux && ebpf` tag
// because "none of them needs a kernel or libbpfgo to run, and a check that
// only compiles on the host it guards is a check nobody runs until it is too
// late to fix". That reasoning holds for every check in that file: reading an
// ELF section, comparing two integers and validating a size against the page
// size are all answerable anywhere.
//
// It does not hold here. requireCgroupV2 reads /proc/mounts, which is a Linux
// kernel interface and not a file that merely happens to be absent elsewhere.
// Off Linux the read fails with a path error rather than ErrNoCgroupV2, so the
// function cannot report the finding it exists to report, and the test written
// against it — which deliberately asserts against the real host rather than a
// mock — fails for a reason that says nothing about the check.
//
// So the tag is `linux` and not `linux && ebpf`. The narrower tag would have
// been wrong in the direction startup.go warns about: BPFLoader.Load is the only
// caller and is `linux && ebpf`, but this check needs no libbpfgo, and gating it
// on the build tag of its caller would mean an ordinary `go test ./...` on Linux
// stopped exercising it. Under `linux` it is compiled and tested by every Linux
// build exactly as it was when it lived in startup.go, and it simply does not
// exist on the platforms where it could not answer.
//
// unescapeMountField travels with it. It is unexported, has exactly one caller,
// and exists solely to undo the escaping /proc/mounts applies; keeping it beside
// the only function that can use it is what stops it reading as dead code on a
// non-Linux build.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoCgroupV2: no cgroup2 filesystem is mounted.
//
// Fatal at startup, not a degradation. The probes filter on the value
// bpf_get_current_cgroup_id() returns, and without a cgroup v2 hierarchy that
// value cannot identify anything user space can name. Every event would miss
// the filter and the daemon would run, attach cleanly, and report nothing —
// which reads downstream as an agent that did nothing. bpf/allseer.bpf.c states
// where this belongs: "Detecting it belongs to the loader, which is the only
// side that can refuse to start."
var ErrNoCgroupV2 = errors.New("telemetry: no cgroup2 filesystem is mounted")

// requireCgroupV2 returns the cgroup2 mount point, or an error if there is none.
//
// The unified hierarchy is what bpf_get_current_cgroup_id() reports on. A v1
// hierarchy mounted alongside is not a substitute and is not looked for: the
// probes key on one ID and v1 has one per controller.
func requireCgroupV2() (string, error) {
	const procMounts = "/proc/mounts"

	b, err := os.ReadFile(procMounts)
	if err != nil {
		return "", fmt.Errorf("telemetry: reading %s: %w", procMounts, err)
	}
	for line := range strings.SplitSeq(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[2] != "cgroup2" {
			continue
		}
		return unescapeMountField(f[1]), nil
	}
	return "", ErrNoCgroupV2
}

// unescapeMountField undoes the octal escaping /proc/mounts applies to space,
// tab, newline and backslash in a path. Trivial, and wrong to skip: an escaped
// mount point compared literally would fail to match a real directory.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v byte
			ok := true
			for _, c := range []byte(s[i+1 : i+4]) {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + (c - '0')
			}
			if ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
