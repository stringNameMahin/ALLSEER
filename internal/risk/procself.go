package risk

import (
	"strconv"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// ownProcReason is why a file in the reader's own /proc directory is not
// graded by the list.
const ownProcReason = "The reading process's own /proc entry. It already holds what is there, and " +
	"runtimes read it at start (Rust's standard library reads /proc/self/maps), so it is not " +
	"another process's environment or memory."

// ownProcEntry reports whether path is a file in the reading process's own
// /proc directory: /proc/<id>/<file> or /proc/<id>/task/<tid>/<file>, where id
// is the reader's process or thread ID. Telemetry rewrites /proc/self to the
// reader's pid, and the probes report initial-namespace IDs, the ones the
// host's /proc uses. root, cwd and exe link into the rest of the filesystem,
// and anything deeper (fd/, map_files/) names another file, so those stay
// graded by the list.
func ownProcEntry(path string, p event.Process) bool {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 4 && parts[1] == "task" && isProcID(parts[2]) {
		parts = []string{parts[0], parts[3]}
	}
	if len(parts) != 2 || !ownProcID(parts[0], p) {
		return false
	}
	switch parts[1] {
	case "", ".", "..", "root", "cwd", "exe":
		return false
	}
	return true
}

func ownProcID(s string, p event.Process) bool {
	if s == "self" || s == "thread-self" {
		return true
	}
	if !isProcID(s) {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return false
	}
	id := int32(n)
	return (p.PID > 0 && id == p.PID) || (p.TID > 0 && id == p.TID)
}

// isProcID reports whether s is an ID as /proc spells it: decimal, no sign,
// no leading zero.
func isProcID(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
