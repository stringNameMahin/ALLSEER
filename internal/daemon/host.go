package daemon

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/containment"
)

// ProcHost implements Host from /proc and the user database.
type ProcHost struct{}

var _ Host = ProcHost{}

// Process returns the parent PID and real UID of pid.
func (ProcHost) Process(pid int32) (int32, uint32, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "status"))
	if err != nil {
		return 0, 0, err
	}
	var ppid int64 = -1
	var uid int64 = -1
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "PPid:":
			ppid, _ = strconv.ParseInt(f[1], 10, 32)
		case "Uid:":
			uid, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if ppid < 0 || uid < 0 {
		return 0, 0, fmt.Errorf("daemon: cannot read identity of pid %d", pid)
	}
	return int32(ppid), uint32(uid), nil
}

// Home returns the user's home directory.
func (ProcHost) Home(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// UserName returns the user's login name, or uid:N.
func (ProcHost) UserName(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return fmt.Sprintf("uid:%d", uid)
	}
	return u.Username
}

// Resolvers returns the nameserver addresses in a resolv.conf.
func Resolvers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, a.String())
			}
		}
	}
	return out
}

// CgroupGroups adapts containment.Manager to Groups.
type CgroupGroups struct{ M *containment.Manager }

var _ Groups = CgroupGroups{}

// Create makes a session cgroup.
func (c CgroupGroups) Create(sid string) (SessionGroup, error) {
	g, err := c.M.Create(sid)
	if err != nil {
		return nil, err
	}
	return cgroupGroup{g}, nil
}

// Capabilities reports what the host supports.
func (c CgroupGroups) Capabilities() containment.Capabilities { return c.M.Capabilities() }

// Governed reports whether pid is inside one of this daemon's session cgroups.
func (c CgroupGroups) Governed(pid int32) (bool, error) { return c.M.Governed(int(pid)) }

type cgroupGroup struct{ *containment.Group }

func (g cgroupGroup) CgroupID() uint64 { return g.ID }
