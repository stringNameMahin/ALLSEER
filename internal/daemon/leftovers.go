package daemon

import (
	"context"
	"sort"

	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// Leftover session cgroups are the ones a previous daemon left behind with
// processes still in them, because it died without ending its sessions. The
// startup sweep freezes them before this daemon is built, which is only safe
// because the base is locked to one daemon. This file records what the sweep
// did and lets root list them, thaw them or kill them.
//
// Root only. Thawing hands processes back to nobody's governance, and the
// processes may belong to any user.

// LeftoverGroup is one leftover session cgroup.
type LeftoverGroup interface {
	Pids() ([]int, error)
	Frozen() (bool, error)
	Thaw(ctx context.Context) error
	Kill(ctx context.Context) error
	Remove() error
}

// noteLeftovers records the startup sweep's leftovers, one audit line each.
func (d *Daemon) noteLeftovers(sw containment.SweepResult) {
	frozen := make(map[string]bool, len(sw.Frozen))
	for _, name := range sw.Frozen {
		frozen[name] = true
	}
	for _, name := range sw.Populated {
		d.leftovers[name] = true
		r := decision.Leftover{SessionID: name, Timestamp: d.now().UTC(), Action: decision.LeftoverFrozen, By: "startup"}
		if !frozen[name] {
			r.Action = decision.LeftoverFreezeFailed
			r.Reason = "the group could not be frozen; its processes are running with nothing governing them"
		}
		if g, err := d.groups.Leftover(name); err == nil {
			r.PIDs = pids32(g)
		}
		d.record(context.Background(), r)
	}
}

func (d *Daemon) leftoverCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.leftovers)
}

// leftover authorizes peer and opens the named leftover.
func (d *Daemon) leftover(peer ipc.Peer, name string) (LeftoverGroup, error) {
	if !peer.Root() {
		return nil, ipc.Errorf(ipc.ErrCodePermissionDenied, "leftover session cgroups are root's to inspect and act on")
	}
	d.mu.Lock()
	known := d.leftovers[name]
	d.mu.Unlock()
	if !known {
		return nil, ipc.Errorf(ipc.ErrCodeSessionNotFound, "no leftover session cgroup %q", name)
	}
	g, err := d.groups.Leftover(name)
	if err != nil {
		return nil, ipc.Errorf(ipc.ErrCodeInternal, "opening leftover %q: %v", name, err)
	}
	return g, nil
}

func (d *Daemon) listLeftovers(peer ipc.Peer) ([]ipc.LeftoverInfo, error) {
	if !peer.Root() {
		return nil, ipc.Errorf(ipc.ErrCodePermissionDenied, "leftover session cgroups are root's to inspect and act on")
	}
	d.mu.Lock()
	names := make([]string, 0, len(d.leftovers))
	for name := range d.leftovers {
		names = append(names, name)
	}
	d.mu.Unlock()
	sort.Strings(names)

	out := make([]ipc.LeftoverInfo, 0, len(names))
	for _, name := range names {
		info := ipc.LeftoverInfo{Name: name}
		g, err := d.groups.Leftover(name)
		if err == nil {
			info.Frozen, _ = g.Frozen()
			info.PIDs = pids32(g)
		}
		users := map[string]bool{}
		for _, pid := range info.PIDs {
			if _, uid, err := d.host.Process(pid); err == nil {
				users[d.host.UserName(uid)] = true
			}
		}
		for u := range users {
			info.Users = append(info.Users, u)
		}
		sort.Strings(info.Users)
		out = append(out, info)
	}
	return out, nil
}

// thawLeftover resumes a leftover. It stays a leftover: its processes are
// still in a session cgroup no session owns, and the next daemon to start
// will freeze them again.
func (d *Daemon) thawLeftover(ctx context.Context, peer ipc.Peer, name string) error {
	g, err := d.leftover(peer, name)
	if err != nil {
		return err
	}
	pids := pids32(g)
	if err := g.Thaw(ctx); err != nil {
		return ipc.Errorf(ipc.ErrCodeInternal, "thawing %q: %v", name, err)
	}
	d.log.Warn("leftover session cgroup thawed; its processes run ungoverned", "session", name, "by", peer.UID)
	d.record(ctx, decision.Leftover{SessionID: name, Timestamp: d.now().UTC(), Action: decision.LeftoverThawed,
		PIDs: pids, By: d.host.UserName(peer.UID)})
	return nil
}

// killLeftover kills every process in a leftover and removes its cgroup.
func (d *Daemon) killLeftover(ctx context.Context, peer ipc.Peer, name string) error {
	g, err := d.leftover(peer, name)
	if err != nil {
		return err
	}
	pids := pids32(g)
	if err := g.Kill(ctx); err != nil {
		return ipc.Errorf(ipc.ErrCodeInternal, "killing %q: %v", name, err)
	}
	if err := g.Remove(); err != nil {
		d.log.Warn("leftover killed but its cgroup was not removed", "session", name, "err", err)
	}
	d.mu.Lock()
	delete(d.leftovers, name)
	d.mu.Unlock()
	d.log.Info("leftover session cgroup killed", "session", name, "by", peer.UID)
	d.record(ctx, decision.Leftover{SessionID: name, Timestamp: d.now().UTC(), Action: decision.LeftoverKilled,
		PIDs: pids, By: d.host.UserName(peer.UID)})
	return nil
}

func pids32(g LeftoverGroup) []int32 {
	pids, _ := g.Pids()
	out := make([]int32, 0, len(pids))
	for _, p := range pids {
		out = append(out, int32(p))
	}
	return out
}
