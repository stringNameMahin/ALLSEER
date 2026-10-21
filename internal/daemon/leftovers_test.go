package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// leftoverRig is a daemon started after a sweep found two leftovers: one it
// froze and one it could not.
func leftoverRig(t *testing.T) *rig {
	t.Helper()
	return newRigWith(t, policy.ModeInteractive, time.Minute, func(r *rig, o *Options) {
		r.groups.groups["s-old-1"] = &fakeGroup{id: 9001, adopted: []int{777, 778}, populated: true, frozen: true}
		r.groups.groups["s-old-2"] = &fakeGroup{id: 9002, adopted: []int{779}, populated: true}
		o.Leftovers = containment.SweepResult{Populated: []string{"s-old-1", "s-old-2"}, Frozen: []string{"s-old-1"}}
	})
}

func call(t *testing.T, r *rig, uid uint32, method string, params any) (any, error) {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return r.d.Call(context.Background(), ipc.Peer{PID: 1, UID: uid}, method, raw)
}

func errCode(err error) ipc.ErrorCode {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// The sweep's work reaches the audit log before anything else happens, so a
// reader sees which dead sessions left processes behind and what became of
// them.
func TestStartupRecordsEachLeftover(t *testing.T) {
	r := leftoverRig(t)
	got := recordsOf[decision.Leftover](r.audit)
	if len(got) != 2 {
		t.Fatalf("leftover records = %+v, want two", got)
	}
	if got[0].SessionID != "s-old-1" || got[0].Action != decision.LeftoverFrozen || got[0].By != "startup" ||
		len(got[0].PIDs) != 2 || got[0].PIDs[0] != 777 {
		t.Errorf("first record = %+v, want s-old-1 frozen at startup with its two pids", got[0])
	}
	if got[1].SessionID != "s-old-2" || got[1].Action != decision.LeftoverFreezeFailed || got[1].Reason == "" {
		t.Errorf("second record = %+v, want s-old-2 freeze_failed with a reason", got[1])
	}
	if n := r.d.status().Leftovers; n != 2 {
		t.Errorf("status leftovers = %d, want 2", n)
	}
}

// Leftovers may hold anybody's processes, and thawing one hands them back to
// no governance at all, so only root may look at or act on them.
func TestLeftoversAreRootOnly(t *testing.T) {
	r := leftoverRig(t)
	for _, m := range []string{ipc.MethodListLeftovers, ipc.MethodThawLeftover, ipc.MethodKillLeftover} {
		if _, err := call(t, r, 1000, m, ipc.LeftoverRequest{Name: "s-old-1"}); errCode(err) != ipc.ErrCodePermissionDenied {
			t.Errorf("%s as uid 1000 = %v, want permission denied", m, err)
		}
	}
	if f, k := r.groups.get("s-old-1").state(); !f || k {
		t.Fatalf("a refused call changed the leftover: frozen %v killed %v", f, k)
	}
}

func TestRootCanListThawAndKillALeftover(t *testing.T) {
	r := leftoverRig(t)

	res, err := call(t, r, 0, ipc.MethodListLeftovers, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := res.([]ipc.LeftoverInfo)
	if len(list) != 2 || list[0].Name != "s-old-1" || !list[0].Frozen || len(list[0].PIDs) != 2 ||
		len(list[0].Users) != 1 || list[1].Name != "s-old-2" || list[1].Frozen {
		t.Fatalf("list = %+v", list)
	}

	if _, err := call(t, r, 0, ipc.MethodThawLeftover, ipc.LeftoverRequest{Name: "s-old-1"}); err != nil {
		t.Fatal(err)
	}
	if f, _ := r.groups.get("s-old-1").state(); f {
		t.Fatal("thaw left the group frozen")
	}

	if _, err := call(t, r, 0, ipc.MethodKillLeftover, ipc.LeftoverRequest{Name: "s-old-1"}); err != nil {
		t.Fatal(err)
	}
	g := r.groups.get("s-old-1")
	if _, k := g.state(); !k || !g.removed {
		t.Fatalf("kill: killed %v removed %v", k, g.removed)
	}
	res, _ = call(t, r, 0, ipc.MethodListLeftovers, nil)
	if list := res.([]ipc.LeftoverInfo); len(list) != 1 || list[0].Name != "s-old-2" {
		t.Fatalf("list after kill = %+v, want only s-old-2", list)
	}

	got := recordsOf[decision.Leftover](r.audit)
	if len(got) != 4 || got[2].Action != decision.LeftoverThawed || got[3].Action != decision.LeftoverKilled ||
		got[3].SessionID != "s-old-1" || len(got[3].PIDs) != 2 {
		t.Fatalf("leftover records = %+v, want frozen, freeze_failed, thawed, killed", got)
	}
}

// Only what the sweep found is a leftover. A live session frozen for approval
// must not be thawable this way, which would answer its approval without the
// approval, and nothing else under the base can be named into it.
func TestALiveSessionIsNotALeftover(t *testing.T) {
	r := leftoverRig(t)
	sid := r.start(t, "run the go tests")
	for _, m := range []string{ipc.MethodThawLeftover, ipc.MethodKillLeftover} {
		for _, name := range []string{sid, "s-unknown"} {
			if _, err := call(t, r, 0, m, ipc.LeftoverRequest{Name: name}); errCode(err) != ipc.ErrCodeSessionNotFound {
				t.Errorf("%s %s = %v, want not found", m, name, err)
			}
		}
	}
	if _, k := r.groups.get(sid).state(); k {
		t.Fatal("a live session's group was killed as a leftover")
	}
}
