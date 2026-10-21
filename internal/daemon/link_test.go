package daemon

import (
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// link is the record the security_path_link hook submits for a hard link.
func link(src, dst string) synth.Spec {
	return synth.Spec{
		Type:  abi.EvtFileLink,
		Flags: uint32(abi.AllseerEvtFOutcomeUnknown),
		File:  &synth.File{Path: src, ResolvedPath: src, NewPath: dst, Inode: 4242, Device: 2049},
	}
}

// A hard link to a file the envelope denies reading gives the agent a second
// name for it, so the link is the denied act. Linking within the workspace is
// ordinary build behaviour and stays inside the envelope.
func TestLinkingADeniedFileIsADenial(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	sid := r.start(t, "run the go tests")

	r.feed(t, sid, link(r.ws+"/build/a.o", r.ws+"/build/b.o"))
	waitFor(t, "the workspace link", func() bool { return len(r.audit.all()) == 1 })
	if d := r.audit.all()[0]; d.Verdict != decision.VerdictWithinEnvelope || d.Action != ece.ActionAllow {
		t.Fatalf("workspace link = %s %s, want within_envelope allow", d.Verdict, d.Action)
	}

	r.feed(t, sid, link("/home/dev/.ssh/id_rsa", r.ws+"/k"))
	waitFor(t, "the kill", func() bool { _, k := r.groups.get(sid).state(); return k })
	d := r.audit.all()[1]
	if d.Verdict != decision.VerdictExplicitlyDenied || d.Action != ece.ActionBlock || !d.Enforced {
		t.Fatalf("credential link = %s %s enforced %v, want an enforced explicit denial", d.Verdict, d.Action, d.Enforced)
	}
}
