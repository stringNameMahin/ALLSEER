package daemon

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// sessionStart is the record that opens a session's part of the audit log.
func (d *Daemon) sessionStart(s *session.Session, ownerUID uint32, cgroupID uint64) decision.SessionStart {
	return decision.SessionStart{
		SessionID:     s.ID,
		Timestamp:     s.StartedAt.UTC(),
		Owner:         d.host.UserName(ownerUID),
		OwnerUID:      ownerUID,
		Mode:          string(s.Mode),
		RootPID:       s.RootPID,
		CgroupID:      cgroupID,
		Envelope:      s.Envelope,
		Coverage:      coverageRecord(d.tel.Coverage()),
		DaemonVersion: d.version,
	}
}

// sessionEnd is the record that closes a session's part of the audit log. It
// reads the ended session back so the summary matches what the session RPCs
// report, and falls back to out if the session cannot be read.
func (d *Daemon) sessionEnd(ctx context.Context, sid string, out session.Outcome) decision.SessionEnd {
	rec := decision.SessionEnd{
		SessionID:         sid,
		Timestamp:         d.now().UTC(),
		Result:            string(out.Result),
		Reason:            out.Reason,
		TelemetryComplete: out.TelemetryComplete,
		ViolationCount:    out.ViolationCount,
		BlockedCount:      out.BlockedCount,
	}
	s, err := d.manager.Get(ctx, sid)
	if err != nil || !session.IsTerminal(s.State) {
		return rec
	}
	if s.EndedAt != nil {
		rec.Timestamp = s.EndedAt.UTC()
	}
	rec.Result = string(s.State)
	rec.Reason = s.Outcome.Reason
	rec.TelemetryComplete = s.Outcome.TelemetryComplete
	rec.ViolationCount = s.Outcome.ViolationCount
	rec.BlockedCount = s.Outcome.BlockedCount
	rec.EventsObserved = s.Summary.EventsObserved
	rec.DecisionsIssued = s.Summary.DecisionsIssued
	rec.PeakRiskScore = s.Summary.PeakRiskScore
	if len(s.Summary.CapabilityUsage) > 0 {
		rec.CapabilityUsage = s.Summary.CapabilityUsage
	}
	rec.UnusedGrants = s.Summary.UnusedGrants
	rec.TopViolations = s.Summary.TopViolations
	rec.UnmatchedConnects = s.Summary.UnmatchedConnects
	rec.UnmatchedConnectTargets = s.Summary.UnmatchedConnectTargets
	return rec
}

// coverageRecord keeps the part of the coverage report an audit reader needs:
// what was observable, what was lost, and which entry points went unwatched.
func coverageRecord(c telemetry.Coverage) decision.Coverage {
	out := decision.Coverage{
		Observable:   c.Observable,
		Unobservable: c.Unobservable,
		Degraded:     c.Degraded,
	}
	if out.Observable == nil {
		out.Observable = []capability.Kind{}
	}
	for _, g := range c.EntryPoints {
		if len(g.Missing) == 0 && len(g.SuccessOnly) == 0 {
			continue
		}
		out.EntryPoints = append(out.EntryPoints, decision.EntryPointGap{
			Kind: g.Kind, Missing: g.Missing, SuccessOnly: g.SuccessOnly,
		})
	}
	return out
}
