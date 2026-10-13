package daemon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// approvals holds requests for decisions a frozen session is waiting on.
//
// A session stays frozen until every open request for it is answered. Any
// denial, and any timeout under the deny posture, kills the session's tree.
type approvals struct {
	d *Daemon

	mu      sync.Mutex
	pending map[string]*pendingApproval
	subs    map[int]chan decision.ApprovalRequest
	nextSub int
	seq     uint64
}

type pendingApproval struct {
	req   decision.ApprovalRequest
	timer *time.Timer
}

func newApprovals(d *Daemon) *approvals {
	return &approvals{d: d, pending: map[string]*pendingApproval{}, subs: map[int]chan decision.ApprovalRequest{}}
}

func (a *approvals) open(dec decision.Decision) {
	now := a.d.now()
	a.mu.Lock()
	a.seq++
	id := fmt.Sprintf("apr-%s-%d", dec.SessionID, a.seq)
	req := decision.ApprovalRequest{
		ID:        id,
		SessionID: dec.SessionID,
		Decision:  dec,
		CreatedAt: now,
		Deadline:  now.Add(a.d.cfg.Policy.ApprovalTimeout),
		Summary:   summarize(dec),
	}
	p := &pendingApproval{req: req}
	p.timer = time.AfterFunc(a.d.cfg.Policy.ApprovalTimeout, func() { a.timeout(id) })
	a.pending[id] = p
	subs := make([]chan decision.ApprovalRequest, 0, len(a.subs))
	for _, ch := range a.subs {
		subs = append(subs, ch)
	}
	a.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
	a.d.log.Warn("approval requested; session frozen", "session", dec.SessionID, "request", id, "summary", req.Summary)
}

// summarize says what happened, why it was flagged, and what each answer
// does, without needing the source.
func summarize(d decision.Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "verdict %s, risk %.0f (%s)", d.Verdict, d.Risk.Score, d.Risk.Level)
	if d.MatchedRule != "" {
		fmt.Fprintf(&b, ", rule %s", d.MatchedRule)
	}
	var finding string
	for _, r := range d.Reasoning {
		if r.Stage == "validator" && r.Conclusion != "" {
			finding = r.Conclusion
			if r.Detail != "" {
				finding += ": " + r.Detail
			}
		}
	}
	if finding != "" {
		fmt.Fprintf(&b, "; %s", finding)
	}
	b.WriteString(". Approve resumes the frozen agent; deny or timeout kills its process tree.")
	return b.String()
}

func (a *approvals) list(owner func(sid string) bool) []decision.ApprovalRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []decision.ApprovalRequest
	for _, p := range a.pending {
		if owner(p.req.SessionID) {
			out = append(out, p.req)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (a *approvals) sessionOf(id string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pending[id]
	if !ok {
		return "", false
	}
	return p.req.SessionID, true
}

func (a *approvals) timeout(id string) {
	allow := a.d.cfg.Policy.ApprovalTimeoutAction == "allow"
	a.resolve(context.Background(), decision.ApprovalResponse{
		RequestID: id, Approved: allow, RespondedBy: "timeout", RespondedAt: a.d.now(), TimedOut: true,
	})
}

// resolve answers a request. It returns false if the request is unknown.
func (a *approvals) resolve(ctx context.Context, resp decision.ApprovalResponse) bool {
	a.mu.Lock()
	p, ok := a.pending[resp.RequestID]
	if !ok {
		a.mu.Unlock()
		return false
	}
	p.timer.Stop()
	delete(a.pending, resp.RequestID)
	sid := p.req.SessionID
	remaining := 0
	for _, q := range a.pending {
		if q.req.SessionID == sid {
			remaining++
		}
	}
	a.mu.Unlock()

	a.d.log.Info("approval answered", "session", sid, "request", resp.RequestID,
		"approved", resp.Approved, "by", resp.RespondedBy, "timed_out", resp.TimedOut)

	if !resp.Approved {
		reason := fmt.Sprintf("approval %s denied by %s", resp.RequestID, resp.RespondedBy)
		if resp.TimedOut {
			reason = fmt.Sprintf("approval %s timed out", resp.RequestID)
		}
		a.d.later(func() {
			if g := a.d.groupOf(sid); g != nil {
				_ = g.Kill(ctx)
			}
			a.d.failSessionAs(context.Background(), sid, session.StateTerminated, reason)
		})
		return true
	}
	if remaining == 0 {
		if err := a.d.manager.Resume(ctx, sid); err != nil {
			a.d.log.Error("resuming session after approval", "session", sid, "err", err)
		}
	}
	return true
}

func (a *approvals) cancelSession(sid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, p := range a.pending {
		if p.req.SessionID == sid {
			p.timer.Stop()
			delete(a.pending, id)
		}
	}
}

func (a *approvals) subscribe() (int, <-chan decision.ApprovalRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextSub++
	ch := make(chan decision.ApprovalRequest, 32)
	a.subs[a.nextSub] = ch
	return a.nextSub, ch
}

func (a *approvals) unsubscribe(id int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.subs, id)
}
