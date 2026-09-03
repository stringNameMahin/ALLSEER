package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The lifecycle is a graph, and the interesting claims are about the graph
// rather than about any one method: a terminated session cannot restart, an
// unapproved envelope cannot govern a running agent, a session cannot be
// started twice under two PIDs. Those are tested here against the table that
// declares them, exhaustively, so a state added to the enum cannot inherit
// permissive behavior by omission.
//
// The other half is that every refusal is an *error*. A no-op Start on an ended
// session produces a record that disagrees with the world, and every conclusion
// drawn from it afterwards is a conclusion about the wrong session.

// --- fixtures -------------------------------------------------------------------

var epoch = time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)

// clock is a manually advanced clock, so lifecycle timestamps are testable
// without sleeping and so CreatedAt ordering is something the test decides
// rather than something it races.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: epoch} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testEnvelope is an admissible envelope for one session.
//
// Admissible matters: Seal runs the same validator.BlockingIssues the daemon
// would, so a fixture with an unmatchable selector would fail sealing rather
// than the transition under test.
func testEnvelope(sessionID string) *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            "env-" + sessionID,
		SessionID:     sessionID,
		CreatedAt:     epoch,
		Intent: ece.IntentRecord{
			RawPrompt: "build the project",
			Summary:   "Run a build in the workspace.",
			Analyzer:  "rules:v1",
		},
		Grants: []capability.Grant{{
			Kind:     capability.KindFileRead,
			Domain:   capability.DomainFilesystem,
			Selector: capability.Selector{PathPatterns: []string{"/home/dev/project/**"}},
		}},
		Constraints:   ece.Constraints{WorkspaceRoot: "/home/dev/project"},
		DefaultAction: ece.ActionRequestApproval,
	}
}

// stubSupervisor stands in for the process supervisor that is M7 and M11.
//
// Present so the Suspend and Resume transitions can be exercised at all: the
// manager refuses both without one, which is itself a tested behavior, and a
// transition that could never be taken would be a row in the table nothing
// checks.
type stubSupervisor struct {
	suspended, resumed int
	suspendErr         error
	resumeErr          error
}

func (s *stubSupervisor) Launch(context.Context, string, Command) (int32, error) { return 1, nil }
func (s *stubSupervisor) Suspend(context.Context, string) error {
	s.suspended++
	return s.suspendErr
}
func (s *stubSupervisor) Resume(context.Context, string) error {
	s.resumed++
	return s.resumeErr
}
func (s *stubSupervisor) Terminate(context.Context, string, time.Duration) error { return nil }
func (s *stubSupervisor) Wait(context.Context, string) (int, error)              { return 0, nil }

var _ Supervisor = (*stubSupervisor)(nil)

// managerFor builds a manager and creates one session in it.
func managerFor(t *testing.T, cfg ManagerConfig) (*MemoryManager, *clock, string) {
	t.Helper()

	c := newClock()
	cfg.Now = c.now
	m := NewManager(cfg)

	const id = "s-1"
	if _, err := m.Create(context.Background(), CreateRequest{Envelope: testEnvelope(id)}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return m, c, id
}

// drive walks a session to the requested state through the real transitions.
//
// Every state is reached the way a caller would reach it, so a test asserting
// what may be done *from* a state is asserting it about a state the machine can
// actually produce.
func drive(t *testing.T, m *MemoryManager, id string, to State) {
	t.Helper()
	ctx := context.Background()

	switch to {
	case StatePending:
		return
	case StateAwaitingApproval:
		mustSeal(t, m, id)
	case StateReady:
		mustSeal(t, m, id)
		if s := stateOf(t, m, id); s == StateAwaitingApproval {
			if err := m.Approve(ctx, id, ece.ApprovalRecord{ApprovedBy: "tester", Method: "cli"}); err != nil {
				t.Fatalf("Approve: %v", err)
			}
		}
	case StateActive:
		drive(t, m, id, StateReady)
		if err := m.Start(ctx, id, 4242); err != nil {
			t.Fatalf("Start: %v", err)
		}
	case StateSuspended:
		drive(t, m, id, StateActive)
		if err := m.Suspend(ctx, id, "approval pending"); err != nil {
			t.Fatalf("Suspend: %v", err)
		}
	case StateCompleted, StateTerminated, StateFailed:
		drive(t, m, id, StateActive)
		if err := m.End(ctx, id, Outcome{Result: to, Reason: "test"}); err != nil {
			t.Fatalf("End: %v", err)
		}
	default:
		t.Fatalf("drive: unhandled state %q", to)
	}

	if got := stateOf(t, m, id); got != to {
		t.Fatalf("drive to %q left the session in %q", to, got)
	}
}

func mustSeal(t *testing.T, m *MemoryManager, id string) {
	t.Helper()
	if err := m.Seal(context.Background(), id); err != nil {
		t.Fatalf("Seal: %v", err)
	}
}

func stateOf(t *testing.T, m *MemoryManager, id string) State {
	t.Helper()
	s, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return s.State
}

// attempt takes an action against a session, whatever state it is in.
func attempt(m *MemoryManager, id string, a Action) error {
	ctx := context.Background()
	switch a {
	case ActionSeal:
		return m.Seal(ctx, id)
	case ActionApprove:
		return m.Approve(ctx, id, ece.ApprovalRecord{ApprovedBy: "tester", Method: "cli"})
	case ActionStart:
		return m.Start(ctx, id, 4242)
	case ActionSuspend:
		return m.Suspend(ctx, id, "test")
	case ActionResume:
		return m.Resume(ctx, id)
	case ActionEnd:
		return m.End(ctx, id, Outcome{Reason: "test"})
	}
	return fmt.Errorf("unhandled action %q", a)
}

// --- the transition table ---------------------------------------------------------

// Every (state, action) pair is either legal or refused, and the table says
// which. A state added to the enum and forgotten here fails this rather than
// quietly inheriting whatever the map's zero value happens to be.
func TestEveryTransitionPairIsClassified(t *testing.T) {
	legalCount := 0
	for _, from := range AllStates() {
		for _, a := range AllActions() {
			if Allowed(a, from) {
				legalCount++
				if IsTerminal(from) {
					t.Errorf("%s is legal from terminal state %s; terminal means terminal", a, from)
				}
			}
		}
	}
	if legalCount == 0 {
		t.Fatal("the transition table declares nothing legal")
	}

	// Every action must be reachable from somewhere, or it is a method no
	// sequence of calls can ever exercise.
	for _, a := range AllActions() {
		reachable := false
		for _, from := range AllStates() {
			if Allowed(a, from) {
				reachable = true
			}
		}
		if !reachable {
			t.Errorf("action %s is legal from no state at all", a)
		}
	}

	// Every non-terminal state must have some way out, or a session can enter
	// it and never leave -- holding its tracking state and never appearing in a
	// completed-session query.
	for _, from := range AllStates() {
		if IsTerminal(from) {
			continue
		}
		out := false
		for _, a := range AllActions() {
			if Allowed(a, from) {
				out = true
			}
		}
		if !out {
			t.Errorf("state %s has no legal transition out of it", from)
		}
	}
}

// The behavioral half of the table: for every state the machine can actually
// produce, every action either succeeds or is refused with a TransitionError,
// and the two agree with Allowed.
//
// This is what catches a method that checks the table and then does the work
// anyway, or one that forgets to check at all.
func TestActionsAgreeWithTheTable(t *testing.T) {
	for _, from := range AllStates() {
		for _, a := range AllActions() {
			t.Run(string(from)+"/"+string(a), func(t *testing.T) {
				// RequireApproval on so awaiting_approval is a state drive can
				// actually reach; a supervisor wired so suspend and resume are
				// refused by the *table* rather than by the missing mechanism,
				// which has its own test.
				m, _, id := managerFor(t, ManagerConfig{
					RequireApproval: true,
					Supervisor:      &stubSupervisor{},
				})
				drive(t, m, id, from)

				err := attempt(m, id, a)

				if !Allowed(a, from) {
					if err == nil {
						t.Fatalf("%s from %s succeeded; the table forbids it", a, from)
					}
					if !errors.Is(err, ErrIllegalTransition) {
						t.Fatalf("%s from %s returned %v, want an illegal-transition error", a, from, err)
					}
					var te *TransitionError
					if !errors.As(err, &te) {
						t.Fatalf("%s from %s returned %v, want a *TransitionError", a, from, err)
					}
					if te.From != from || te.Action != a || te.SessionID != id {
						t.Errorf("error reports {%s %s %s}, want {%s %s %s}",
							te.SessionID, te.Action, te.From, id, a, from)
					}
					// The state must not have moved. A refusal that changed
					// something is worse than one that did not refuse.
					if got := stateOf(t, m, id); got != from {
						t.Errorf("a refused %s moved the session from %s to %s", a, from, got)
					}
					return
				}

				if err != nil {
					t.Fatalf("%s from %s failed: %v; the table allows it", a, from, err)
				}
				if got := stateOf(t, m, id); got == from && a != ActionSeal {
					t.Errorf("%s from %s left the state unchanged at %s", a, from, got)
				}
			})
		}
	}
}

// The single most important refusal in the graph, called out on its own because
// it is the one an operator would notice: an ended session stays ended.
func TestTerminalStatesAreFinal(t *testing.T) {
	for _, final := range TerminalStates() {
		t.Run(string(final), func(t *testing.T) {
			m, _, id := managerFor(t, ManagerConfig{Supervisor: &stubSupervisor{}})
			drive(t, m, id, final)

			for _, a := range AllActions() {
				if err := attempt(m, id, a); !errors.Is(err, ErrIllegalTransition) {
					t.Errorf("%s on a %s session = %v, want refusal", a, final, err)
				}
			}
			if got := stateOf(t, m, id); got != final {
				t.Errorf("state is now %s, want %s", got, final)
			}
		})
	}
}

// A session is started once. Two Starts would mean two root PIDs for one
// governed tree, and the second would silently replace the first -- leaving the
// events attributed to a process nothing was watching.
func TestSessionCannotBeStartedTwice(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)

	if err := m.Start(context.Background(), id, 9999); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("second Start = %v, want refusal", err)
	}
	s, _ := m.Get(context.Background(), id)
	if s.RootPID != 4242 {
		t.Errorf("RootPID = %d, want the first PID 4242 kept", s.RootPID)
	}
}

// --- creation ----------------------------------------------------------------------

func TestCreateRequiresAnEnvelope(t *testing.T) {
	m := NewManager(ManagerConfig{})

	_, err := m.Create(context.Background(), CreateRequest{Prompt: "do the thing"})
	if !errors.Is(err, ErrNoEnvelope) {
		t.Fatalf("Create with only a prompt = %v, want ErrNoEnvelope", err)
	}
	// The refusal has to say what is missing, or the caller reads it as a bug
	// rather than as an unimplemented milestone.
	if !strings.Contains(err.Error(), "M8") || !strings.Contains(err.Error(), "M9") {
		t.Errorf("error = %q, want it to name the milestones that would supply an envelope", err)
	}
	if m.Len() != 0 {
		t.Errorf("a refused Create left %d sessions behind", m.Len())
	}
}

func TestCreateRequiresASessionIDOnTheEnvelope(t *testing.T) {
	env := testEnvelope("s-1")
	env.SessionID = ""

	m := NewManager(ManagerConfig{})
	if _, err := m.Create(context.Background(), CreateRequest{Envelope: env}); !errors.Is(err, ErrNoSessionID) {
		t.Fatalf("Create = %v, want ErrNoSessionID", err)
	}
}

// Refused rather than overwritten: the second caller would take over the first
// one's governance and the first one's accumulated state would vanish
// mid-session.
func TestDuplicateCreateIsRefused(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)

	_, err := m.Create(context.Background(), CreateRequest{Envelope: testEnvelope(id)})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate Create = %v, want ErrExists", err)
	}
	if got := stateOf(t, m, id); got != StateActive {
		t.Errorf("the existing session is now %s; a refused Create must not disturb it", got)
	}
}

func TestCreateDefaultsModeAndWorkspace(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})

	s, err := m.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Mode != policy.ModeMonitor {
		t.Errorf("Mode = %q, want monitor; a system that starts out blocking gets uninstalled", s.Mode)
	}
	if s.WorkspaceRoot != "/home/dev/project" {
		t.Errorf("WorkspaceRoot = %q, want the envelope's own constraint", s.WorkspaceRoot)
	}
	if s.State != StatePending {
		t.Errorf("State = %q, want pending", s.State)
	}
	if !s.CreatedAt.Equal(epoch) {
		t.Errorf("CreatedAt = %v, want the injected clock's %v", s.CreatedAt, epoch)
	}
	if !s.StartedAt.IsZero() {
		t.Error("StartedAt is set on a session that has not started")
	}
}

func TestCreateRequestOverridesTheEnvelope(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now, DefaultMode: policy.ModeMonitor})

	_, err := m.Create(context.Background(), CreateRequest{
		Envelope:      testEnvelope("s-1"),
		Mode:          policy.ModeEnforce,
		WorkspaceRoot: "/srv/build",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s, _ := m.Get(context.Background(), "s-1")
	if s.Mode != policy.ModeEnforce {
		t.Errorf("Mode = %q, want the request's enforce", s.Mode)
	}
	if s.WorkspaceRoot != "/srv/build" {
		t.Errorf("WorkspaceRoot = %q, want the request's override", s.WorkspaceRoot)
	}
}

// --- sealing and approval -----------------------------------------------------------

// Seal runs the same admission check the daemon and the approval CLI run, so
// one definition of "inadmissible" serves all three. A session governed by an
// envelope the system would refuse to load is a session governed by nothing.
func TestSealRefusesAnInadmissibleEnvelope(t *testing.T) {
	env := testEnvelope("s-1")
	// A denial whose pattern can never match. Critical per
	// validator.entryRole.unmatchable: an unmatchable *denial* fails open, so
	// it refuses admission where the same defect in a grant is only a warning.
	env.Denials = []capability.Grant{{
		Kind:     capability.KindFileWrite,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: []string{"relative/../escape"}},
	}}

	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	if _, err := m.Create(context.Background(), CreateRequest{Envelope: env}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	err := m.Seal(context.Background(), "s-1")
	if !errors.Is(err, ErrEnvelopeInadmissible) {
		t.Fatalf("Seal = %v, want ErrEnvelopeInadmissible", err)
	}
	if got := stateOf(t, m, "s-1"); got != StatePending {
		t.Errorf("state = %s after a refused Seal, want pending", got)
	}
	if env.Sealed {
		t.Error("the envelope was marked sealed despite the refusal")
	}
}

func TestSealMarksTheEnvelopeSealed(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	mustSeal(t, m, id)

	s, _ := m.Get(context.Background(), id)
	if !s.Envelope.Sealed {
		t.Error("the envelope is not marked sealed")
	}
	if s.State != StateReady {
		t.Errorf("state = %s, want ready when no approval is required", s.State)
	}
}

func TestSealAwaitsApprovalWhenRequired(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{RequireApproval: true})
	mustSeal(t, m, id)

	if got := stateOf(t, m, id); got != StateAwaitingApproval {
		t.Fatalf("state = %s, want awaiting_approval", got)
	}
	// Start is the transition this state exists to prevent.
	if err := m.Start(context.Background(), id, 42); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Start on an unapproved session = %v, want refusal", err)
	}
}

// An envelope approved out of band is approved. Demanding a second sign-off for
// the same document is how operators are trained to click through prompts.
func TestSealSkipsApprovalWhenTheEnvelopeCarriesOne(t *testing.T) {
	env := testEnvelope("s-1")
	env.Approval = &ece.ApprovalRecord{ApprovedBy: "ops", ApprovedAt: epoch, Method: "cli"}

	c := newClock()
	m := NewManager(ManagerConfig{RequireApproval: true, Now: c.now})
	if _, err := m.Create(context.Background(), CreateRequest{Envelope: env}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	mustSeal(t, m, "s-1")

	if got := stateOf(t, m, "s-1"); got != StateReady {
		t.Errorf("state = %s, want ready; a pre-approved envelope needs no second sign-off", got)
	}
}

func TestApproveRecordsWhoAndWhen(t *testing.T) {
	m, c, id := managerFor(t, ManagerConfig{RequireApproval: true})
	mustSeal(t, m, id)

	c.advance(90 * time.Second)
	err := m.Approve(context.Background(), id, ece.ApprovalRecord{ApprovedBy: "ops", Method: "cli"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	s, _ := m.Get(context.Background(), id)
	if s.State != StateReady {
		t.Fatalf("state = %s, want ready", s.State)
	}
	if s.Envelope.Approval == nil {
		t.Fatal("the approval was not written onto the envelope")
	}
	if s.Envelope.Approval.ApprovedBy != "ops" {
		t.Errorf("ApprovedBy = %q, want ops", s.Envelope.Approval.ApprovedBy)
	}
	if !s.Envelope.Approval.ApprovedAt.Equal(epoch.Add(90 * time.Second)) {
		t.Errorf("ApprovedAt = %v, want the clock's time when it was stamped", s.Envelope.Approval.ApprovedAt)
	}
}

// An anonymous approval is not an approval. The whole point of the record is
// that somebody is accountable for the decision.
func TestApproveRequiresAnApprover(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{RequireApproval: true})
	mustSeal(t, m, id)

	if err := m.Approve(context.Background(), id, ece.ApprovalRecord{Method: "cli"}); err == nil {
		t.Fatal("an approval naming nobody was accepted")
	}
	if got := stateOf(t, m, id); got != StateAwaitingApproval {
		t.Errorf("state = %s after a refused Approve, want awaiting_approval", got)
	}
}

// --- start ---------------------------------------------------------------------------

func TestStartRequiresARealPID(t *testing.T) {
	for _, pid := range []int32{0, -1} {
		t.Run(fmt.Sprint(pid), func(t *testing.T) {
			m, _, id := managerFor(t, ManagerConfig{})
			drive(t, m, id, StateReady)

			if err := m.Start(context.Background(), id, pid); !errors.Is(err, ErrNoRootPID) {
				t.Fatalf("Start(%d) = %v, want ErrNoRootPID", pid, err)
			}
			if got := stateOf(t, m, id); got != StateReady {
				t.Errorf("state = %s after a refused Start, want ready", got)
			}
		})
	}
}

// Elapsed time in a session constraint and elapsed time in the lifecycle record
// have to be one measurement. Two clocks started moments apart is how a
// duration budget comes to disagree with the audit trail about how long the
// agent ran.
func TestStartFixesOneClockForBothTheSessionAndItsState(t *testing.T) {
	m, c, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateReady)

	c.advance(5 * time.Minute)
	if err := m.Start(context.Background(), id, 4242); err != nil {
		t.Fatalf("Start: %v", err)
	}

	s, _ := m.Get(context.Background(), id)
	want := epoch.Add(5 * time.Minute)
	if !s.StartedAt.Equal(want) {
		t.Errorf("StartedAt = %v, want %v", s.StartedAt, want)
	}

	st, ok := m.State(id)
	if !ok {
		t.Fatal("State returned nothing for a started session")
	}
	c.advance(30 * time.Second)
	if got := st.(*MemoryState).ElapsedSeconds(); got != 30 {
		t.Errorf("ElapsedSeconds = %v, want 30; the tracking state is on a different clock", got)
	}
}

// --- suspend and resume ----------------------------------------------------------------

// Refused rather than recorded. Marking a session suspended while the agent
// keeps running puts a claim in the record that nothing enforced, and a reader
// cannot tell it from a suspension that worked.
func TestSuspendAndResumeRefuseWithoutASupervisor(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)

	err := m.Suspend(context.Background(), id, "approval pending")
	if !errors.Is(err, ErrNoSupervisor) {
		t.Fatalf("Suspend = %v, want ErrNoSupervisor", err)
	}
	if got := stateOf(t, m, id); got != StateActive {
		t.Errorf("state = %s, want active; a refused Suspend must not move it", got)
	}
	if !strings.Contains(err.Error(), "M7") {
		t.Errorf("error = %q, want it to name the milestone that supplies a supervisor", err)
	}
}

func TestSuspendAndResumeDriveTheSupervisor(t *testing.T) {
	sup := &stubSupervisor{}
	m, _, id := managerFor(t, ManagerConfig{Supervisor: sup})
	drive(t, m, id, StateActive)

	if err := m.Suspend(context.Background(), id, "approval pending"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if sup.suspended != 1 {
		t.Errorf("supervisor Suspend called %d times, want 1", sup.suspended)
	}
	if got := stateOf(t, m, id); got != StateSuspended {
		t.Fatalf("state = %s, want suspended", got)
	}

	if err := m.Resume(context.Background(), id); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if sup.resumed != 1 {
		t.Errorf("supervisor Resume called %d times, want 1", sup.resumed)
	}
	if got := stateOf(t, m, id); got != StateActive {
		t.Errorf("state = %s, want active", got)
	}
}

// The tree is stopped first and the state moves only if it worked. A session
// recorded as suspended whose process is still running is a lie; recorded as
// active when the stop failed is the truth.
func TestSupervisorFailureLeavesTheStateAlone(t *testing.T) {
	sup := &stubSupervisor{suspendErr: errors.New("no such process")}
	m, _, id := managerFor(t, ManagerConfig{Supervisor: sup})
	drive(t, m, id, StateActive)

	if err := m.Suspend(context.Background(), id, "test"); err == nil {
		t.Fatal("Suspend succeeded over a failing supervisor")
	}
	if got := stateOf(t, m, id); got != StateActive {
		t.Errorf("state = %s, want active; the tree was never stopped", got)
	}
}

// --- ending -----------------------------------------------------------------------------

func TestEndDefaultsToCompleted(t *testing.T) {
	m, c, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)

	c.advance(time.Minute)
	if err := m.End(context.Background(), id, Outcome{Reason: "agent exited 0"}); err != nil {
		t.Fatalf("End: %v", err)
	}

	s, _ := m.Get(context.Background(), id)
	if s.State != StateCompleted {
		t.Errorf("state = %s, want completed", s.State)
	}
	if s.Outcome.Result != StateCompleted {
		t.Errorf("Outcome.Result = %q, want it filled in with the state it landed in", s.Outcome.Result)
	}
	if s.EndedAt == nil || !s.EndedAt.Equal(epoch.Add(time.Minute)) {
		t.Errorf("EndedAt = %v, want %v", s.EndedAt, epoch.Add(time.Minute))
	}
}

// Terminated, failed, and completed are three different findings about three
// different subjects. The caller says which; nothing here infers it from a
// reason string.
func TestEndRecordsWhichTerminalStateWasMeant(t *testing.T) {
	for _, want := range TerminalStates() {
		t.Run(string(want), func(t *testing.T) {
			m, _, id := managerFor(t, ManagerConfig{})
			drive(t, m, id, StateActive)

			if err := m.End(context.Background(), id, Outcome{Result: want, Reason: "test"}); err != nil {
				t.Fatalf("End: %v", err)
			}
			if got := stateOf(t, m, id); got != want {
				t.Errorf("state = %s, want %s", got, want)
			}
		})
	}
}

func TestEndRefusesANonTerminalResult(t *testing.T) {
	for _, bad := range []State{StateActive, StatePending, StateReady, State("nonsense")} {
		t.Run(string(bad), func(t *testing.T) {
			m, _, id := managerFor(t, ManagerConfig{})
			drive(t, m, id, StateActive)

			if err := m.End(context.Background(), id, Outcome{Result: bad}); !errors.Is(err, ErrBadOutcome) {
				t.Fatalf("End with result %q = %v, want ErrBadOutcome", bad, err)
			}
			if got := stateOf(t, m, id); got != StateActive {
				t.Errorf("state = %s after a refused End, want active", got)
			}
		})
	}
}

// A session can fail before it ever starts -- an inadmissible envelope, a shim
// that never launched, a daemon shutting down mid-approval. A lifecycle that
// could only end started sessions would leave those in a non-terminal state
// forever.
func TestASessionCanEndBeforeItStarts(t *testing.T) {
	for _, from := range []State{StatePending, StateAwaitingApproval, StateReady} {
		t.Run(string(from), func(t *testing.T) {
			cfg := ManagerConfig{}
			if from == StateAwaitingApproval {
				cfg.RequireApproval = true
			}
			m, _, id := managerFor(t, cfg)
			drive(t, m, id, from)

			err := m.End(context.Background(), id, Outcome{Result: StateFailed, Reason: "daemon shutdown"})
			if err != nil {
				t.Fatalf("End from %s: %v", from, err)
			}
			if got := stateOf(t, m, id); got != StateFailed {
				t.Errorf("state = %s, want failed", got)
			}
		})
	}
}

// The summary is captured at End because that is the moment the session's
// writer goroutine has stopped. Before then it is zero, which is a documented
// limitation rather than an accident.
func TestEndCapturesTheSummary(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)

	st, ok := m.State(id)
	if !ok {
		t.Fatal("State returned nothing")
	}
	for i := 0; i < 3; i++ {
		st.RecordEvent(&event.Event{
			ID:         fmt.Sprintf("e-%d", i),
			SessionID:  id,
			Capability: capability.KindFileRead,
			Domain:     capability.DomainFilesystem,
			WallClock:  epoch.Add(time.Duration(i) * time.Second),
		})
	}

	live, _ := m.Get(context.Background(), id)
	if live.Summary.EventsObserved != 0 {
		t.Errorf("Summary.EventsObserved = %d on a running session, want 0; "+
			"a live summary is a documented limitation", live.Summary.EventsObserved)
	}

	if err := m.End(context.Background(), id, Outcome{Reason: "done"}); err != nil {
		t.Fatalf("End: %v", err)
	}
	ended, _ := m.Get(context.Background(), id)
	if ended.Summary.EventsObserved != 3 {
		t.Errorf("Summary.EventsObserved = %d after End, want 3", ended.Summary.EventsObserved)
	}
}

// --- queries ------------------------------------------------------------------------------

// Handing out a pointer into the manager's map would give every caller a read
// into state another goroutine is writing. Get returns a copy, and mutating it
// must not reach back.
func TestGetReturnsACopy(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})
	drive(t, m, id, StateActive)
	if err := m.End(context.Background(), id, Outcome{Reason: "done"}); err != nil {
		t.Fatalf("End: %v", err)
	}

	first, _ := m.Get(context.Background(), id)
	first.State = StateFailed
	first.RootPID = 1
	first.Outcome.Reason = "tampered"
	if first.Summary.CapabilityUsage != nil {
		first.Summary.CapabilityUsage[capability.KindFileRead] = 999
	}
	if first.EndedAt != nil {
		*first.EndedAt = epoch.Add(time.Hour)
	}

	second, _ := m.Get(context.Background(), id)
	if second.State != StateCompleted {
		t.Errorf("State = %s, want completed; the copy was not a copy", second.State)
	}
	if second.RootPID != 4242 {
		t.Errorf("RootPID = %d, want 4242", second.RootPID)
	}
	if second.Outcome.Reason != "done" {
		t.Errorf("Outcome.Reason = %q, want done", second.Outcome.Reason)
	}
	if second.EndedAt != nil && second.EndedAt.Equal(epoch.Add(time.Hour)) {
		t.Error("EndedAt was mutated through the returned pointer")
	}
	if n := second.Summary.CapabilityUsage[capability.KindFileRead]; n == 999 {
		t.Error("the summary map was shared with the caller")
	}
}

func TestGetAndStateReportMissingSessions(t *testing.T) {
	m := NewManager(ManagerConfig{})

	if _, err := m.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get = %v, want ErrNotFound", err)
	}
	if _, ok := m.State("nope"); ok {
		t.Error("State reported a tracking state for a session that does not exist")
	}
	for _, a := range AllActions() {
		if err := attempt(m, "nope", a); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a missing session = %v, want ErrNotFound", a, err)
		}
	}
}

func TestListIsOrderedAndFiltered(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	// Created out of alphabetical order so the ordering assertion is about
	// CreatedAt rather than about the map or the IDs.
	for _, id := range []string{"s-c", "s-a", "s-b"} {
		if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		c.advance(time.Minute)
	}
	mustSeal(t, m, "s-a")

	all, err := m.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := ids(all); !equal(got, []string{"s-c", "s-a", "s-b"}) {
		t.Errorf("order = %v, want creation order", got)
	}

	ready, _ := m.List(ctx, Filter{State: StateReady})
	if got := ids(ready); !equal(got, []string{"s-a"}) {
		t.Errorf("State filter = %v, want [s-a]", got)
	}

	// Since is inclusive, Until exclusive, both on CreatedAt.
	window, _ := m.List(ctx, Filter{Since: epoch.Add(time.Minute), Until: epoch.Add(2 * time.Minute)})
	if got := ids(window); !equal(got, []string{"s-a"}) {
		t.Errorf("time window = %v, want [s-a]", got)
	}

	limited, _ := m.List(ctx, Filter{Limit: 2})
	if got := ids(limited); !equal(got, []string{"s-c", "s-a"}) {
		t.Errorf("Limit = %v, want the first two in order", got)
	}
}

// A pending session that never started has no StartedAt at all. Filtering a
// time window on it would silently hide exactly the sessions someone querying a
// window is most likely to want -- the ones that failed before they began.
func TestListWindowsOnCreatedAtNotStartedAt(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope("s-never-started")}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, _ := m.List(ctx, Filter{Since: epoch.Add(-time.Hour), Until: epoch.Add(time.Hour)})
	if len(got) != 1 {
		t.Fatalf("List returned %d sessions, want the never-started one", len(got))
	}
}

func TestListReturnsCopies(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})

	first, _ := m.List(context.Background(), Filter{})
	first[0].State = StateTerminated

	second, _ := m.List(context.Background(), Filter{})
	if second[0].State != StatePending {
		t.Errorf("State = %s, want pending; List handed out the live record", second[0].State)
	}
	_ = id
}

// --- state handoff -------------------------------------------------------------------------

// The one thing handed out by reference rather than by copy, deliberately: it
// is what a pipeline writes through, and a copy would be a pipeline recording
// into nothing.
func TestStateIsSharedNotCopied(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})

	first, ok := m.State(id)
	if !ok {
		t.Fatal("State returned nothing")
	}
	first.RecordEvent(&event.Event{
		ID: "e-1", SessionID: id,
		Capability: capability.KindFileRead, Domain: capability.DomainFilesystem,
		WallClock: epoch,
	})

	second, _ := m.State(id)
	if got := second.Snapshot().EventsObserved; got != 1 {
		t.Errorf("EventsObserved = %d through a second handle, want 1; the state was copied", got)
	}
}

// The manager sizes the tracking state from the session's own envelope, so a
// grant budget is charged against the grants that actually govern the session.
func TestStateIsBoundToTheSessionEnvelope(t *testing.T) {
	m, _, id := managerFor(t, ManagerConfig{})

	st, _ := m.State(id)
	ms := st.(*MemoryState)
	if ms.SessionID() != id {
		t.Errorf("SessionID = %q, want %q", ms.SessionID(), id)
	}
	ms.RecordGrantUse(0)
	if got := ms.GrantUseCount(0); got != 1 {
		t.Errorf("GrantUseCount(0) = %d, want 1; the state has no grant slots", got)
	}
}

// --- concurrency ---------------------------------------------------------------------------

// A manager is genuinely shared, unlike MemoryState: an IPC handler creates
// sessions, a shim starts them, a supervisor ends them, and a status query
// lists them, all on different goroutines. This is written to be meaningful
// under -race; without the detector it pins that every session survives the
// crossfire and lands in a legal state.
func TestConcurrentLifecycleOperations(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now, Supervisor: &stubSupervisor{}})
	ctx := context.Background()

	const n = 24
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("s-%02d", i)
			if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
				t.Errorf("Create %s: %v", id, err)
				return
			}
			if err := m.Seal(ctx, id); err != nil {
				t.Errorf("Seal %s: %v", id, err)
				return
			}
			if err := m.Start(ctx, id, int32(1000+i)); err != nil {
				t.Errorf("Start %s: %v", id, err)
				return
			}
			if err := m.End(ctx, id, Outcome{Reason: "done"}); err != nil {
				t.Errorf("End %s: %v", id, err)
			}
		}(i)
	}

	// Readers running against the churn, which is where a returned pointer into
	// the live record would show up as a race.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sessions, err := m.List(ctx, Filter{})
				if err != nil {
					t.Errorf("List: %v", err)
					return
				}
				for _, s := range sessions {
					if s.State == "" {
						t.Error("a listed session has no state")
					}
					_, _ = m.Get(ctx, s.ID)
					_, _ = m.State(s.ID)
				}
			}
		}()
	}
	wg.Wait()

	if m.Len() != n {
		t.Fatalf("manager holds %d sessions, want %d", m.Len(), n)
	}
	final, _ := m.List(ctx, Filter{})
	for _, s := range final {
		if s.State != StateCompleted {
			t.Errorf("%s ended in %s, want completed", s.ID, s.State)
		}
	}
}

// Two goroutines racing to create the same session: exactly one wins, and the
// loser is told so rather than silently taking over.
func TestConcurrentCreateOfTheSameSessionHasOneWinner(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})

	const racers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var created, refused int

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Create(context.Background(), CreateRequest{Envelope: testEnvelope("s-1")})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case errors.Is(err, ErrExists):
				refused++
			default:
				t.Errorf("Create: %v", err)
			}
		}()
	}
	wg.Wait()

	if created != 1 {
		t.Errorf("%d creates succeeded, want exactly 1", created)
	}
	if refused != racers-1 {
		t.Errorf("%d creates were refused, want %d", refused, racers-1)
	}
	if m.Len() != 1 {
		t.Errorf("manager holds %d sessions, want 1", m.Len())
	}
}

// --- helpers ---------------------------------------------------------------------------------

func ids(sessions []*Session) []string {
	out := make([]string, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.ID)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- benchmarks ---------------------------------------------------------------------------------

// The whole lifecycle of one session. Not a hot path -- this runs once or twice
// per agent invocation rather than once per syscall -- measured so that a
// daemon creating many short sessions has a number rather than an assumption.
func BenchmarkSessionLifecycle(b *testing.B) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("s-%d", i)
		if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
			b.Fatalf("Create: %v", err)
		}
		if err := m.Seal(ctx, id); err != nil {
			b.Fatalf("Seal: %v", err)
		}
		if err := m.Start(ctx, id, 1); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if err := m.End(ctx, id, Outcome{Reason: "done"}); err != nil {
			b.Fatalf("End: %v", err)
		}
	}
}

// Get is what a status query calls, and it copies. This is the cost of that
// copy against a session with a populated summary.
func BenchmarkGet(b *testing.B) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope("s-1")}); err != nil {
		b.Fatalf("Create: %v", err)
	}
	if err := m.Seal(ctx, "s-1"); err != nil {
		b.Fatalf("Seal: %v", err)
	}
	if err := m.Start(ctx, "s-1", 1); err != nil {
		b.Fatalf("Start: %v", err)
	}
	st, _ := m.State("s-1")
	st.RecordEvent(&event.Event{
		ID: "e-1", SessionID: "s-1",
		Capability: capability.KindFileRead, Domain: capability.DomainFilesystem,
		WallClock: epoch,
	})
	if err := m.End(ctx, "s-1", Outcome{Reason: "done"}); err != nil {
		b.Fatalf("End: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Get(ctx, "s-1"); err != nil {
			b.Fatalf("Get: %v", err)
		}
	}
}
