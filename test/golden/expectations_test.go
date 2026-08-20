package golden

import (
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// expected is what the deterministic core concludes about each committed
// recording, written out in Go beside the bytes it concludes them in.
//
// The golden files already pin all of this and more. This table exists because
// a regenerated golden is a diff of twenty JSON objects, and a reviewer skimming
// one can accept a flipped verdict as noise far more easily than they can accept
// a deleted line here. Editing an entry below is a deliberate act with a reason
// attached; regenerating a file is one command.
//
// What is *not* here is any restatement of how a number was reached. No weight,
// threshold, matcher rule, or rule-set priority appears — those belong to
// internal/risk and internal/policy and are tested there. What appears is the
// system's conclusion per event, which is the one thing no single-component test
// can see.
var expected = map[string][]finding{

	// git-operation: `git commit -am` under an envelope granting the workspace
	// and denying CI configuration inside it.
	//
	// Seven of the ten events are the common case and score zero, which is the
	// point: a governance system that finds something in every event of an
	// ordinary commit is a system nobody will leave enabled. The two findings
	// are the two the recording was built to produce.
	"git-operation": {
		{EventID: "gt-001", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "gt-002", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "gt-003", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "gt-004", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "gt-005", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},

		// gt-006 writes .git/index. Expected for a commit, granted by the
		// workspace pattern, and deliberately *not* caught by the .github
		// denial beside it — the two paths differ by four characters and a
		// matcher that confused them would be a security defect in either
		// direction.
		{EventID: "gt-006", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "gt-007", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},

		// gt-008 writes .github/workflows/release.yml: supply-chain tampering
		// through CI configuration. The denial wins over the workspace-wide
		// write grant that would otherwise have covered it, and denial is the
		// heaviest single verdict contribution the model has.
		{EventID: "gt-008", SessionID: "s-git", Verdict: decision.VerdictExplicitlyDenied,
			Score: 75, Level: decision.LevelHigh, Rule: "envelope-explicit-denial", Action: ece.ActionBlock,
			Factors: []string{"verdict", "violation_severity", "sensitive_path", "novel_target", "evidence_basis"},
			Evidence: map[string]string{
				"verdict": "explicitly_denied",
				"target":  "/home/dev/project/.github/workflows/release.yml",
			}},

		// gt-009 is a *failed* read of a private SSH key. The syscall returned
		// ENOENT and the finding stands anyway: the resource was reached for,
		// and an agent repeatedly failing to open credential material is more
		// alarming than one that succeeds once. grant_exceeded rather than
		// outside_envelope, because fs.read was granted and the target was not.
		{EventID: "gt-009", SessionID: "s-git", Verdict: decision.VerdictGrantExceeded,
			Score: 81, Level: decision.LevelHigh, Rule: "credential-access-high-risk", Action: ece.ActionRequestApproval,
			Factors: []string{"verdict", "violation_severity", "sensitive_path", "workspace_escape",
				"novel_target", "violation_history", "evidence_basis"},
			Evidence: map[string]string{
				"target":      "/home/dev/.ssh/id_rsa",
				"sensitivity": "critical",
				"observed":    "/home/dev/.ssh/id_rsa",
			}},
		{EventID: "gt-010", SessionID: "s-git", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
	},

	// credential-egress: the pattern the system most wants to catch, with every
	// near-miss placed beside it.
	//
	// This is the case that makes the golden worth having. Four of these ten
	// decisions depend on *session history* rather than on the event alone —
	// the sequence detector's antecedent, the novelty of a target, the running
	// violation count — so a change to when the pipeline commits state, or to
	// the order events are processed in, moves numbers here and nowhere else.
	"credential-egress": {
		{EventID: "ex-001", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
		{EventID: "ex-002", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},

		// ex-003 reads ~/.aws/credentials and succeeds. The only qualifying
		// antecedent in the recording, and everything the sequence detector
		// later says points back at this event ID.
		{EventID: "ex-003", SessionID: "s-exfil", Verdict: decision.VerdictGrantExceeded,
			Score: 80, Level: decision.LevelHigh, Rule: "credential-access-high-risk", Action: ece.ActionRequestApproval,
			Factors: []string{"verdict", "violation_severity", "sensitive_path", "workspace_escape",
				"novel_target", "evidence_basis"},
			Evidence: map[string]string{
				"target":      "/home/dev/.aws/credentials",
				"sensitivity": "critical",
			}},

		// ex-004 reads /etc/passwd and succeeds. Rated medium — identity, read
		// constantly through getpwnam — so it lands on a warning rather than a
		// prompt, and it must never qualify as the sequence detector's first
		// half. A detector that fired here would fire on most sessions that
		// touch the network.
		{EventID: "ex-004", SessionID: "s-exfil", Verdict: decision.VerdictGrantExceeded,
			Score: 64, Level: decision.LevelHigh, Rule: "medium-risk-departure", Action: ece.ActionWarn,
			Factors: []string{"verdict", "violation_severity", "sensitive_path", "workspace_escape",
				"novel_target", "violation_history", "evidence_basis"},
			Evidence: map[string]string{
				"target":      "/etc/passwd",
				"sensitivity": "medium",
			}},

		// ex-005 reads ~/.ssh/id_ed25519 and *fails*. sensitive_path still
		// charges the full critical grade — the resource was reached for — while
		// the sequence detector rejects it as an antecedent, because an ENOENT
		// disclosed nothing and there is nothing that could subsequently leave.
		// The two factors ask different questions, and this is where the
		// difference is visible in the record.
		{EventID: "ex-005", SessionID: "s-exfil", Verdict: decision.VerdictGrantExceeded,
			Score: 82, Level: decision.LevelHigh, Rule: "credential-access-high-risk", Action: ece.ActionRequestApproval,
			Factors: []string{"verdict", "violation_severity", "sensitive_path", "workspace_escape",
				"novel_target", "violation_history", "evidence_basis"},
			Evidence: map[string]string{
				"target":      "/home/dev/.ssh/id_ed25519",
				"sensitivity": "critical",
			}},

		// ex-006 is a DNS lookup. Egress is net.connect and net.send; resolving
		// a name is not a channel out of the host, so the detector reports
		// nothing at all here rather than reporting a finding worth zero.
		{EventID: "ex-006", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_host", "evidence_basis"}},

		// ex-007 and ex-008 are egress the envelope granted. The sequence is
		// found and reported on both — the evidence names ex-003 — and
		// contributes exactly zero points, with not_charged saying why. An
		// event a grant covered scores zero however alarming its shape.
		{EventID: "ex-007", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_host", "credential_access_egress", "evidence_basis"},
			Evidence: map[string]string{
				"access_event_id": "ex-003",
				"not_charged":     "the envelope covered this operation",
			}},
		{EventID: "ex-008", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_host", "credential_access_egress", "evidence_basis"},
			Evidence: map[string]string{
				"access_event_id":   "ex-003",
				"egress_capability": "net.send",
			}},

		// ex-009 connects to an address no DNS answer covers, under an envelope
		// granting net.connect by hostname. The validator cannot tell whether
		// that address *is* the granted host, so the verdict is indeterminate
		// rather than a mismatch — unresolved is not safe, and it is not a
		// finding about the agent either.
		//
		// This is the event the sequence detector moves. Without it the score
		// sits low enough for a warning; with 30 points of
		// credential_access_egress it reaches indeterminate-high-risk and a
		// human is asked. It is the single best demonstration in the corpus
		// that the composition does something the parts do not.
		{EventID: "ex-009", SessionID: "s-exfil", Verdict: decision.VerdictIndeterminate,
			Score: 78, Level: decision.LevelHigh, Rule: "indeterminate-high-risk", Action: ece.ActionRequestApproval,
			Factors: []string{"verdict", "violation_severity", "sensitive_host", "uncorrelated_destination",
				"credential_access_egress", "novel_target", "violation_history", "evidence_basis"},
			Evidence: map[string]string{
				"access_event_id": "ex-003",
				"correlation":     "missing",
				"dest_ip":         "198.51.100.77",
				"distance_events": "6",
			}},
		{EventID: "ex-010", SessionID: "s-exfil", Verdict: decision.VerdictWithinEnvelope,
			Score: 0, Level: decision.LevelNone, Rule: "within-envelope", Action: ece.ActionAllow,
			Factors: []string{"verdict", "sensitive_path", "evidence_basis"}},
	},
}
