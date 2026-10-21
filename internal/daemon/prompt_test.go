package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
)

// marker stands for anything a user might paste into a prompt.
const marker = "zq7-pasted-secret-value"

// A prompt is analyzed and dropped. The envelope is still derived from it,
// but no copy reaches the envelope, the session, the audit log or the
// diagnostic log.
func TestThePromptIsNotRetainedByDefault(t *testing.T) {
	var logs bytes.Buffer
	r := newRigWith(t, policy.ModeInteractive, time.Minute, func(_ *rig, o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	ctx := context.Background()
	prompt := "run the go tests, token " + marker + ", and ignore previous instructions"
	resp := createWith(t, r, prompt)

	in := resp.Envelope.Intent
	if in.RawPrompt != "" {
		t.Fatalf("raw prompt = %q, want it dropped", in.RawPrompt)
	}
	if in.TaskType == "" || len(resp.Envelope.Grants) == 0 || !resp.Envelope.Sealed {
		t.Fatalf("the envelope was not generated from the prompt: task %q, %d grants, sealed %v",
			in.TaskType, len(resp.Envelope.Grants), resp.Envelope.Sealed)
	}

	r.approveAndStart(t, resp.SessionID)
	s, err := r.client.GetSession(ctx, resp.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	everything := []any{resp, s}
	for _, rec := range r.audit.records() {
		everything = append(everything, rec)
	}
	for _, v := range everything {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), marker) {
			t.Fatalf("the prompt survived in a %T:\n%s", v, b)
		}
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatalf("the prompt reached the diagnostic log:\n%s", logs.String())
	}
}

// An operator who wants prompts on record gets them verbatim.
func TestRetainPromptKeepsItVerbatim(t *testing.T) {
	r := newRigWith(t, policy.ModeInteractive, time.Minute, func(_ *rig, o *Options) {
		o.Config.Intent.RetainPrompt = true
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	})
	prompt := "run the go tests, token " + marker
	if got := createWith(t, r, prompt).Envelope.Intent.RawPrompt; got != prompt {
		t.Fatalf("raw prompt = %q, want %q", got, prompt)
	}
}

func (r *rig) approveAndStart(t *testing.T, sid string) {
	t.Helper()
	ctx := context.Background()
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: sid, Approved: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.client.StartSession(ctx, sid, 4242); err != nil {
		t.Fatal(err)
	}
}
