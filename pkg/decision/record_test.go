package decision

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every line names its kind first, written by the type itself, so no producer
// can emit a line without one.
func TestEveryLineNamesItsKindFirst(t *testing.T) {
	values := map[RecordKind]any{
		RecordDecision:       Decision{ID: "d1"},
		RecordSessionStart:   SessionStart{SessionID: "s1"},
		RecordApproval:       Approval{SessionID: "s1"},
		RecordControlRefused: ControlRefused{Method: "CreateSession"},
		RecordSessionEnd:     SessionEnd{SessionID: "s1"},
	}
	if len(values) != len(AllRecordKinds()) {
		t.Fatalf("%d kinds tested, %d declared", len(values), len(AllRecordKinds()))
	}
	for _, kind := range AllRecordKinds() {
		v, ok := values[kind]
		if !ok {
			t.Errorf("kind %q has no test value", kind)
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if prefix := `{"record":"` + string(kind) + `",`; !strings.HasPrefix(string(b), prefix) {
			t.Errorf("%s does not start with %s\ngot: %s", kind, prefix, b)
		}
		if got, err := KindOf(b); err != nil || got != kind {
			t.Errorf("KindOf(%s) = %q, %v", kind, got, err)
		}
		if r, ok := v.(Record); ok && r.RecordKind() != kind {
			t.Errorf("%T.RecordKind() = %q, want %q", v, r.RecordKind(), kind)
		}
	}
}

// Reading a line as the wrong type fails loudly. Without this a session record
// read as a decision would come back as a decision with only a session ID.
func TestALineOfAnotherKindIsRefused(t *testing.T) {
	start, _ := json.Marshal(SessionStart{SessionID: "s1"})
	dec, _ := json.Marshal(Decision{ID: "d1", SessionID: "s1"})

	var d Decision
	if err := json.Unmarshal(start, &d); err == nil {
		t.Errorf("a session_start line decoded as a decision: %+v", d)
	}
	for name, into := range map[string]any{
		"SessionStart": new(SessionStart), "Approval": new(Approval),
		"ControlRefused": new(ControlRefused), "SessionEnd": new(SessionEnd),
	} {
		if err := json.Unmarshal(dec, into); err == nil {
			t.Errorf("a decision line decoded as %s", name)
		}
	}
}

// A decision written before the discriminator existed still decodes; only a
// line that names a different kind is refused.
func TestADecisionWithoutAKindStillDecodes(t *testing.T) {
	var d Decision
	if err := json.Unmarshal([]byte(`{"id":"d1","session_id":"s1","verdict":"within_envelope"}`), &d); err != nil {
		t.Fatalf("decoding a kindless decision: %v", err)
	}
	if d.ID != "d1" || d.Verdict != VerdictWithinEnvelope {
		t.Errorf("decoded %+v", d)
	}
	if _, err := KindOf([]byte(`{"id":"d1"}`)); !errors.Is(err, ErrNoRecordKind) {
		t.Errorf("KindOf on a kindless line = %v, want ErrNoRecordKind", err)
	}
}

// The schema's kind enum and each record's const have to agree with the Go
// vocabulary, or a consumer validating against the schema rejects lines this
// build writes.
func TestRecordKindsMatchTheSchema(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", "api", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	type constProp struct {
		Properties struct {
			Record struct {
				Const string `json:"const"`
			} `json:"record"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	var audit struct {
		Defs struct {
			RecordKind struct {
				Enum []string `json:"enum"`
			} `json:"recordKind"`
			SessionStart   constProp `json:"sessionStart"`
			Approval       constProp `json:"approval"`
			ControlRefused constProp `json:"controlRefused"`
			SessionEnd     constProp `json:"sessionEnd"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(read("audit.v1alpha2.schema.json"), &audit); err != nil {
		t.Fatal(err)
	}
	var dec constProp
	if err := json.Unmarshal(read("decision.v1alpha2.schema.json"), &dec); err != nil {
		t.Fatal(err)
	}

	enum := audit.Defs.RecordKind.Enum
	kinds := AllRecordKinds()
	if len(enum) != len(kinds) {
		t.Fatalf("schema enum %v, Go kinds %v", enum, kinds)
	}
	for i, k := range kinds {
		if enum[i] != string(k) {
			t.Errorf("schema enum[%d] = %q, Go kind %q", i, enum[i], k)
		}
	}

	for kind, def := range map[RecordKind]constProp{
		RecordDecision:       dec,
		RecordSessionStart:   audit.Defs.SessionStart,
		RecordApproval:       audit.Defs.Approval,
		RecordControlRefused: audit.Defs.ControlRefused,
		RecordSessionEnd:     audit.Defs.SessionEnd,
	} {
		if def.Properties.Record.Const != string(kind) {
			t.Errorf("schema const for %s = %q", kind, def.Properties.Record.Const)
		}
		required := false
		for _, r := range def.Required {
			required = required || r == "record"
		}
		if !required {
			t.Errorf("schema for %s does not require the record field", kind)
		}
	}
}
