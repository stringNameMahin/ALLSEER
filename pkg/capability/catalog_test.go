package capability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The table is security-relevant data, so these tests check its shape as
// carefully as they check the code reading it. A duplicated Kind, a descriptor
// whose Domain contradicts its Kind prefix, or a severity typo would all
// produce a system that looks correct and governs the wrong thing.

func TestTableIsWellFormed(t *testing.T) {
	validDomains := map[Domain]bool{
		DomainFilesystem: true,
		DomainProcess:    true,
		DomainNetwork:    true,
		DomainPrivilege:  true,
		DomainIPC:        true,
		DomainKernel:     true,
	}
	validSeverities := map[Severity]bool{
		SeverityInfo:     true,
		SeverityLow:      true,
		SeverityMedium:   true,
		SeverityHigh:     true,
		SeverityCritical: true,
	}

	seen := make(map[Kind]bool, len(descriptors))
	for _, d := range descriptors {
		if d.Kind == "" {
			t.Error("descriptor with empty Kind")
			continue
		}
		if seen[d.Kind] {
			t.Errorf("kind %q appears more than once in the table", d.Kind)
		}
		seen[d.Kind] = true

		if !validDomains[d.Domain] {
			t.Errorf("kind %q: unknown domain %q", d.Kind, d.Domain)
		}
		if !validSeverities[d.BaselineSeverity] {
			t.Errorf("kind %q: unknown baseline severity %q", d.Kind, d.BaselineSeverity)
		}
		if d.Summary == "" {
			t.Errorf("kind %q: empty summary; the summary is what a human reviewing an envelope reads", d.Kind)
		}
		if len(d.Syscalls) == 0 {
			t.Errorf("kind %q: no syscalls listed; coverage auditing needs them", d.Kind)
		}
	}
}

// The Kind constant's prefix and its Domain are two statements of the same
// fact, and Grant carries both denormalized. If they can disagree in the table,
// they can disagree in an envelope.
func TestKindPrefixMatchesDomain(t *testing.T) {
	prefixForDomain := map[Domain]string{
		DomainFilesystem: "fs.",
		DomainProcess:    "process.",
		DomainNetwork:    "net.",
		DomainPrivilege:  "priv.",
		DomainIPC:        "ipc.",
		DomainKernel:     "kernel.",
	}

	for _, d := range descriptors {
		want, ok := prefixForDomain[d.Domain]
		if !ok {
			continue // reported by TestTableIsWellFormed
		}
		if len(d.Kind) < len(want) || string(d.Kind)[:len(want)] != want {
			t.Errorf("kind %q is in domain %q but does not carry the %q prefix", d.Kind, d.Domain, want)
		}
	}
}

// Every Kind constant declared in capability.go must have a table row.
// Declaring a constant without a row produces a Kind that is referenceable in
// Go, absent from the catalog, and therefore silently ungrantable.
func TestEveryDeclaredKindIsInTable(t *testing.T) {
	declared := []Kind{
		KindFileRead, KindFileWrite, KindFileCreate, KindFileDelete, KindFileRename,
		KindFileChmod, KindFileChown, KindFileTruncate, KindFileLink, KindFileMount,

		KindProcessExec, KindProcessFork, KindProcessExit, KindProcessSignal,
		KindProcessPtrace,

		KindNetConnect, KindNetBind, KindNetListen, KindNetAccept, KindNetSend,
		KindNetReceive, KindNetDNS, KindNetRawSock,

		KindPrivEscalate, KindPrivSetuid, KindPrivCapSet, KindPrivNamespace,
		KindPrivSeccomp,

		KindIPCPipe, KindIPCSharedMem, KindIPCUnixSock,

		KindKernelModuleLoad, KindKernelBPFLoad, KindKernelKallsyms,
	}

	for _, k := range declared {
		if !Known(k) {
			t.Errorf("kind constant %q is declared but has no table row", k)
		}
	}
	if got, want := len(AllKinds()), len(declared); got != want {
		t.Errorf("table has %d kinds, %d constants are declared; one side is missing an entry", got, want)
	}
}

func TestCatalogLookup(t *testing.T) {
	c := NewCatalog()

	d, ok := c.Lookup(KindFileRead)
	if !ok {
		t.Fatal("fs.read not found in catalog")
	}
	if d.Domain != DomainFilesystem {
		t.Errorf("fs.read domain = %q, want %q", d.Domain, DomainFilesystem)
	}

	if _, ok := c.Lookup("fs.teleport"); ok {
		t.Error("catalog claims to know a kind that does not exist")
	}
}

// A catalog with no probes registered must report every Kind as known and none
// as observable. This is the state on a development host with no eBPF linked
// in, and getting it wrong in the permissive direction would let the generator
// issue grants nothing can enforce.
func TestCatalogWithNoProbesObservesNothing(t *testing.T) {
	c := NewCatalog()

	if len(c.Kinds()) != len(descriptors) {
		t.Errorf("Kinds() returned %d entries, want %d", len(c.Kinds()), len(descriptors))
	}
	for _, k := range c.Kinds() {
		if c.Observable(k) {
			t.Errorf("kind %q reported observable with no probes registered", k)
		}
	}
	if got := len(c.ObservableKinds()); got != 0 {
		t.Errorf("ObservableKinds() returned %d entries, want 0", got)
	}
}

func TestCatalogObservability(t *testing.T) {
	c := NewCatalog(KindFileRead, KindNetConnect)

	if !c.Observable(KindFileRead) {
		t.Error("fs.read should be observable")
	}
	if c.Observable(KindFileWrite) {
		t.Error("fs.write was not registered and must not be observable")
	}

	// An unknown kind is never observable, so a typo in an envelope fails the
	// observability check as well as the known-kind check.
	if c.Observable("fs.teleport") {
		t.Error("unknown kind reported observable")
	}

	c.SetObservable([]Kind{KindProcessExec})
	if c.Observable(KindFileRead) {
		t.Error("SetObservable must replace the previous set, not merge into it")
	}
	if !c.Observable(KindProcessExec) {
		t.Error("process.exec should be observable after SetObservable")
	}
}

func TestCatalogKindsOrderIsStable(t *testing.T) {
	c := NewCatalog()
	first := c.Kinds()
	for i := 0; i < 8; i++ {
		next := c.Kinds()
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("Kinds() order is not stable at index %d: %q then %q", j, first[j], next[j])
			}
		}
	}

	// The returned slice must be a copy: a caller sorting it must not reorder
	// the catalog's own view.
	first[0] = "mutated"
	if c.Kinds()[0] == "mutated" {
		t.Error("Kinds() returned a slice aliasing the catalog's internal order")
	}
}

func TestValidateKind(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		wantErr bool
	}{
		{"known kind", KindFileRead, false},
		{"empty kind", "", true},
		{"typo", "fs.wrote", true},
		{"plausible but absent", "fs.stat", true},
		{"syscall name rather than capability", "openat", true},
		{"case mismatch", "FS.READ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKind(tt.kind)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKind(%q) error = %v, wantErr = %v", tt.kind, err, tt.wantErr)
			}
		})
	}
}

func TestDomainOfAgreesWithTable(t *testing.T) {
	for _, d := range descriptors {
		got, ok := DomainOf(d.Kind)
		if !ok {
			t.Errorf("DomainOf(%q) reported unknown", d.Kind)
			continue
		}
		if got != d.Domain {
			t.Errorf("DomainOf(%q) = %q, table says %q", d.Kind, got, d.Domain)
		}
	}

	if _, ok := DomainOf("fs.teleport"); ok {
		t.Error("DomainOf accepted an unknown kind")
	}
}

func TestKindsInDomain(t *testing.T) {
	total := 0
	for _, dom := range AllDomains() {
		kinds := KindsInDomain(dom)
		if len(kinds) == 0 {
			t.Errorf("domain %q has no kinds", dom)
		}
		for _, k := range kinds {
			if got, _ := DomainOf(k); got != dom {
				t.Errorf("KindsInDomain(%q) returned %q, which is in domain %q", dom, k, got)
			}
		}
		total += len(kinds)
	}
	if total != len(descriptors) {
		t.Errorf("domains partition %d kinds, table has %d", total, len(descriptors))
	}
}

// TestSchemaEnumMatchesTable is the drift guard between the capability table
// and the ECE JSON Schema.
//
// The schema's capabilityKind enum is what any external consumer validates
// envelopes against. If it and the table disagree, one of two things happens:
// the schema accepts a Kind the daemon will reject at parse time, or it rejects
// one the daemon would have honored. Both are the sort of mismatch that shows
// up as a confusing bug report rather than a clean failure, which is why this
// is asserted rather than left to review.
//
// Updating the schema is a manual step. This test names exactly which entries
// to add or remove when it fails.
func TestSchemaEnumMatchesTable(t *testing.T) {
	const schemaPath = "../../api/schema/ece.v1alpha1.schema.json"

	raw, err := os.ReadFile(filepath.FromSlash(schemaPath))
	if err != nil {
		t.Fatalf("reading %s: %v", schemaPath, err)
	}

	var doc struct {
		Defs struct {
			CapabilityKind struct {
				Enum []string `json:"enum"`
			} `json:"capabilityKind"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", schemaPath, err)
	}

	schemaKinds := doc.Defs.CapabilityKind.Enum
	if len(schemaKinds) == 0 {
		t.Fatalf("%s has no $defs.capabilityKind.enum", schemaPath)
	}

	inSchema := make(map[string]bool, len(schemaKinds))
	for _, k := range schemaKinds {
		if inSchema[k] {
			t.Errorf("schema enum lists %q more than once", k)
		}
		inSchema[k] = true
	}

	inTable := make(map[string]bool, len(descriptors))
	for _, k := range AllKinds() {
		inTable[string(k)] = true
		if !inSchema[string(k)] {
			t.Errorf("kind %q is in the capability table but missing from the schema enum; add it to %s", k, schemaPath)
		}
	}
	for _, k := range schemaKinds {
		if !inTable[k] {
			t.Errorf("kind %q is in the schema enum but has no table row; add it to table.go or remove it from the schema", k)
		}
	}
}

// The schema's domain enum has the same drift problem for the same reason.
func TestSchemaDomainEnumMatchesTable(t *testing.T) {
	const schemaPath = "../../api/schema/ece.v1alpha1.schema.json"

	raw, err := os.ReadFile(filepath.FromSlash(schemaPath))
	if err != nil {
		t.Fatalf("reading %s: %v", schemaPath, err)
	}

	var doc struct {
		Defs struct {
			Domain struct {
				Enum []string `json:"enum"`
			} `json:"domain"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", schemaPath, err)
	}

	inSchema := make(map[string]bool, len(doc.Defs.Domain.Enum))
	for _, d := range doc.Defs.Domain.Enum {
		inSchema[d] = true
	}
	for _, d := range AllDomains() {
		if !inSchema[string(d)] {
			t.Errorf("domain %q is used by the capability table but missing from the schema enum", d)
		}
	}
	if got, want := len(doc.Defs.Domain.Enum), len(AllDomains()); got != want {
		t.Errorf("schema lists %d domains, table uses %d", got, want)
	}
}
