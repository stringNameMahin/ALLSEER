package capability

import (
	"fmt"
	"sort"
	"sync"
)

// MemoryCatalog is the default Catalog: an in-memory registry over the table in
// table.go, with observability driven by a registered probe set.
//
// The known/observable split is the point of this type. Every Kind in the table
// is known: it is part of the vocabulary, it may appear in an archived audit
// log, and Lookup will describe it. Only a Kind with a probe behind it is
// observable, and only an observable Kind can be meaningfully granted.
//
// A catalog built with no probes therefore reports every Kind known and none
// observable. That is the right answer for a build with no eBPF collector
// linked in, and it makes the "generation may not exceed the catalog" property
// fail loudly on a development host instead of passing by accident.
//
// Safe for concurrent use. The table is fixed at construction; only the
// observable set changes, and it is guarded.
type MemoryCatalog struct {
	// byKind is written once at construction and never again, so it needs no
	// lock.
	byKind map[Kind]Descriptor

	// order preserves table declaration order so Kinds() is stable. Callers
	// render it into documentation and schema enums, where a map's randomized
	// iteration would produce spurious diffs.
	order []Kind

	mu         sync.RWMutex
	observable map[Kind]bool
}

var _ Catalog = (*MemoryCatalog)(nil)

// NewCatalog returns a catalog over the full capability table, treating the
// given Kinds as observable.
//
// Passing none is valid and yields a catalog where nothing is observable; see
// the type documentation for why that is the right default. Unknown Kinds are
// ignored rather than rejected. The argument describes which probes a build
// loaded, and a probe reporting a Kind this binary does not know is a build
// mismatch for the telemetry layer to catch at load time.
func NewCatalog(observable ...Kind) *MemoryCatalog {
	c := &MemoryCatalog{
		byKind:     make(map[Kind]Descriptor, len(descriptors)),
		order:      make([]Kind, 0, len(descriptors)),
		observable: make(map[Kind]bool, len(observable)),
	}
	for _, d := range descriptors {
		c.byKind[d.Kind] = d
		c.order = append(c.order, d.Kind)
	}
	for _, k := range observable {
		if _, ok := c.byKind[k]; ok {
			c.observable[k] = true
		}
	}
	return c
}

// NewCatalogAllObservable returns a catalog in which every known Kind is
// observable.
//
// For tests and replay-driven analysis, where the recorded stream stands in for
// a fully instrumented kernel. Do not use it to build the daemon's catalog:
// that would let the generator issue grants for capabilities the running build
// cannot see, which is the blind spot Observable exists to prevent.
func NewCatalogAllObservable() *MemoryCatalog {
	return NewCatalog(AllKinds()...)
}

// Kinds returns every capability this build knows about, in table declaration
// order. The returned slice is a copy.
func (c *MemoryCatalog) Kinds() []Kind {
	out := make([]Kind, len(c.order))
	copy(out, c.order)
	return out
}

// Lookup reports the descriptor for a Kind and whether the Kind is known.
func (c *MemoryCatalog) Lookup(k Kind) (Descriptor, bool) {
	d, ok := c.byKind[k]
	return d, ok
}

// Observable reports whether a probe backing this Kind is loaded. An unknown
// Kind is never observable, so a typo in an envelope fails both this check and
// the known-Kind check. The envelope is unenforceable either way.
func (c *MemoryCatalog) Observable(k Kind) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.observable[k]
}

// SetObservable records which Kinds have probes behind them, replacing any
// previous set.
//
// The daemon calls this once probes are attached, from Collector.Probes(), so
// the catalog reflects what this process can actually see rather than what the
// build might have supported. Kinds outside the table are ignored, for the
// reason given on NewCatalog.
func (c *MemoryCatalog) SetObservable(kinds []Kind) {
	next := make(map[Kind]bool, len(kinds))
	for _, k := range kinds {
		if _, ok := c.byKind[k]; ok {
			next[k] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observable = next
}

// ObservableKinds returns the observable subset, in table declaration order.
// Used for coverage reporting: an envelope granting a Kind absent from this
// list cannot be enforced, and the daemon warns accordingly.
func (c *MemoryCatalog) ObservableKinds() []Kind {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Kind, 0, len(c.observable))
	for _, k := range c.order {
		if c.observable[k] {
			out = append(out, k)
		}
	}
	return out
}

// --- Package-level vocabulary queries ---------------------------------------
//
// Kind is a closed enum fixed by table.go at compile time. These functions
// answer questions about that set without needing a Catalog instance.
//
// An unknown Kind in an envelope is far more likely a typo or a model
// hallucination than a genuine out-of-tree probe, and accepting one silently
// means enforcing an envelope nothing can observe.
//
// Enforcement lives at the envelope parse boundary rather than in a
// Kind.UnmarshalJSON hook. Kind stays a plain string on the wire so archived
// audit logs and recorded event streams remain parseable by a binary whose
// table has since moved on. Rejecting an unknown Kind is a decision about what
// may be granted, and it belongs where grants are admitted.

// AllKinds returns every valid Kind in table declaration order.
func AllKinds() []Kind {
	out := make([]Kind, len(descriptors))
	for i, d := range descriptors {
		out[i] = d.Kind
	}
	return out
}

// kindIndex backs Known and Describe. Built once, read-only thereafter.
var kindIndex = func() map[Kind]Descriptor {
	m := make(map[Kind]Descriptor, len(descriptors))
	for _, d := range descriptors {
		m[d.Kind] = d
	}
	return m
}()

// Known reports whether a Kind is part of the vocabulary.
func Known(k Kind) bool {
	_, ok := kindIndex[k]
	return ok
}

// Describe returns a Kind's static metadata.
func Describe(k Kind) (Descriptor, bool) {
	d, ok := kindIndex[k]
	return d, ok
}

// DomainOf returns the domain a Kind belongs to, and whether the Kind is known.
//
// Grant and Observation both carry Domain denormalized alongside Kind, and the
// two must agree. A grant claiming fs.write is in the network domain is
// malformed, and this is how that is caught.
func DomainOf(k Kind) (Domain, bool) {
	d, ok := kindIndex[k]
	return d.Domain, ok
}

// ValidateKind returns an error describing why a Kind is unacceptable, or nil.
// This is the check the envelope parser applies to every grant and denial.
func ValidateKind(k Kind) error {
	if k == "" {
		return fmt.Errorf("capability kind is empty")
	}
	if !Known(k) {
		return fmt.Errorf("unknown capability kind %q: not in the capability catalog", k)
	}
	return nil
}

// KindsInDomain returns every Kind belonging to a domain, in table order.
// Policy rules address domains without enumerating Kinds, and the linter uses
// this to check that a domain condition is satisfiable.
func KindsInDomain(d Domain) []Kind {
	var out []Kind
	for _, desc := range descriptors {
		if desc.Domain == d {
			out = append(out, desc.Kind)
		}
	}
	return out
}

// AllDomains returns every domain present in the table, sorted for stable
// output.
func AllDomains() []Domain {
	seen := make(map[Domain]bool, 8)
	var out []Domain
	for _, d := range descriptors {
		if !seen[d.Domain] {
			seen[d.Domain] = true
			out = append(out, d.Domain)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
