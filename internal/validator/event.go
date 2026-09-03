package validator

import (
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file is the only place the validator meets an event.Event. Everything
// else in the package works on capability.Observation, which is what keeps
// selector matching independent of how a probe happens to shape its payload.

// ObservationOf returns the observation to validate for e.
//
// Enrichment is supposed to have resolved it already, and a recorded stream
// carries it verbatim, so a populated Event.Observation is used as-is: it is
// the record of what the collector concluded at the time, and re-deriving it
// from the payload would let a replayed session be validated against different
// facts than the live one was.
//
// When it is absent -- a hand-written fixture, a source that predates the
// resolver, a decode that skipped enrichment -- it is derived from the payload
// rather than treated as an empty observation, because an empty observation
// would match a Kind-only grant and quietly read as expected behavior.
func ObservationOf(e *event.Event) (capability.Observation, error) {
	if e != nil && e.Observation.Kind != "" {
		return e.Observation, nil
	}
	return resolve.Observe(e)
}

// MatchEvent reports whether a grant covers the event.
//
// It is the entry point a pipeline uses: given an event off any event.Source,
// including a replayed one, it produces the same MatchResult that Match
// produces for an observation.
//
// An event that cannot be resolved is unevaluable, never a mismatch and never a
// match. A record the system cannot interpret is a blind spot, and a blind spot
// reported as coverage is the one outcome that must not happen.
func (m *SelectorMatcher) MatchEvent(g capability.Grant, e *event.Event) MatchResult {
	obs, err := ObservationOf(e)
	if err != nil {
		return unevaluable("event cannot be resolved to an observation: %v", err)
	}
	return m.Match(g, obs)
}
