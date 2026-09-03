// Package resolve turns a decoded event into the normalized, selector-matchable
// capability.Observation the validator compares against an envelope.
//
// This is the seam named in docs/architecture.md: the envelope declares
// capabilities as grants, the collector resolves each kernel event to an
// observation, and the validator asks whether the observation is covered. It
// lives under telemetry because resolution is the last enrichment step, not a
// validation step -- keeping it here is what lets internal/validator stay
// payload-agnostic, never reaching into FilePayload or NetworkPayload.
//
// It is pure: no I/O, no kernel, no DNS. Everything it needs was already
// resolved upstream, which is what lets replayed fixtures and unit tests use it
// on any platform.
//
// # What it does not do
//
// It translates and nothing more. It never decides whether an observation is
// permitted, never compares against a selector, and never repairs a target it
// was handed. In particular it will not fall back from ResolvedPath to the raw
// syscall path: matching a pre-resolution path is exactly the symlink escape
// docs/path-matching.md exists to prevent, so an event whose path could not be
// resolved yields an observation with an empty target, and the matcher reports
// it as unevaluable.
//
// That division is deliberate. An empty or unresolved target is not an error
// here -- it is a fact about the observation, and the validator already knows
// what to do with facts it cannot evaluate. Errors are reserved for events that
// cannot be interpreted at all.
package resolve

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Errors reported when an event cannot be turned into an observation.
//
// Both mean the same thing operationally -- this event cannot be validated --
// and neither may be treated as "nothing happened". A caller that cannot
// resolve an event must surface it, not drop it.
var (
	// ErrUnknownCapability: the event's Kind is not in this build's catalog, so
	// there is no rule for interpreting its target. Guessing would be inventing
	// a selector.
	ErrUnknownCapability = errors.New("capability is not in this build's catalog")

	// ErrMissingPayload: the Kind requires a payload the event does not carry,
	// which means decode or enrichment failed.
	ErrMissingPayload = errors.New("event is missing the payload its capability requires")

	// ErrNilEvent guards the obvious.
	ErrNilEvent = errors.New("event is nil")
)

// Observe resolves an event to the observation the validator should evaluate.
//
// The returned observation's Domain always comes from the catalog rather than
// from Event.Domain, which is a denormalized copy that a hand-edited or
// mis-decoded record can contradict.
func Observe(e *event.Event) (capability.Observation, error) {
	if e == nil {
		return capability.Observation{}, ErrNilEvent
	}

	domain, known := capability.DomainOf(e.Capability)
	if !known {
		return capability.Observation{}, fmt.Errorf("%w: %q", ErrUnknownCapability, e.Capability)
	}

	obs := capability.Observation{Kind: e.Capability, Domain: domain}

	switch domain {
	case capability.DomainFilesystem:
		return observeFile(e, obs)
	case capability.DomainNetwork:
		return observeNetwork(e, obs)
	case capability.DomainProcess:
		return observeProcess(e, obs)
	default:
		return observeOther(e, obs)
	}
}

// observeFile handles the filesystem domain.
func observeFile(e *event.Event, obs capability.Observation) (capability.Observation, error) {
	if e.File == nil {
		return capability.Observation{}, fmt.Errorf("%w: %s has no file payload", ErrMissingPayload, e.Capability)
	}

	// ResolvedPath only. See the package comment: falling back to File.Path
	// would hand the matcher a pre-resolution path.
	obs.Target = e.File.ResolvedPath

	if e.File.NewPath != "" {
		// A rename or a link names two paths, and an Observation has one
		// Target. The source is the target and the destination is carried
		// beside it, which is the convention the committed replay fixtures
		// already use.
		//
		// The consequence is a real gap, not a stylistic one: selector matching
		// evaluates Target alone, so a rename *into* a protected location is
		// not caught by a path selector on the destination. Renaming
		// ./payload onto /etc/cron.d/job is matched as an operation on
		// ./payload. Recording the destination here at least means the
		// information reaches risk scoring and the audit log rather than being
		// discarded.
		//
		// TODO(validator): decide how a two-path operation is validated. The
		// options are a second observation per event, which changes the
		// one-event-one-decision shape the pipeline assumes, or a Target pair
		// in capability.Observation, which touches the wire format. Both are
		// larger than this bridge and neither should be chosen by default.
		obs.Attributes = map[string]string{capability.AttrNewPath: e.File.NewPath}
	}

	return obs, nil
}

// observeNetwork handles the network domain.
func observeNetwork(e *event.Event, obs capability.Observation) (capability.Observation, error) {
	if e.Network == nil {
		return capability.Observation{}, fmt.Errorf("%w: %s has no network payload", ErrMissingPayload, e.Capability)
	}
	n := e.Network

	// The correlated name when there is one, the address otherwise. Which of
	// the two the target holds is exactly what tells the matcher whether a
	// hostname grant can be compared at all, so the choice is not cosmetic.
	host := n.Hostname
	if host == "" {
		host = n.DestAddr
	}

	if e.Capability == capability.KindNetDNS {
		// A DNS query acts on a name, not on an endpoint. Appending the
		// resolver's port would make the target unmatchable against any grant
		// a human would write.
		obs.Target = host
	} else if host != "" && n.DestPort > 0 {
		// JoinHostPort, not concatenation: an IPv6 literal needs brackets or
		// the result cannot be split back apart.
		obs.Target = net.JoinHostPort(host, strconv.Itoa(n.DestPort))
	} else {
		obs.Target = host
	}

	attrs := map[string]string{}
	if n.Protocol != "" {
		attrs[capability.AttrProtocol] = n.Protocol
	}
	if n.DestAddr != "" {
		attrs[capability.AttrDestIP] = n.DestAddr
	}
	if n.DestPort > 0 {
		attrs[capability.AttrPort] = strconv.Itoa(n.DestPort)
	}
	if n.Hostname == "" {
		// Stated rather than left to be inferred from the target's shape. Risk
		// scoring treats an uncorrelated destination as a signal in its own
		// right.
		attrs[capability.AttrHostnameCorrelated] = "false"
	}
	if len(attrs) > 0 {
		obs.Attributes = attrs
	}

	return obs, nil
}

// observeProcess handles the process domain.
func observeProcess(e *event.Event, obs capability.Observation) (capability.Observation, error) {
	if e.Capability == capability.KindProcessExec {
		if e.Exec == nil {
			return capability.Observation{}, fmt.Errorf("%w: %s has no exec payload", ErrMissingPayload, e.Capability)
		}
		obs.Target = e.Exec.Filename

		attrs := map[string]string{}
		if len(e.Exec.Argv) > 0 {
			// Joined verbatim, never abbreviated. A shortened command line
			// would read better and match differently from what ran.
			attrs[capability.AttrArgv] = strings.Join(e.Exec.Argv, " ")
		}
		if e.Exec.Interpreter != "" {
			attrs[capability.AttrInterpreter] = e.Exec.Interpreter
		}
		if len(attrs) > 0 {
			obs.Attributes = attrs
		}
		return obs, nil
	}

	// fork, exit, signal, ptrace. The acting process's binary is the only
	// resource these name in the current event model.
	//
	// For fork and exit that is the right answer: the process is what acted and
	// what was acted upon. For signal and ptrace it is not -- the resource is
	// the *target* process, which the event carries no field for, so a grant's
	// Executables constrains who may signal rather than who may be signalled.
	//
	// TODO(telemetry): carry the target process of a signal or ptrace on the
	// event. Until then, an envelope cannot express "may not ptrace the
	// supervisor", which is the case that matters.
	obs.Target = e.Process.Executable
	return obs, nil
}

// observeOther handles privilege, IPC, and kernel capabilities.
func observeOther(e *event.Event, obs capability.Observation) (capability.Observation, error) {
	// These carry no selector dimension of their own: exercising the capability
	// is the whole observation, and the Kind alone is what a grant matches.
	//
	// Some are nonetheless named by a path -- a unix socket, a loaded module --
	// and the event model has no payload of its own for them. When such an
	// event arrives carrying a file payload, its resolved path is the resource,
	// which is what makes a PathPatterns selector on ipc.unixsocket work.
	if e.File != nil {
		obs.Target = e.File.ResolvedPath
	}
	return obs, nil
}
