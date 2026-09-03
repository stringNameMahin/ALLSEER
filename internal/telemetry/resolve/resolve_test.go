package resolve

import (
	"errors"
	"maps"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

func TestObserveFile(t *testing.T) {
	e := &event.Event{
		Capability: capability.KindFileWrite,
		Domain:     capability.DomainFilesystem,
		File: &event.FilePayload{
			Path:         "src/main.go",
			ResolvedPath: "/ws/src/main.go",
		},
	}

	obs, err := Observe(e)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Kind != capability.KindFileWrite || obs.Domain != capability.DomainFilesystem {
		t.Errorf("kind/domain = %s/%s", obs.Kind, obs.Domain)
	}
	if obs.Target != "/ws/src/main.go" {
		t.Errorf("Target = %q, want the resolved path", obs.Target)
	}
	if len(obs.Attributes) != 0 {
		t.Errorf("Attributes = %v, want none", obs.Attributes)
	}
}

// TestObserveFileNeverFallsBackToRawPath is the symlink-escape guard. The raw
// syscall path may be relative and may traverse a symlink; using it as the
// target would hand the matcher exactly the pre-resolution path that
// docs/path-matching.md exists to keep out.
func TestObserveFileNeverFallsBackToRawPath(t *testing.T) {
	e := &event.Event{
		Capability: capability.KindFileRead,
		File: &event.FilePayload{
			Path:         "/ws/link/../../etc/shadow",
			ResolvedPath: "", // enrichment failed, or the probe truncated
		},
	}

	obs, err := Observe(e)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Target != "" {
		t.Errorf("Target = %q, want empty; the unresolved path must not be used", obs.Target)
	}
	if obs.Kind != capability.KindFileRead {
		t.Errorf("Kind = %q; an unresolvable path must still produce an observation to evaluate", obs.Kind)
	}
}

// TestObserveRename covers the case where one event names two paths.
//
// The source is the Target and the destination rides in AttrNewPath, which is
// the convention the committed replay fixtures already use. The rule being
// pinned here is that no information is dropped, not that both paths are
// matched -- see TestRenameDestinationIsNotInTheTarget.
func TestObserveRename(t *testing.T) {
	for _, kind := range []capability.Kind{capability.KindFileRename, capability.KindFileLink} {
		e := &event.Event{
			Capability: kind,
			File: &event.FilePayload{
				Path:         ".git/index.lock",
				ResolvedPath: "/ws/.git/index.lock",
				NewPath:      "/ws/.git/index",
			},
		}

		obs, err := Observe(e)
		if err != nil {
			t.Fatalf("Observe(%s): %v", kind, err)
		}
		if obs.Target != "/ws/.git/index.lock" {
			t.Errorf("%s: Target = %q, want the source path", kind, obs.Target)
		}
		if got := obs.Attributes[capability.AttrNewPath]; got != "/ws/.git/index" {
			t.Errorf("%s: %s = %q, want the destination path", kind, capability.AttrNewPath, got)
		}
	}
}

// TestRenameDestinationIsNotInTheTarget documents a known limitation rather
// than a desired property.
//
// An Observation has one Target and selector matching evaluates only that, so
// the destination of a rename is not compared against path selectors: renaming
// a payload onto /etc/cron.d/job is matched as an operation on the payload.
// The destination is preserved in attributes so risk scoring and the audit log
// still see it.
//
// When the model grows a way to validate both paths, this test should fail and
// be replaced. That is the point of writing it down.
func TestRenameDestinationIsNotInTheTarget(t *testing.T) {
	e := &event.Event{
		Capability: capability.KindFileRename,
		File: &event.FilePayload{
			ResolvedPath: "/ws/payload",
			NewPath:      "/etc/cron.d/job",
		},
	}

	obs, err := Observe(e)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Target == "/etc/cron.d/job" {
		t.Fatal("the destination became the target; the two-path limitation has changed and the docs must follow")
	}
	if obs.Attributes[capability.AttrNewPath] != "/etc/cron.d/job" {
		t.Error("the destination was dropped entirely, which loses it for risk scoring too")
	}
}

func TestObserveNetwork(t *testing.T) {
	tests := []struct {
		name       string
		kind       capability.Kind
		payload    event.NetworkPayload
		wantTarget string
		wantAttrs  map[string]string
	}{
		{
			name: "correlated connection",
			kind: capability.KindNetConnect,
			payload: event.NetworkPayload{
				Protocol: "tcp", DestAddr: "104.16.24.35", DestPort: 443,
				Hostname: "registry.npmjs.org",
			},
			wantTarget: "registry.npmjs.org:443",
			wantAttrs: map[string]string{
				capability.AttrProtocol: "tcp",
				capability.AttrDestIP:   "104.16.24.35",
				capability.AttrPort:     "443",
			},
		},
		{
			// Correlation failed, so the target is the address and the fact is
			// stated rather than left to be inferred.
			name: "uncorrelated connection",
			kind: capability.KindNetConnect,
			payload: event.NetworkPayload{
				Protocol: "tcp", DestAddr: "151.101.1.162", DestPort: 443,
			},
			wantTarget: "151.101.1.162:443",
			wantAttrs: map[string]string{
				capability.AttrProtocol:           "tcp",
				capability.AttrDestIP:             "151.101.1.162",
				capability.AttrPort:               "443",
				capability.AttrHostnameCorrelated: "false",
			},
		},
		{
			// The trap: concatenation would produce an unsplittable target.
			name: "IPv6 destination is bracketed",
			kind: capability.KindNetConnect,
			payload: event.NetworkPayload{
				Protocol: "tcp", DestAddr: "2606:2800:220::1946", DestPort: 443,
			},
			wantTarget: "[2606:2800:220::1946]:443",
			wantAttrs: map[string]string{
				capability.AttrProtocol:           "tcp",
				capability.AttrDestIP:             "2606:2800:220::1946",
				capability.AttrPort:               "443",
				capability.AttrHostnameCorrelated: "false",
			},
		},
		{
			// A DNS query acts on a name. Appending the resolver's port would
			// make the target unmatchable against any grant a human would write.
			name: "DNS names the queried host, not an endpoint",
			kind: capability.KindNetDNS,
			payload: event.NetworkPayload{
				Protocol: "udp", DestAddr: "127.0.0.53", DestPort: 53,
				Hostname: "registry.npmjs.org",
			},
			wantTarget: "registry.npmjs.org",
			wantAttrs: map[string]string{
				capability.AttrProtocol: "udp",
				capability.AttrDestIP:   "127.0.0.53",
				capability.AttrPort:     "53",
			},
		},
		{
			name:       "no port yields a bare host",
			kind:       capability.KindNetConnect,
			payload:    event.NetworkPayload{Protocol: "icmp", DestAddr: "10.1.2.3"},
			wantTarget: "10.1.2.3",
			wantAttrs: map[string]string{
				capability.AttrProtocol:           "icmp",
				capability.AttrDestIP:             "10.1.2.3",
				capability.AttrHostnameCorrelated: "false",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := tt.payload
			obs, err := Observe(&event.Event{Capability: tt.kind, Network: &payload})
			if err != nil {
				t.Fatalf("Observe: %v", err)
			}
			if obs.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", obs.Target, tt.wantTarget)
			}
			if !maps.Equal(obs.Attributes, tt.wantAttrs) {
				t.Errorf("Attributes = %v, want %v", obs.Attributes, tt.wantAttrs)
			}
		})
	}
}

func TestObserveProcess(t *testing.T) {
	exec := &event.Event{
		Capability: capability.KindProcessExec,
		Exec: &event.ExecPayload{
			Filename: "/usr/bin/git",
			Argv:     []string{"git", "commit", "-am", "fix parser"},
		},
	}
	obs, err := Observe(exec)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Target != "/usr/bin/git" {
		t.Errorf("Target = %q, want the executed binary", obs.Target)
	}
	// Space-joined, which is lossy for the argument holding a space. Tolerable
	// only because ArgPatterns is never a security boundary.
	if got := obs.Attributes[capability.AttrArgv]; got != "git commit -am fix parser" {
		t.Errorf("argv = %q", got)
	}

	// Lifecycle events carry no payload; the acting binary is the resource.
	exit := &event.Event{
		Capability: capability.KindProcessExit,
		Process:    event.Process{Executable: "/usr/bin/git"},
	}
	obs, err = Observe(exit)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Target != "/usr/bin/git" {
		t.Errorf("Target = %q, want the acting binary", obs.Target)
	}
	if len(obs.Attributes) != 0 {
		t.Errorf("Attributes = %v, want none", obs.Attributes)
	}
}

func TestObserveSelectorlessDomains(t *testing.T) {
	// Exercising the capability is the whole observation.
	obs, err := Observe(&event.Event{
		Capability: capability.KindPrivSetuid,
		Privil:     &event.PrivPayload{Operation: "setuid"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Kind != capability.KindPrivSetuid || obs.Domain != capability.DomainPrivilege {
		t.Errorf("kind/domain = %s/%s", obs.Kind, obs.Domain)
	}
	if obs.Target != "" {
		t.Errorf("Target = %q, want empty; a privilege change acts on no resource", obs.Target)
	}

	// A unix socket is named by a path, and the event model has no IPC payload
	// of its own, so a file payload supplies the resource.
	obs, err = Observe(&event.Event{
		Capability: capability.KindIPCUnixSock,
		File:       &event.FilePayload{ResolvedPath: "/run/docker.sock"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Target != "/run/docker.sock" {
		t.Errorf("Target = %q, want the socket path", obs.Target)
	}
}

func TestObserveErrors(t *testing.T) {
	tests := []struct {
		name string
		e    *event.Event
		want error
	}{
		{"nil event", nil, ErrNilEvent},
		{
			"unknown capability",
			&event.Event{Capability: capability.Kind("fs.teleport")},
			ErrUnknownCapability,
		},
		{
			"file event with no payload",
			&event.Event{Capability: capability.KindFileWrite},
			ErrMissingPayload,
		},
		{
			"network event with no payload",
			&event.Event{Capability: capability.KindNetConnect},
			ErrMissingPayload,
		},
		{
			"exec event with no payload",
			&event.Event{Capability: capability.KindProcessExec},
			ErrMissingPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, err := Observe(tt.e)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if obs.Kind != "" {
				t.Errorf("a failed resolution returned an observation: %+v", obs)
			}
		})
	}
}

// TestObserveIgnoresDenormalizedDomain: Event.Domain is a copy kept for cheap
// filtering, and a copy can be wrong. The catalog is authoritative.
func TestObserveIgnoresDenormalizedDomain(t *testing.T) {
	obs, err := Observe(&event.Event{
		Capability: capability.KindFileWrite,
		Domain:     capability.DomainNetwork, // wrong on purpose
		File:       &event.FilePayload{ResolvedPath: "/ws/main.go"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Domain != capability.DomainFilesystem {
		t.Errorf("Domain = %q, want the catalog's answer", obs.Domain)
	}
}

func TestObserveDoesNotMutateTheEvent(t *testing.T) {
	// Events are immutable once decoded, so a stage that panics cannot corrupt
	// a record. Resolution returns a value; it does not write one back.
	e := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{ResolvedPath: "/ws/main.go"},
	}
	if _, err := Observe(e); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if e.Observation.Kind != "" {
		t.Error("Observe wrote back into the event")
	}
}
