// Package winpath canonicalizes Windows paths for enrichment.
//
// It is the Windows half of the division of labour docs/path-matching.md
// already requires: the validator is purely lexical and matches only paths that
// are already canonical, and getting them there is enrichment's job. On Linux
// that job is nearly free, because the kernel hands the probe a resolved path.
// On Windows it is a real step, and it is the first one:
//
//	\Device\HarddiskVolume5\ALLSEER\dev\fileprobe\   ->  D:\ALLSEER\dev\fileprobe
//
// 684 of 684 path values in an elevated ETW capture were in the left-hand form
// and not one was in the right-hand one. That makes device-to-drive translation
// unlike the other equivalence axes the path model defends against. Those are
// spellings an adversary may choose; this is the spelling telemetry always
// delivers. Without it the matcher does not merely under-match, it matches
// nothing, ever.
//
// # What it does and does not do
//
// Canonicalize translates and trims. It does not repair. Trailing separators
// are stripped because ETW emits them on ordinary directory operations and
// refusing them would turn every delete into an unresolvable violation, which
// is fail-closed but noisy and avoidable. Everything else the canonical form
// forbids -- a "..", a trailing dot, an 8.3 short name -- is reported as an
// error rather than fixed, for the reason the validator gives: accepting two
// spellings of one file is what creates the hole.
//
// A device with no drive-letter mapping -- a volume mounted only at a
// directory, a VHD, a shadow copy -- has no Win32 spelling, and such a path is
// refused rather than guessed at.
//
// # Why the package is not build-tagged
//
// Only the live device map needs Windows. Translation, trimming and validation
// are string operations over strings a Windows kernel produced, and they are
// the part with the security consequences, so they are built and tested
// everywhere. QueryDeviceMap is the one Windows-only entry point.
//
// # Not the ETW consumer
//
// Nothing here opens a session, names a provider, or decodes a record. The
// input is a string; where the string came from is the consumer's problem.
package winpath

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
)

// Errors reported when a path cannot be canonicalized.
//
// All of them mean the same thing operationally -- this path cannot be matched
// against a selector -- and none may be treated as "nothing happened". A caller
// that cannot canonicalize a path surfaces it as ViolationUnresolvable, exactly
// as it would a path truncated by a probe.
var (
	// ErrEmptyPath guards the obvious.
	ErrEmptyPath = errors.New("winpath: path is empty")

	// ErrUnmappedDevice: the path names an NT device this host has no
	// drive-letter mapping for. Guessing a letter would be inventing a file
	// identity, so the path is refused.
	ErrUnmappedDevice = errors.New("winpath: no drive letter is mapped to this device")

	// ErrNotCanonical: translation succeeded and the result is still not
	// something the matcher can evaluate. The wrapped error names the rule.
	ErrNotCanonical = errors.New("winpath: path is not in canonical form")
)

// DeviceMap translates NT device names to drive letters.
//
// Built from the live host by QueryDeviceMap and immutable thereafter. The
// mapping is per volume rather than per system -- HarddiskVolume5 was D: and
// HarddiskVolume3 was C: on the host this was measured on -- and it changes
// when a volume mounts, which is why Canonicalizer holds one swappably rather
// than baking it in.
//
// Safe for concurrent use.
type DeviceMap struct {
	// entries are sorted by descending device-name length so the first prefix
	// match is the longest. Without that, \Device\HarddiskVolume1 would claim
	// every path under \Device\HarddiskVolume10.
	entries []deviceEntry
}

type deviceEntry struct {
	device string // e.g. `\Device\HarddiskVolume3`, as reported
	folded string // the same, ASCII-lowercased, for comparison
	drive  string // e.g. `C:`
}

// NewDeviceMap builds a device map from device name to drive letter.
//
// Keys are NT device names without a trailing separator; values are a drive
// letter and a colon. Both are checked rather than trusted: a malformed entry
// here would mistranslate every event on that volume for the life of the
// process, and the caller supplying it is a syscall wrapper whose output is
// worth validating once.
func NewDeviceMap(m map[string]string) (*DeviceMap, error) {
	d := &DeviceMap{entries: make([]deviceEntry, 0, len(m))}
	for device, drive := range m {
		device = strings.TrimRight(device, `\`)
		if device == "" {
			return nil, fmt.Errorf("winpath: empty device name for drive %q", drive)
		}
		if len(drive) != 2 || drive[1] != ':' || drive[0] < 'A' || drive[0] > 'Z' {
			return nil, fmt.Errorf("winpath: %q is not an uppercase drive letter and colon", drive)
		}
		d.entries = append(d.entries, deviceEntry{
			device: device,
			folded: strings.ToLower(device),
			drive:  drive,
		})
	}
	sort.Slice(d.entries, func(i, j int) bool {
		if len(d.entries[i].device) != len(d.entries[j].device) {
			return len(d.entries[i].device) > len(d.entries[j].device)
		}
		return d.entries[i].device < d.entries[j].device
	})
	return d, nil
}

// Len reports how many devices are mapped.
func (d *DeviceMap) Len() int {
	if d == nil {
		return 0
	}
	return len(d.entries)
}

// Devices returns the mapped device names paired with their drive letters, in
// the order lookups consider them. For diagnostics: an operator staring at a
// stream of unmapped-device errors needs to see what the process thinks the
// host looks like.
func (d *DeviceMap) Devices() [][2]string {
	if d == nil {
		return nil
	}
	out := make([][2]string, 0, len(d.entries))
	for _, e := range d.entries {
		out = append(out, [2]string{e.device, e.drive})
	}
	return out
}

// Translate rewrites an NT device path to its drive-letter form.
//
// The boundary check is what makes this safe: a device name matches only when
// the path ends there or continues with a separator, so \Device\HarddiskVolume1
// does not claim \Device\HarddiskVolume10\secrets. Device names are compared
// case-insensitively, as the object manager compares them.
//
// Returns false when no device is mapped, which the caller must treat as a
// refusal rather than a reason to fall back to the untranslated path.
func (d *DeviceMap) Translate(p string) (string, bool) {
	if d == nil {
		return "", false
	}
	folded := strings.ToLower(p)
	for _, e := range d.entries {
		if !strings.HasPrefix(folded, e.folded) {
			continue
		}
		rest := p[len(e.device):]
		if rest != "" && rest[0] != '\\' {
			continue
		}
		if rest == "" {
			rest = `\`
		}
		return e.drive + rest, true
	}
	return "", false
}

// Canonicalizer turns a reported path into the canonical form the validator
// requires.
//
// The device map is held behind an atomic pointer so it can be replaced when a
// volume mounts without stopping the event stream and without a lock on the hot
// path. A canonicalizer with no device map translates nothing and refuses every
// NT path, which is the right answer for a process that has not yet queried the
// host: refusing loudly beats matching a path whose volume it cannot name.
//
// Safe for concurrent use.
type Canonicalizer struct {
	devices atomic.Pointer[DeviceMap]
}

// NewCanonicalizer returns a canonicalizer over the given device map, which may
// be nil.
func NewCanonicalizer(d *DeviceMap) *Canonicalizer {
	c := &Canonicalizer{}
	if d != nil {
		c.devices.Store(d)
	}
	return c
}

// SetDeviceMap replaces the device map, for a volume mount or unmount.
func (c *Canonicalizer) SetDeviceMap(d *DeviceMap) { c.devices.Store(d) }

// DeviceMap returns the current map, which may be nil.
func (c *Canonicalizer) DeviceMap() *DeviceMap { return c.devices.Load() }

// Canonicalize returns raw in the form validator.IsResolvedWindows accepts.
//
// The steps, in order, and each of them measured rather than assumed:
//
//  1. Strip the extended-length and NT object-manager prefixes, `\\?\` and
//     `\??\`. Both name the same file as the path they wrap and neither is
//     canonical.
//  2. Translate an NT device name to its drive letter. This is step zero of
//     enrichment in every sense: nothing downstream ever sees an NT path.
//  3. Strip trailing separators. ETW reports directory operations as
//     `...\fileprobe\` and a delete as `...\delta-deleted.txt\`; refusing those
//     would report every ordinary delete as unresolvable.
//  4. Uppercase the drive letter, which is the only case the canonical form
//     fixes. Everything else keeps the casing it arrived with, so a violation
//     report names the file as it exists on disk.
//  5. Validate. Anything the canonical form forbids and this function does not
//     repair is returned as an error naming the rule.
//
// What it deliberately does not do is expand an 8.3 short name. That needs
// GetLongPathName, which needs the file to still exist -- it does not, on the
// delete events where the question matters most -- and which is a syscall per
// event on the hot path. Short names are refused here with an error saying so.
// They were not observed in the capture this was built against; when a decision
// is needed it belongs with the consumer that knows the event's timing.
func (c *Canonicalizer) Canonicalize(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmptyPath
	}

	p := stripNTPrefix(raw)

	if isDevicePath(p) {
		translated, ok := c.devices.Load().Translate(p)
		if !ok {
			// A volume mounted only at a directory, a VHD, or a shadow copy has
			// no Win32 spelling at all. Refusing is the same fail-closed choice
			// the validator makes everywhere else.
			return "", fmt.Errorf("%w: %q", ErrUnmappedDevice, raw)
		}
		p = translated
	}

	p = trimTrailingSeparators(p)
	p = upperDrive(p)

	if err := validator.ExplainWindowsPath(p); err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	return p, nil
}

// isDevicePath reports whether p is in the NT device namespace.
func isDevicePath(p string) bool {
	const prefix = `\device\`
	return len(p) >= len(prefix) && strings.EqualFold(p[:len(prefix)], prefix)
}

// stripNTPrefix removes the extended-length and object-manager prefixes.
//
// `\\?\UNC\server\share` is deliberately not rewritten to `\\server\share`: the
// canonical form has no UNC spelling, so the result would be refused either way
// and rewriting it would only make the error message describe a path nobody
// reported.
func stripNTPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\`), strings.HasPrefix(p, `\??\`):
		return p[4:]
	}
	return p
}

// trimTrailingSeparators removes trailing backslashes, keeping a drive root
// intact. `C:\` is a path; `C:` is a drive-relative reference to a different
// file per process.
func trimTrailingSeparators(p string) string {
	for len(p) > 3 && p[len(p)-1] == '\\' {
		p = p[:len(p)-1]
	}
	return p
}

// upperDrive uppercases a leading drive letter. The canonical form fixes the
// drive's case and nothing else's, because the drive letter is an identifier
// while a path segment is a name someone chose.
func upperDrive(p string) string {
	if len(p) >= 2 && p[1] == ':' && p[0] >= 'a' && p[0] <= 'z' {
		return string(p[0]-'a'+'A') + p[1:]
	}
	return p
}
