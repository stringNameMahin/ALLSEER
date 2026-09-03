package winpath

import (
	"errors"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
)

// The device numbers here are the ones measured on the host the ETW capture
// came from -- HarddiskVolume5 was D: and HarddiskVolume3 was C: -- so the
// fixtures are the strings a real trace produced rather than invented ones.
func testMap(t *testing.T) *DeviceMap {
	t.Helper()

	d, err := NewDeviceMap(map[string]string{
		`\Device\HarddiskVolume3`: "C:",
		`\Device\HarddiskVolume5`: "D:",
	})
	if err != nil {
		t.Fatalf("NewDeviceMap: %v", err)
	}
	return d
}

func TestCanonicalizeMeasuredPaths(t *testing.T) {
	c := NewCanonicalizer(testMap(t))

	tests := []struct {
		name, raw, want string
	}{
		{
			name: "device path, the universal case",
			raw:  `\Device\HarddiskVolume5\AllSeer\dev\spike-results\fileprobe\alpha-created.txt`,
			want: `D:\AllSeer\dev\spike-results\fileprobe\alpha-created.txt`,
		},
		{
			name: "a second volume maps to a different letter",
			raw:  `\Device\HarddiskVolume3\Windows\System32\cmd.exe`,
			want: `C:\Windows\System32\cmd.exe`,
		},
		{
			// Observed on directory operations. Refusing these would report
			// every ordinary delete as unresolvable.
			name: "trailing separator is stripped",
			raw:  `\Device\HarddiskVolume5\AllSeer\dev\spike-results\fileprobe\`,
			want: `D:\AllSeer\dev\spike-results\fileprobe`,
		},
		{
			name: "trailing separator on a file",
			raw:  `\Device\HarddiskVolume5\AllSeer\delta-deleted.txt\`,
			want: `D:\AllSeer\delta-deleted.txt`,
		},
		{
			// Casing is preserved, not folded: the validator folds for
			// comparison and a violation report must name the file as it is.
			name: "caller casing survives",
			raw:  `\Device\HarddiskVolume5\ALLSEER\delta-deleted.txt`,
			want: `D:\ALLSEER\delta-deleted.txt`,
		},
		{
			name: "a stream suffix passes through",
			raw:  `\Device\HarddiskVolume3\Users\desktop.ini:Zone.Identifier`,
			want: `C:\Users\desktop.ini:Zone.Identifier`,
		},
		{
			name: "the typed stream form passes through",
			raw:  `\Device\HarddiskVolume3\EdgeWebView\manifest.json::$ATTRIBUTE_LIST`,
			want: `C:\EdgeWebView\manifest.json::$ATTRIBUTE_LIST`,
		},
		{
			name: "a volume root",
			raw:  `\Device\HarddiskVolume3\`,
			want: `C:\`,
		},
		{
			name: "a volume with no trailing separator at all",
			raw:  `\Device\HarddiskVolume3`,
			want: `C:\`,
		},
		{
			name: "the device name is matched case-insensitively",
			raw:  `\DEVICE\HARDDISKVOLUME3\Windows\notepad.exe`,
			want: `C:\Windows\notepad.exe`,
		},
		{
			name: "extended-length prefix is stripped",
			raw:  `\\?\C:\ws\secret.txt`,
			want: `C:\ws\secret.txt`,
		},
		{
			name: "object-manager prefix is stripped",
			raw:  `\??\C:\ws\secret.txt`,
			want: `C:\ws\secret.txt`,
		},
		{
			name: "an already-canonical path is returned unchanged",
			raw:  `C:\ws\main.go`,
			want: `C:\ws\main.go`,
		},
		{
			name: "a lowercase drive is the one case that is fixed",
			raw:  `c:\ws\main.go`,
			want: `C:\ws\main.go`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Canonicalize(tt.raw)
			if err != nil {
				t.Fatalf("Canonicalize(%q) = %v, want %q", tt.raw, err, tt.want)
			}
			if got != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			// The contract with the validator, asserted rather than assumed:
			// anything this returns is something the matcher can evaluate.
			if !validator.IsResolvedWindows(got) {
				t.Errorf("Canonicalize(%q) returned %q, which the matcher refuses", tt.raw, got)
			}
		})
	}
}

func TestCanonicalizeRefuses(t *testing.T) {
	c := NewCanonicalizer(testMap(t))

	tests := []struct {
		name, raw string
		want      error
	}{
		{"empty", "", ErrEmptyPath},
		{
			// A volume mounted only at a directory, a VHD, a shadow copy. No
			// Win32 spelling exists, so there is nothing to guess at.
			name: "unmapped volume",
			raw:  `\Device\HarddiskVolume9\ws\secret.txt`,
			want: ErrUnmappedDevice,
		},
		{
			name: "unmapped device family",
			raw:  `\Device\Mup\server\share\secret.txt`,
			want: ErrUnmappedDevice,
		},
		{
			// The boundary check. Without it HarddiskVolume3 would claim every
			// path on HarddiskVolume30.
			name: "device name is not a bare string prefix",
			raw:  `\Device\HarddiskVolume30\ws\secret.txt`,
			want: ErrUnmappedDevice,
		},
		{"dot-dot survives translation and is refused", `\Device\HarddiskVolume3\ws\..\Windows\x`, ErrNotCanonical},
		{"trailing dot", `\Device\HarddiskVolume3\ws\secret.txt.`, ErrNotCanonical},
		{"trailing space", "\\Device\\HarddiskVolume3\\ws\\secret.txt ", ErrNotCanonical},
		{"short name is refused, not expanded", `\Device\HarddiskVolume3\PROGRA~1\app.exe`, ErrNotCanonical},
		{"reserved device name", `\Device\HarddiskVolume3\ws\NUL.txt`, ErrNotCanonical},
		{"doubled separator", `\Device\HarddiskVolume3\ws\\secret.txt`, ErrNotCanonical},
		{"UNC has no canonical spelling", `\\localhost\C$\ws\secret.txt`, ErrNotCanonical},
		{"UNC behind the extended-length prefix", `\\?\UNC\server\share\secret.txt`, ErrNotCanonical},
		{"a POSIX path is not a Windows path", `/ws/main.go`, ErrNotCanonical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Canonicalize(tt.raw)
			if err == nil {
				t.Fatalf("Canonicalize(%q) = %q, want an error", tt.raw, got)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Canonicalize(%q) = %v, want %v", tt.raw, err, tt.want)
			}
		})
	}
}

// TestCanonicalizeRefusesWithoutDeviceMap pins the behaviour of a process that
// has not yet queried the host. Refusing loudly beats matching a path whose
// volume the process cannot name.
func TestCanonicalizeRefusesWithoutDeviceMap(t *testing.T) {
	c := NewCanonicalizer(nil)

	if _, err := c.Canonicalize(`\Device\HarddiskVolume3\ws\a.txt`); !errors.Is(err, ErrUnmappedDevice) {
		t.Errorf("with no device map: got %v, want ErrUnmappedDevice", err)
	}
	// A path that needs no translation is still canonicalizable, which is what
	// keeps replayed fixtures usable on a host with no volumes at all.
	if got, err := c.Canonicalize(`C:\ws\a.txt`); err != nil || got != `C:\ws\a.txt` {
		t.Errorf("with no device map: Canonicalize(C:\\ws\\a.txt) = %q, %v", got, err)
	}
}

// TestSetDeviceMap covers the mount case: a volume that was unmapped becomes
// mapped without the canonicalizer being rebuilt.
func TestSetDeviceMap(t *testing.T) {
	c := NewCanonicalizer(testMap(t))
	raw := `\Device\HarddiskVolume9\ws\a.txt`

	if _, err := c.Canonicalize(raw); !errors.Is(err, ErrUnmappedDevice) {
		t.Fatalf("before mount: got %v, want ErrUnmappedDevice", err)
	}

	mounted, err := NewDeviceMap(map[string]string{
		`\Device\HarddiskVolume3`: "C:",
		`\Device\HarddiskVolume5`: "D:",
		`\Device\HarddiskVolume9`: "E:",
	})
	if err != nil {
		t.Fatalf("NewDeviceMap: %v", err)
	}
	c.SetDeviceMap(mounted)

	got, err := c.Canonicalize(raw)
	if err != nil {
		t.Fatalf("after mount: %v", err)
	}
	if want := `E:\ws\a.txt`; got != want {
		t.Errorf("after mount: got %q, want %q", got, want)
	}
}

// TestTranslateLongestPrefixWins is the ordering property NewDeviceMap sorts
// for. Map iteration order is randomized, so a map that happened to be built
// in the wrong order would fail intermittently rather than never.
func TestTranslateLongestPrefixWins(t *testing.T) {
	d, err := NewDeviceMap(map[string]string{
		`\Device\HarddiskVolume1`:  "C:",
		`\Device\HarddiskVolume10`: "D:",
		`\Device\HarddiskVolume11`: "E:",
	})
	if err != nil {
		t.Fatalf("NewDeviceMap: %v", err)
	}

	tests := []struct{ raw, want string }{
		{`\Device\HarddiskVolume1\a.txt`, `C:\a.txt`},
		{`\Device\HarddiskVolume10\a.txt`, `D:\a.txt`},
		{`\Device\HarddiskVolume11\a.txt`, `E:\a.txt`},
	}
	for _, tt := range tests {
		got, ok := d.Translate(tt.raw)
		if !ok || got != tt.want {
			t.Errorf("Translate(%q) = %q, %v; want %q, true", tt.raw, got, ok, tt.want)
		}
	}

	if got, ok := d.Translate(`\Device\HarddiskVolume100\a.txt`); ok {
		t.Errorf("Translate(HarddiskVolume100) = %q, true; want a refusal", got)
	}
}

func TestNewDeviceMapRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]string
	}{
		{"empty device name", map[string]string{`\`: "C:"}},
		{"drive without colon", map[string]string{`\Device\HarddiskVolume1`: "C"}},
		{"lowercase drive", map[string]string{`\Device\HarddiskVolume1`: "c:"}},
		{"a path, not a letter", map[string]string{`\Device\HarddiskVolume1`: `C:\`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewDeviceMap(tt.m); err == nil {
				t.Errorf("NewDeviceMap(%v) = nil error, want one", tt.m)
			}
		})
	}
}

func TestDeviceMapDiagnostics(t *testing.T) {
	d := testMap(t)

	if d.Len() != 2 {
		t.Errorf("Len() = %d, want 2", d.Len())
	}
	devices := d.Devices()
	if len(devices) != 2 {
		t.Fatalf("Devices() returned %d entries, want 2", len(devices))
	}
	for _, entry := range devices {
		if !strings.HasPrefix(entry[0], `\Device\`) || len(entry[1]) != 2 {
			t.Errorf("Devices() returned a malformed entry %v", entry)
		}
	}

	var nilMap *DeviceMap
	if nilMap.Len() != 0 || nilMap.Devices() != nil {
		t.Error("the nil DeviceMap should report itself empty rather than panic")
	}
	if _, ok := nilMap.Translate(`\Device\HarddiskVolume3\a`); ok {
		t.Error("the nil DeviceMap translated something")
	}
}

// FuzzCanonicalize asserts the one invariant that matters: whatever comes back
// without an error is something the matcher will evaluate. A canonicalizer that
// emitted a path the validator then refused would produce a stream of
// unresolvable violations that looked like an attack.
func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		`\Device\HarddiskVolume5\AllSeer\a.txt`,
		`\Device\HarddiskVolume3\`,
		`\\?\C:\ws\a.txt`,
		`\??\C:\ws\a.txt`,
		`C:\ws\a.txt:Zone.Identifier`,
		`C:\ws\a.txt::$ATTRIBUTE_LIST`,
		`\\localhost\C$\ws\a.txt`,
		`C:`,
		`\`,
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	c := NewCanonicalizer(mustMap(f))

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := c.Canonicalize(raw)
		if err != nil {
			return
		}
		if !validator.IsResolvedWindows(got) {
			t.Fatalf("Canonicalize(%q) = %q, which the matcher refuses", raw, got)
		}
	})
}

func mustMap(f *testing.F) *DeviceMap {
	f.Helper()

	d, err := NewDeviceMap(map[string]string{
		`\Device\HarddiskVolume3`: "C:",
		`\Device\HarddiskVolume5`: "D:",
	})
	if err != nil {
		f.Fatalf("NewDeviceMap: %v", err)
	}
	return d
}
