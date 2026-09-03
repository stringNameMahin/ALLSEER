//go:build windows

package winpath

import (
	"os"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
)

// These run against the live host rather than a fixture. That is the point:
// the device map is the one part of this package whose correctness is a claim
// about Windows, and a fixture would only assert that the fixture is what the
// author expected.

func TestQueryDeviceMapLiveHost(t *testing.T) {
	d, err := QueryDeviceMap()
	if err != nil {
		t.Fatalf("QueryDeviceMap: %v", err)
	}
	if d.Len() == 0 {
		t.Fatal("no drive letters resolved to a device; every reported path would be refused")
	}

	sawSystemDrive := false
	for _, entry := range d.Devices() {
		device, drive := entry[0], entry[1]
		if !strings.HasPrefix(strings.ToLower(device), `\device\`) {
			t.Errorf("drive %s resolved to %q, which is not an NT device name", drive, device)
		}
		if strings.HasSuffix(device, `\`) {
			t.Errorf("drive %s resolved to %q, which has a trailing separator", drive, device)
		}
		if drive == os.Getenv("SystemDrive") {
			sawSystemDrive = true
		}
	}
	if !sawSystemDrive {
		t.Errorf("the system drive %q is not in the map: %v", os.Getenv("SystemDrive"), d.Devices())
	}
}

// TestCanonicalizeRoundTripsALiveDevicePath is the end-to-end claim. A real
// path on this host is rewritten into the form ETW would report it in, pushed
// through the canonicalizer, and must come back as the path we started with --
// and as something the matcher accepts.
func TestCanonicalizeRoundTripsALiveDevicePath(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if len(exe) < 2 || exe[1] != ':' {
		t.Skipf("test binary is not on a lettered drive: %q", exe)
	}
	drive := strings.ToUpper(exe[:2])

	d, err := QueryDeviceMap()
	if err != nil {
		t.Fatalf("QueryDeviceMap: %v", err)
	}

	var device string
	for _, entry := range d.Devices() {
		if entry[1] == drive {
			device = entry[0]
			break
		}
	}
	if device == "" {
		t.Skipf("drive %s has no device mapping on this host", drive)
	}

	ntPath := device + exe[2:]
	got, err := NewCanonicalizer(d).Canonicalize(ntPath)
	if err != nil {
		t.Fatalf("Canonicalize(%q): %v", ntPath, err)
	}

	want := drive + exe[2:]
	if got != want {
		t.Errorf("Canonicalize(%q) = %q, want %q", ntPath, got, want)
	}
	if !validator.IsResolvedWindows(got) {
		t.Errorf("the canonicalized live path %q is one the matcher refuses", got)
	}

	// And the whole point of the exercise: a selector written against the
	// Win32 path covers the event ETW would have reported in device form.
	pattern := drive + `\**`
	if !validator.MatchWindowsPath(pattern, got) {
		t.Errorf("MatchWindowsPath(%q, %q) = false; the translation bought nothing", pattern, got)
	}
}
