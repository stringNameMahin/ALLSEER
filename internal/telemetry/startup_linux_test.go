//go:build linux

package telemetry

import (
	"errors"
	"os"
	"testing"
)

// requireCgroupV2 is checked against the host rather than mocked: /proc/mounts
// is not injectable and the value of the check is that it agrees with reality.
// Both outcomes are legitimate, so both are accepted -- what is asserted is that
// it does not return a path and an error, or neither.
//
// That is also why this test is `linux`-tagged rather than skipped elsewhere. A
// skip would still compile the check into every platform's binary and assert
// nothing about it there; the tag says the check does not exist off Linux, which
// is the truth. Off Linux the read failed with a path error rather than
// ErrNoCgroupV2, and the test failed on a finding about the operating system
// rather than about the check.
func TestRequireCgroupV2AgreesWithTheHost(t *testing.T) {
	path, err := requireCgroupV2()
	switch {
	case err != nil:
		if !errors.Is(err, ErrNoCgroupV2) {
			t.Fatalf("unexpected error kind: %v", err)
		}
		if path != "" {
			t.Errorf("got a mount point %q alongside an error", path)
		}
		t.Logf("no cgroup2 on this host; the loader would refuse to start here")
	default:
		if path == "" {
			t.Fatal("no error, but no mount point either")
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Errorf("reported cgroup2 mount %q does not stat: %v", path, statErr)
		}
	}
}

func TestUnescapeMountField(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/sys/fs/cgroup", "/sys/fs/cgroup"},
		{`/mnt/with\040space`, "/mnt/with space"},
		{`/mnt/tab\011here`, "/mnt/tab\there"},
		{`/mnt/back\134slash`, `/mnt/back\slash`},
		{`/mnt/trailing\`, `/mnt/trailing\`},
		{`/mnt/bad\09x`, `/mnt/bad\09x`},
	} {
		if got := unescapeMountField(tc.in); got != tc.want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
