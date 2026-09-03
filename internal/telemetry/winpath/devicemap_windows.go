//go:build windows

package winpath

import (
	"fmt"
	"syscall"
	"unsafe"
)

// QueryDeviceMap reads the host's drive-letter to NT device mapping.
//
// This is the one Windows-only entry point in the package, and it exists
// because the translation it feeds is mandatory: every path ETW reports is in
// the device namespace, so without this map the matcher sees nothing it can
// evaluate.
//
// The direction of the query is the reverse of the direction of use.
// QueryDosDevice answers "what device is C:", so the map is built by asking
// that for each of the 26 letters and inverting the result. There is no
// documented call that goes the other way, and enumerating volumes with
// FindFirstVolume would need a second call per volume to find its mount points
// anyway.
//
// A letter that resolves to nothing is skipped rather than reported: most hosts
// have most letters unassigned, and an error per empty letter would bury the
// one that matters. An empty map is not an error either -- it is a fact about
// the host, and Canonicalize refuses every device path under it, which is the
// visible failure an operator can act on.
//
// Call it again on a volume mount and hand the result to
// Canonicalizer.SetDeviceMap. The mapping is not stable for the life of a
// process.
func QueryDeviceMap() (*DeviceMap, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	queryDosDevice := kernel32.NewProc("QueryDosDeviceW")
	if err := queryDosDevice.Find(); err != nil {
		return nil, fmt.Errorf("winpath: QueryDosDeviceW unavailable: %w", err)
	}

	// The target of a drive letter is a device name, not a path, so it is short.
	// MAX_PATH would do; this is generous and still one allocation reused for
	// all 26 letters.
	buf := make([]uint16, 1024)
	m := make(map[string]string, 4)

	for letter := byte('A'); letter <= 'Z'; letter++ {
		name, err := syscall.UTF16PtrFromString(string(letter) + ":")
		if err != nil {
			return nil, fmt.Errorf("winpath: encode drive name %c: %w", letter, err)
		}

		n, _, callErr := queryDosDevice.Call(
			uintptr(unsafe.Pointer(name)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if n == 0 {
			// ERROR_FILE_NOT_FOUND for an unassigned letter, which is the
			// common case and not worth reporting. Anything else is worth a
			// wrapped error only if no letter at all resolves, and that shows
			// up as an empty map.
			_ = callErr
			continue
		}

		// The result is a MULTI_SZ. A letter can name several devices; the
		// first is the one the object manager resolves it to.
		target := utf16FirstString(buf[:n])
		if target == "" {
			continue
		}
		m[target] = string(letter) + ":"
	}

	return NewDeviceMap(m)
}

// utf16FirstString decodes the first NUL-terminated string of a MULTI_SZ.
func utf16FirstString(b []uint16) string {
	for i, c := range b {
		if c == 0 {
			return syscall.UTF16ToString(b[:i])
		}
	}
	return syscall.UTF16ToString(b)
}
