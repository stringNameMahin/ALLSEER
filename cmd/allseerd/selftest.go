package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// selfTestArg makes allseerd run as the startup self-test's process instead of
// as the daemon. Not a flag: it is the first argument, checked before flag
// parsing, so no configuration can turn the daemon into it by accident.
const selfTestArg = "__allseer_selftest_open"

// Exit codes of the self-test process. The daemon reads the record, not these;
// they exist so a failure is legible in a process listing or a log.
const (
	selfTestOK         = 0
	selfTestBadArgs    = 2
	selfTestGateClosed = 3
	selfTestOpened     = 4
)

// selfTestChild waits on the gate, then opens path once. The daemon moves it
// into the self-test cgroup and tracks that cgroup before releasing the gate,
// so the open is the first thing it does that telemetry can see. path never
// exists; an open that succeeds means the self-test picked a name it should
// not have, and is reported as such rather than treated as a pass.
func selfTestChild(args []string) int {
	if len(args) != 1 {
		return selfTestBadArgs
	}
	gate := os.NewFile(3, "gate")
	var b [1]byte
	n, _ := gate.Read(b[:])
	_ = gate.Close()
	if n != 1 || b[0] != 'g' {
		return selfTestGateClosed
	}
	fd, err := syscall.Open(args[0], syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return selfTestOpened
	}
	return selfTestOK
}

// selfTestProber starts this binary as the self-test process, held on a gate
// until the daemon calls release. The launch order is the shim's: start,
// adopt into the cgroup, attach telemetry, release.
func selfTestProber(ctx context.Context, path string) (int, func() error, func() error, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("locating allseerd: %w", err)
	}
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return 0, nil, nil, err
	}
	cmd := exec.CommandContext(ctx, self, selfTestArg, path)
	cmd.ExtraFiles = []*os.File{gateR}
	if err := cmd.Start(); err != nil {
		_ = gateR.Close()
		_ = gateW.Close()
		return 0, nil, nil, fmt.Errorf("starting the self-test process: %w", err)
	}
	_ = gateR.Close()

	release := func() error {
		_, err := gateW.Write([]byte{'g'})
		_ = gateW.Close()
		return err
	}
	wait := func() error {
		// Closing the gate unreleased makes the process read EOF and exit
		// without opening anything.
		_ = gateW.Close()
		err := cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == selfTestOpened {
			return fmt.Errorf("the self-test path %s exists", path)
		}
		return err
	}
	return cmd.Process.Pid, release, wait, nil
}
