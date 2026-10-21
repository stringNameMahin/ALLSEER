//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// askTTY asks a yes/no question on the controlling terminal.
//
// The agent sharing the terminal may have left it in raw mode, where Enter
// sends a carriage return and nothing is echoed, and it may own the
// terminal's foreground process group, where a read from the shim would stop
// it with SIGTTIN. So the question is asked in line mode with echo and
// CR read as newline, from the foreground, and the terminal is handed back
// exactly as it was found. Input typed before the question is discarded, so
// a key meant for the agent cannot answer it.
//
// It returns ctx's error when ctx ends first, after restoring the terminal.
func askTTY(ctx context.Context, question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer tty.Close()
	rc, err := tty.SyscallConn()
	if err != nil {
		return false, err
	}

	restore, err := takeTerminal(rc)
	if err != nil {
		return false, err
	}
	defer restore()

	fmt.Fprint(tty, question)
	line, err := readLine(ctx, tty)
	if err != nil {
		fmt.Fprintln(tty)
		return false, err
	}
	return isYes(line), nil
}

// takeTerminal makes this process group the terminal's foreground and puts
// the terminal in line mode. The returned function undoes both.
func takeTerminal(rc syscall.RawConn) (func(), error) {
	var (
		saved      syscall.Termios
		fg         int32
		took, mode bool
		ierr       error
	)
	own := int32(syscall.Getpgrp())

	// Changing the foreground, or the terminal's settings, from a background
	// process group raises SIGTTOU, whose default action stops the process.
	signal.Ignore(syscall.SIGTTOU)
	restore := func() {
		_ = rc.Control(func(fd uintptr) {
			if mode {
				_ = ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&saved)))
			}
			if took {
				_ = ioctl(fd, syscall.TIOCSPGRP, uintptr(unsafe.Pointer(&fg)))
			}
		})
		signal.Reset(syscall.SIGTTOU)
	}

	err := rc.Control(func(fd uintptr) {
		if ierr = ioctl(fd, syscall.TIOCGPGRP, uintptr(unsafe.Pointer(&fg))); ierr != nil {
			return
		}
		if fg != own {
			if ierr = ioctl(fd, syscall.TIOCSPGRP, uintptr(unsafe.Pointer(&own))); ierr != nil {
				return
			}
			took = true
		}
		if ierr = ioctl(fd, syscall.TCGETS, uintptr(unsafe.Pointer(&saved))); ierr != nil {
			return
		}
		t := saved
		t.Iflag |= syscall.ICRNL
		t.Iflag &^= syscall.IGNCR | syscall.INLCR
		t.Oflag |= syscall.OPOST | syscall.ONLCR
		t.Lflag |= syscall.ICANON | syscall.ECHO | syscall.ECHOE
		if ierr = ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t))); ierr != nil {
			return
		}
		mode = true
		_ = ioctl(fd, tcflsh, tciflush)
	})
	if err == nil {
		err = ierr
	}
	if err != nil {
		restore()
		return nil, fmt.Errorf("preparing the terminal: %w", err)
	}
	return restore, nil
}

// The syscall package does not name TCFLSH. The value is the same on amd64
// and arm64.
const (
	tcflsh   = 0x540B
	tciflush = 0
)

func ioctl(fd, req, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}
