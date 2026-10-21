//go:build !linux

package main

import (
	"context"
	"fmt"
	"os"
)

// askTTY asks a yes/no question on the controlling terminal. Only Linux
// restores a raw-mode terminal around the question; elsewhere it is asked as
// the terminal stands.
func askTTY(ctx context.Context, question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer tty.Close()
	fmt.Fprint(tty, question)
	line, err := readLine(ctx, tty)
	if err != nil {
		return false, err
	}
	return isYes(line), nil
}
