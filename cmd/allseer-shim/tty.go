package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// readLine reads one line from the terminal, giving up when ctx ends. The
// read is retried on a short deadline so cancellation is noticed even while
// nobody types; where the terminal does not support deadlines it blocks.
func readLine(ctx context.Context, tty *os.File) (string, error) {
	var line []byte
	buf := make([]byte, 256)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		_ = tty.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := tty.Read(buf)
		line = append(line, buf[:n]...)
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			return string(line[:i]), nil
		}
		switch {
		case err == nil, errors.Is(err, os.ErrDeadlineExceeded):
		case errors.Is(err, io.EOF):
			return string(line), nil
		default:
			return "", err
		}
	}
}

func isYes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}
