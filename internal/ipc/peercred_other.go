//go:build !linux

package ipc

import (
	"errors"
	"net"
)

func peerOf(net.Conn) (Peer, error) {
	return Peer{}, errors.New("peer credentials are only available on Linux")
}
