package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Peer is the caller as the kernel reports it, never as the request claims.
type Peer struct {
	PID int32  `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// Root reports whether the peer is uid 0.
func (p Peer) Root() bool { return p.UID == 0 }

// Handler serves requests.
type Handler interface {
	// Call answers one request.
	Call(ctx context.Context, peer Peer, method string, params json.RawMessage) (any, error)
	// Stream sends items until ctx ends or it returns. ctx ends when the client
	// disconnects.
	Stream(ctx context.Context, peer Peer, method string, params json.RawMessage, send func(any) error) error
}

// SocketServer serves Handler on a Unix socket.
type SocketServer struct {
	Path    string
	Mode    os.FileMode
	Handler Handler

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

var _ Server = (*SocketServer)(nil)

// Listen creates the socket. It refuses to replace a socket another server is
// still answering on.
func (s *SocketServer) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	if c, err := net.DialTimeout("unix", s.Path, 200*time.Millisecond); err == nil {
		_ = c.Close()
		return fmt.Errorf("ipc: %s is already being served", s.Path)
	}
	_ = os.Remove(s.Path)
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return fmt.Errorf("ipc: listening on %s: %w", s.Path, err)
	}
	mode := s.Mode
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(s.Path, mode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("ipc: %w", err)
	}
	s.mu.Lock()
	s.ln = ln
	s.conns = make(map[net.Conn]context.CancelFunc)
	s.mu.Unlock()
	return nil
}

// Serve accepts until ctx ends or Shutdown is called.
func (s *SocketServer) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.ln == nil {
		s.mu.Unlock()
		if err := s.Listen(); err != nil {
			return err
		}
		s.mu.Lock()
	}
	ln := s.ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			cancel()
			_ = c.Close()
			return nil
		}
		s.conns[c] = cancel
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConn(cctx, cancel, c)
	}
}

// Shutdown stops accepting, cancels open streams, and waits for in-flight
// requests until ctx ends.
func (s *SocketServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, cancel := range s.conns {
		cancel()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	_ = os.Remove(s.Path)
	return nil
}

func (s *SocketServer) serveConn(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
	defer s.wg.Done()
	defer func() {
		cancel()
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()

	peer, err := peerOf(c)
	if err != nil {
		_ = writeJSON(c, response{Error: Errorf(ErrCodePermissionDenied, "cannot identify the caller: %v", err)})
		return
	}

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := newReader(c)
	line, err := readLine(r)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		_ = writeJSON(c, response{Error: Errorf(ErrCodeInvalidRequest, "malformed request: %v", err)})
		return
	}
	if req.Protocol != ProtocolVersion {
		_ = writeJSON(c, response{Error: Errorf(ErrCodeVersionMismatch,
			"protocol %q is not supported; this daemon speaks %q", req.Protocol, ProtocolVersion)})
		return
	}

	if IsStream(req.Method) {
		// The client sends nothing more; a read returning means it went away.
		go func() {
			_, _ = r.ReadByte()
			cancel()
		}()
		var mu sync.Mutex
		mu.Lock()
		err := writeJSON(c, response{OK: true})
		mu.Unlock()
		if err != nil {
			return
		}
		send := func(v any) error {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			return writeJSON(c, response{OK: true, Result: b})
		}
		if err := s.Handler.Stream(ctx, peer, req.Method, req.Params, send); err != nil && ctx.Err() == nil {
			mu.Lock()
			_ = writeJSON(c, response{Error: AsError(err)})
			mu.Unlock()
		}
		return
	}

	result, err := s.Handler.Call(ctx, peer, req.Method, req.Params)
	if err != nil {
		_ = writeJSON(c, response{Error: AsError(err)})
		return
	}
	b, err := json.Marshal(result)
	if err != nil {
		_ = writeJSON(c, response{Error: Errorf(ErrCodeInternal, "encoding result: %v", err)})
		return
	}
	_ = writeJSON(c, response{OK: true, Result: b})
}
