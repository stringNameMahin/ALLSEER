//go:build linux

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

type testHandler struct{ streamed chan struct{} }

func (h *testHandler) Call(_ context.Context, peer Peer, method string, params json.RawMessage) (any, error) {
	switch method {
	case MethodStatus:
		return StatusResponse{Version: "test", ProtocolVersion: ProtocolVersion, ActiveSessions: int(peer.UID)}, nil
	case MethodGetEnvelope:
		var r SessionRequest
		_ = json.Unmarshal(params, &r)
		return nil, Errorf(ErrCodeSessionNotFound, "no session %q", r.SessionID)
	}
	return nil, Errorf(ErrCodeInvalidRequest, "unknown method %q", method)
}

func (h *testHandler) Stream(ctx context.Context, _ Peer, _ string, _ json.RawMessage, send func(any) error) error {
	for i := 0; i < 3; i++ {
		if err := send(decision.Decision{ID: string(rune('a' + i))}); err != nil {
			return err
		}
	}
	<-ctx.Done()
	close(h.streamed)
	return nil
}

func serve(t *testing.T) (*SocketServer, *testHandler) {
	t.Helper()
	h := &testHandler{streamed: make(chan struct{})}
	s := &SocketServer{Path: filepath.Join(t.TempDir(), "d.sock"), Mode: 0o600, Handler: h}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = s.Shutdown(context.Background()) })
	return s, h
}

func TestCallCarriesKernelPeerIdentity(t *testing.T) {
	s, _ := serve(t)
	c, err := Dial(context.Background(), s.Path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.ActiveSessions != os.Getuid() {
		t.Fatalf("server saw uid %d, want %d", st.ActiveSessions, os.Getuid())
	}
	fi, _ := os.Stat(s.Path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
}

func TestTypedErrorsCrossTheWire(t *testing.T) {
	s, _ := serve(t)
	c := &SocketClient{Path: s.Path}
	_, err := c.GetEnvelope(context.Background(), "nope")
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrCodeSessionNotFound {
		t.Fatalf("err = %v, want session_not_found", err)
	}
}

func TestProtocolMismatchIsRefused(t *testing.T) {
	s, _ := serve(t)
	conn, err := net.Dial("unix", s.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = writeJSON(conn, request{Protocol: "0", Method: MethodStatus})
	line, err := readLine(newReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	var resp response
	_ = json.Unmarshal(line, &resp)
	if resp.OK || resp.Error == nil || resp.Error.Code != ErrCodeVersionMismatch {
		t.Fatalf("response = %s", line)
	}
}

func TestStreamEndsServerSideWhenClientLeaves(t *testing.T) {
	s, h := serve(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := (&SocketClient{Path: s.Path}).StreamDecisions(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := 0; i < 3; i++ {
		got = append(got, (<-ch).ID)
	}
	if got[0] != "a" || got[2] != "c" {
		t.Fatalf("stream = %v", got)
	}
	cancel()
	select {
	case <-h.streamed:
	case <-time.After(3 * time.Second):
		t.Fatal("server-side stream did not end after the client disconnected")
	}
}

func TestDialFailsWithoutDaemon(t *testing.T) {
	if _, err := Dial(context.Background(), filepath.Join(t.TempDir(), "none.sock")); err == nil {
		t.Fatal("Dial succeeded with no daemon")
	}
}

func TestListenRefusesALiveSocket(t *testing.T) {
	s, _ := serve(t)
	other := &SocketServer{Path: s.Path, Handler: &testHandler{}}
	if err := other.Listen(); err == nil {
		t.Fatal("a second server took over a live socket")
	}
}
