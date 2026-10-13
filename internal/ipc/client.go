package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// SocketClient implements Client over the daemon's Unix socket. Each call is
// one connection.
type SocketClient struct {
	Path        string
	DialTimeout time.Duration
}

var _ Client = (*SocketClient)(nil)

// Dial returns a client after checking the daemon answers. A shim must refuse
// to launch when this fails.
func Dial(ctx context.Context, path string) (*SocketClient, error) {
	c := &SocketClient{Path: path, DialTimeout: 2 * time.Second}
	if _, err := c.Status(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *SocketClient) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.DialTimeout}
	if d.Timeout == 0 {
		d.Timeout = 2 * time.Second
	}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("ipc: cannot reach allseerd at %s: %w", c.Path, err)
	}
	return conn, nil
}

func (c *SocketClient) call(ctx context.Context, method string, params, out any) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := send(conn, method, params); err != nil {
		return err
	}
	line, err := readLine(newReader(conn))
	if err != nil {
		return fmt.Errorf("ipc: %s: reading response: %w", method, err)
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("ipc: %s: malformed response: %w", method, err)
	}
	if !resp.OK {
		if resp.Error != nil {
			return resp.Error
		}
		return fmt.Errorf("ipc: %s failed", method)
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("ipc: %s: decoding result: %w", method, err)
		}
	}
	return nil
}

func send(conn net.Conn, method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("ipc: encoding params: %w", err)
		}
		raw = b
	}
	return writeJSON(conn, request{Protocol: ProtocolVersion, Method: method, Params: raw})
}

// stream opens a streaming method and decodes each item with decode.
func stream[T any](ctx context.Context, c *SocketClient, method string, params any) (<-chan T, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := send(conn, method, params); err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := newReader(conn)
	line, err := readLine(r)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ipc: %s: %w", method, err)
	}
	var ack response
	if err := json.Unmarshal(line, &ack); err != nil || !ack.OK {
		_ = conn.Close()
		if ack.Error != nil {
			return nil, ack.Error
		}
		return nil, fmt.Errorf("ipc: %s was refused", method)
	}

	out := make(chan T, 64)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	go func() {
		defer close(out)
		defer stop()
		defer conn.Close()
		for {
			line, err := readLine(r)
			if err != nil {
				return
			}
			var resp response
			if json.Unmarshal(line, &resp) != nil || !resp.OK {
				return
			}
			var v T
			if json.Unmarshal(resp.Result, &v) != nil {
				return
			}
			select {
			case out <- v:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// CreateSession implements Client.
func (c *SocketClient) CreateSession(ctx context.Context, req CreateSessionRequest) (*CreateSessionResponse, error) {
	var out CreateSessionResponse
	return &out, c.call(ctx, MethodCreateSession, req, &out)
}

// ApproveEnvelope implements Client.
func (c *SocketClient) ApproveEnvelope(ctx context.Context, req ApproveEnvelopeRequest) error {
	return c.call(ctx, MethodApproveEnvelope, req, nil)
}

// StartSession implements Client.
func (c *SocketClient) StartSession(ctx context.Context, sessionID string, rootPID int32) error {
	return c.call(ctx, MethodStartSession, StartSessionRequest{SessionID: sessionID, RootPID: rootPID}, nil)
}

// EndSession implements Client.
func (c *SocketClient) EndSession(ctx context.Context, sessionID string, exitCode int) (*session.Session, error) {
	var out session.Session
	return &out, c.call(ctx, MethodEndSession, EndSessionRequest{SessionID: sessionID, ExitCode: exitCode}, &out)
}

// GetSession implements Client.
func (c *SocketClient) GetSession(ctx context.Context, sessionID string) (*session.Session, error) {
	var out session.Session
	return &out, c.call(ctx, MethodGetSession, SessionRequest{SessionID: sessionID}, &out)
}

// ListSessions implements Client.
func (c *SocketClient) ListSessions(ctx context.Context, f session.Filter) ([]*session.Session, error) {
	var out []*session.Session
	return out, c.call(ctx, MethodListSessions, f, &out)
}

// GetEnvelope implements Client.
func (c *SocketClient) GetEnvelope(ctx context.Context, sessionID string) (*ece.Envelope, error) {
	var out ece.Envelope
	return &out, c.call(ctx, MethodGetEnvelope, SessionRequest{SessionID: sessionID}, &out)
}

// StreamDecisions implements Client. An empty session ID streams every
// session the caller may see.
func (c *SocketClient) StreamDecisions(ctx context.Context, sessionID string) (<-chan decision.Decision, error) {
	return stream[decision.Decision](ctx, c, MethodStreamDecisions, SessionRequest{SessionID: sessionID})
}

// PendingApprovals implements Client.
func (c *SocketClient) PendingApprovals(ctx context.Context) ([]decision.ApprovalRequest, error) {
	var out []decision.ApprovalRequest
	return out, c.call(ctx, MethodPendingApprovals, nil, &out)
}

// RespondApproval implements Client.
func (c *SocketClient) RespondApproval(ctx context.Context, resp decision.ApprovalResponse) error {
	return c.call(ctx, MethodRespondApproval, resp, nil)
}

// StreamApprovals implements Client.
func (c *SocketClient) StreamApprovals(ctx context.Context) (<-chan decision.ApprovalRequest, error) {
	return stream[decision.ApprovalRequest](ctx, c, MethodStreamApprovals, nil)
}

// Status implements Client.
func (c *SocketClient) Status(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	return &out, c.call(ctx, MethodStatus, nil, &out)
}

// ReloadPolicy implements Client.
func (c *SocketClient) ReloadPolicy(ctx context.Context) error {
	return c.call(ctx, MethodReloadPolicy, nil, nil)
}

// Close implements Client. Connections are per call, so there is nothing to
// release.
func (c *SocketClient) Close() error { return nil }
