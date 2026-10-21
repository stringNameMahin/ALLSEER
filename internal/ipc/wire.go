package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Wire format: newline-delimited JSON over a Unix stream socket, one request
// per connection.
//
//	client -> {"protocol":"1","method":"Status","params":{...}}
//	server -> {"ok":true,"result":{...}}            one line for a call
//	server -> {"ok":true} then one line per item     for a stream
//	server -> {"ok":false,"error":{"code":...}}      on failure
//
// Every request carries the protocol version and the server refuses a
// mismatch before reading params, so an old client never has a new request
// half-understood.

const maxLine = 4 << 20

type request struct {
	Protocol string          `json:"protocol"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Method names.
const (
	MethodCreateSession    = "CreateSession"
	MethodApproveEnvelope  = "ApproveEnvelope"
	MethodStartSession     = "StartSession"
	MethodEndSession       = "EndSession"
	MethodGetSession       = "GetSession"
	MethodListSessions     = "ListSessions"
	MethodGetEnvelope      = "GetEnvelope"
	MethodStreamDecisions  = "StreamDecisions"
	MethodPendingApprovals = "PendingApprovals"
	MethodRespondApproval  = "RespondApproval"
	MethodStreamApprovals  = "StreamApprovals"
	MethodStatus           = "Status"
	MethodReloadPolicy     = "ReloadPolicy"
	MethodListLeftovers    = "ListLeftovers"
	MethodThawLeftover     = "ThawLeftover"
	MethodKillLeftover     = "KillLeftover"
)

// IsStream reports whether a method streams results.
func IsStream(method string) bool {
	return method == MethodStreamDecisions || method == MethodStreamApprovals
}

func newReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 64<<10) }

func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxLine {
			return nil, errors.New("ipc: message exceeds the size limit")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: encoding: %w", err)
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// Errorf builds a typed protocol error.
func Errorf(code ErrorCode, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// AsError converts any error into a protocol error.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: ErrCodeInternal, Message: err.Error()}
}
