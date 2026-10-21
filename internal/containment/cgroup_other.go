//go:build !linux

package containment

import "context"

// Manager is unavailable off Linux.
type Manager struct{}

// Group is unavailable off Linux.
type Group struct {
	Session string `json:"session"`
	Path    string `json:"path"`
	ID      uint64 `json:"id"`
}

// NewManager reports that containment is unsupported.
func NewManager(string) (*Manager, error) { return nil, ErrUnsupported }

func (*Manager) Base() string                               { return "" }
func (*Manager) Capabilities() Capabilities                 { return Capabilities{} }
func (*Manager) Governed(int) (string, bool, error)         { return "", false, ErrUnsupported }
func (*Manager) List() ([]*Group, error)                    { return nil, ErrUnsupported }
func (*Manager) Sweep(context.Context) (SweepResult, error) { return SweepResult{}, ErrUnsupported }
func (*Manager) Lock() error                                { return ErrUnsupported }
func (*Manager) Unlock() error                              { return nil }
func (*Manager) Create(string) (*Group, error)              { return nil, ErrUnsupported }
func (*Manager) Open(string) (*Group, error)                { return nil, ErrUnsupported }
func (*Group) Adopt(int) error                              { return ErrUnsupported }
func (*Group) Pids() ([]int, error)                         { return nil, ErrUnsupported }
func (*Group) Freeze(context.Context) error                 { return ErrUnsupported }
func (*Group) Thaw(context.Context) error                   { return ErrUnsupported }
func (*Group) Frozen() (bool, error)                        { return false, ErrUnsupported }
func (*Group) Kill(context.Context) error                   { return ErrUnsupported }
func (*Group) Populated() (bool, error)                     { return false, ErrUnsupported }
func (*Group) WaitEmpty(context.Context) error              { return ErrUnsupported }
func (*Group) Remove() error                                { return ErrUnsupported }
