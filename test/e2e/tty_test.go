package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// The approval prompt under a terminal agent. The shim runs with a pseudo
// terminal as its controlling terminal, the way a user's shell would start
// it, and the agent puts that terminal in raw mode the way a TUI does.

// openPTY returns a pseudo-terminal pair. The slave is handed to the agent
// user so the shim, running as that user, can open /dev/tty.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals on this host: %v", err)
	}
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Fatalf("unlocking the pty: %v", errno)
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		t.Fatalf("naming the pty: %v", errno)
	}
	name := "/dev/pts/" + strconv.Itoa(int(n))
	if err := os.Chown(name, agentUID, agentUID); err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// screen collects what the shim and the agent write to the terminal.
type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *screen) waitFor(t *testing.T, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !strings.Contains(s.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("%q never appeared on the terminal:\n%s", want, s.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type ttyRun struct {
	cmd    *exec.Cmd
	master *os.File
	screen *screen
	done   chan error
}

// shimOnTTY starts the shim as the agent user in a new session whose
// controlling terminal is a fresh pty, with terminal approvals on and no mode
// requested, so the daemon's default applies.
func shimOnTTY(t *testing.T, socket, ws, agent string) *ttyRun {
	t.Helper()
	master, slave := openPTY(t)
	cmd := exec.Command(filepath.Join(e.bin, "allseer-shim"), "-socket", socket, "-yes", "-quiet",
		"-prompt", "build the project and run the tests", "-workspace", ws, "--", agent)
	cmd.Dir = ws
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + ws, "TERM=xterm"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, Setctty: true, Ctty: 0,
		Credential: &syscall.Credential{Uid: agentUID, Gid: agentUID},
	}
	r := &ttyRun{cmd: cmd, master: master, screen: &screen{}, done: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			_, _ = r.screen.Write(b[:n])
			if err != nil {
				return
			}
		}
	}()
	go func() { r.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
	})
	return r
}

func (r *ttyRun) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case err := <-r.done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(d):
		_ = r.cmd.Process.Kill()
		t.Fatalf("shim did not exit within %s:\n%s", d, r.screen.String())
	}
	return -1
}

func (r *ttyRun) sessionID(t *testing.T) string {
	t.Helper()
	r.screen.waitFor(t, "[allseer] session ", 10*time.Second)
	m := sessionLine.FindStringSubmatch(r.screen.String())
	if m == nil {
		t.Fatalf("no session id on the terminal:\n%s", r.screen.String())
	}
	return m[1]
}

// stillRaw reports whether a `stty -a` capture shows the raw mode the agent
// set: no canonical input and no echo.
func stillRaw(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the agent did not record its terminal after resuming: %v", err)
	}
	fields := strings.Fields(string(b))
	has := func(f string) bool {
		for _, x := range fields {
			if x == f {
				return true
			}
		}
		return false
	}
	if !has("-icanon") || !has("-echo") {
		t.Fatalf("the agent's terminal was not handed back raw:\n%s", b)
	}
}

const promptText = "approve and resume? [y/N]"

// interactive is the default, and its prompt works on a terminal a TUI agent
// has put in raw mode: Enter arrives as a carriage return and is accepted,
// and the terminal is raw again when the agent resumes.
func TestInteractiveDefaultPromptsOnARawTerminal(t *testing.T) {
	d := startDaemonWith(t, "", "")
	ctx := context.Background()

	t.Run("raw mode", func(t *testing.T) {
		ws := workspace(t)
		marker, after := filepath.Join(ws, "finished"), filepath.Join(ws, "after")
		r := shimOnTTY(t, d.socket, ws, script(t, fmt.Sprintf(`stty raw -echo
(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null
sleep 2
stty -a > %s
echo x > %s`, after, marker)))
		sid := r.sessionID(t)
		r.screen.waitFor(t, promptText, 20*time.Second)
		if _, err := r.master.Write([]byte("y\r")); err != nil {
			t.Fatal(err)
		}
		if code := r.wait(t, 20*time.Second); code != 0 {
			t.Fatalf("shim exit = %d\n%s", code, r.screen.String())
		}
		if !exists(marker) {
			t.Fatal("the agent did not finish after approval")
		}
		stillRaw(t, after)
		start, _ := d.framed(t, sid)
		if start.Mode != "interactive" {
			t.Errorf("session mode = %q, want the default interactive", start.Mode)
		}
		approvals := records[decision.Approval](t, d, decision.RecordApproval, sid)
		if len(approvals) != 1 || !approvals[0].Approved {
			t.Errorf("approval records = %+v, want one approval", approvals)
		}
	})

	// A job-control agent hands the terminal's foreground to its own job. The
	// shim is then in a background process group, where reading the terminal
	// would stop it. The job reads its own group and the terminal's foreground
	// group from /proc so the test can check that is the situation.
	t.Run("agent owns the foreground", func(t *testing.T) {
		ws := workspace(t)
		marker, after, fg := filepath.Join(ws, "finished"), filepath.Join(ws, "after"), filepath.Join(ws, "fg")
		r := shimOnTTY(t, d.socket, ws, script(t, fmt.Sprintf(`set -m
stty raw -echo
bash -c 'read -r -a st < /proc/$$/stat; echo ${st[4]} ${st[7]} > %s; (exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null; sleep 2; echo x > %s'
stty -a > %s`, fg, marker, after)))
		r.sessionID(t)
		r.screen.waitFor(t, promptText, 20*time.Second)
		if f := strings.Fields(readFile(t, fg)); len(f) != 2 || f[0] != f[1] || f[0] == strconv.Itoa(r.cmd.Process.Pid) {
			t.Fatalf("the agent's job is not the foreground group apart from the shim's (pgid tpgid = %v, shim %d)",
				f, r.cmd.Process.Pid)
		}
		if _, err := r.master.Write([]byte("y\r")); err != nil {
			t.Fatal(err)
		}
		if code := r.wait(t, 20*time.Second); code != 0 {
			t.Fatalf("shim exit = %d\n%s", code, r.screen.String())
		}
		if !exists(marker) {
			t.Fatal("the agent did not finish after approval")
		}
		stillRaw(t, after)
	})

	// Answered with allseerctl from elsewhere: the question is withdrawn and
	// the terminal is the agent's again by the time it resumes.
	t.Run("answered elsewhere", func(t *testing.T) {
		ws := workspace(t)
		marker, after := filepath.Join(ws, "finished"), filepath.Join(ws, "after")
		r := shimOnTTY(t, d.socket, ws, script(t, fmt.Sprintf(`stty raw -echo
(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null
sleep 2
stty -a > %s
echo x > %s`, after, marker)))
		sid := r.sessionID(t)
		r.screen.waitFor(t, promptText, 20*time.Second)
		pending, err := d.client().PendingApprovals(ctx)
		if err != nil {
			t.Fatal(err)
		}
		id := ""
		for _, p := range pending {
			if p.SessionID == sid {
				id = p.ID
			}
		}
		if id == "" {
			t.Fatalf("no pending approval for %s: %+v", sid, pending)
		}
		if err := d.client().RespondApproval(ctx, decision.ApprovalResponse{RequestID: id, Approved: true}); err != nil {
			t.Fatal(err)
		}
		r.screen.waitFor(t, "settled elsewhere", 10*time.Second)
		if code := r.wait(t, 20*time.Second); code != 0 {
			t.Fatalf("shim exit = %d\n%s", code, r.screen.String())
		}
		if !exists(marker) {
			t.Fatal("the agent did not finish after approval")
		}
		stillRaw(t, after)
	})
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
