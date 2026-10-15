package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// The startup self-test.
//
// Every probe in this object can be attached and still not report. On one
// kernel update the open probe's entry side stopped running while its exit
// side and every other probe kept going, so the daemon listed 29 probes
// attached, reported coverage as complete, and recorded nothing when an agent
// read /etc/shadow in enforce mode. Attachment is a statement about the kernel
// accepting a program; it says nothing about the program running.
//
// So before governing anything the daemon performs one open and waits for its
// record. The open is chosen so that only the critical probe can report it: a
// path that does not exist. A failed lookup never reaches security_file_open,
// so the kernel-side hook cannot satisfy this check, and the record has to come
// from the openat pair on do_sys_openat2 - the path that reports refused and
// failed opens, which is the one a credential denial depends on. The record
// must carry the probe's return value (ENOENT), not the hook's "outcome
// unobserved" marker and kernel path, or the check fails.
//
// The open runs in a dedicated cgroup, in a separate process the prober starts
// and holds until the cgroup is tracked, the same launch order the shim uses
// for an agent. Its records are consumed here and never reach a pipeline or the
// audit log.

// DefaultSelfTestTimeout bounds how long the self-test waits for its record.
// The record normally arrives in milliseconds; this is a deadline for a probe
// that is not going to report, not a performance target.
const DefaultSelfTestTimeout = 5 * time.Second

// SelfTestProbe names the probe family the self-test proves.
const SelfTestProbe = telemetry.FamilyOpenat

// ErrSelfTestFailed means the critical probe did not report the open the
// self-test performed. The daemon must not govern after it.
var ErrSelfTestFailed = errors.New("daemon: telemetry self-test failed")

// errNoProber is the failure when nothing can start the self-test process.
// Refusing is the only safe reading: a daemon that skipped the check would be
// claiming reliability it never established.
var errNoProber = errors.New("no self-test prober is configured")

// Prober starts a process that, once released, opens path read-only and
// exits. path never exists, so the open fails with ENOENT. The process must
// not open path before release is called: it is moved into the self-test
// cgroup first. wait reaps it.
type Prober func(ctx context.Context, path string) (pid int, release func() error, wait func() error, err error)

// SelfTest proves the critical probe reports before any session is governed,
// and records the result for status and for session creation. It must run
// before Run: it reads the telemetry stream directly.
func (d *Daemon) SelfTest(ctx context.Context) (ipc.SelfTestResult, error) {
	res, err := d.selfTest(ctx)
	res.Probe = SelfTestProbe
	res.At = d.now()
	if err != nil {
		res.Passed = false
		res.Detail = err.Error()
		err = fmt.Errorf("%w: %v", ErrSelfTestFailed, err)
	}
	d.mu.Lock()
	d.selfTestResult = res
	d.mu.Unlock()
	if err != nil {
		d.log.Error("telemetry self-test failed; refusing to govern", "probe", res.Probe, "detail", res.Detail)
	} else {
		d.log.Info("telemetry self-test passed", "probe", res.Probe, "latency", res.Latency, "detail", res.Detail)
	}
	return res, err
}

func (d *Daemon) selfTest(ctx context.Context) (ipc.SelfTestResult, error) {
	var res ipc.SelfTestResult
	if d.prober == nil {
		return res, errNoProber
	}

	tag, err := randomTag()
	if err != nil {
		return res, err
	}
	sid := "selftest-" + tag
	path := filepath.Join(os.TempDir(), "allseer-selftest-"+tag, "absent")

	g, err := d.groups.Create(sid)
	if err != nil {
		return res, fmt.Errorf("creating the self-test cgroup: %w", err)
	}
	defer func() {
		_ = g.Kill(context.Background())
		_ = g.Remove()
	}()

	pid, release, wait, err := d.prober(ctx, path)
	if err != nil {
		return res, fmt.Errorf("starting the self-test process: %w", err)
	}
	reaped := false
	defer func() {
		if !reaped {
			_ = g.Kill(context.Background())
			_ = wait()
		}
	}()

	if err := g.Adopt(pid); err != nil {
		return res, fmt.Errorf("moving the self-test process into its cgroup: %w", err)
	}
	if err := d.tel.AttachCgroup(ctx, sid, g.CgroupID(), int32(pid)); err != nil {
		return res, fmt.Errorf("attaching telemetry to the self-test cgroup: %w", err)
	}
	defer func() { _ = d.tel.DetachSession(context.Background(), sid) }()

	start := d.now()
	if err := release(); err != nil {
		return res, fmt.Errorf("releasing the self-test process: %w", err)
	}

	deadline := time.NewTimer(d.selfTestTimeout)
	defer deadline.Stop()
	var seen []string
	for {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-deadline.C:
			detail := fmt.Sprintf("no record of the failed open of %s from the %s probe within %s",
				path, SelfTestProbe, d.selfTestTimeout)
			if len(seen) > 0 {
				detail += "; saw only: " + fmt.Sprint(seen)
			}
			return res, errors.New(detail)
		case e, ok := <-d.tel.Events():
			if !ok {
				return res, errors.New("the telemetry stream ended during the self-test")
			}
			if e.SessionID != sid || e.File == nil || e.File.Path != path {
				continue
			}
			// The record for our open. It has to be the probe's, with the
			// probe's return value; a record from the kernel-side hook would
			// mean the critical path was not the one that reported.
			switch {
			case e.File.KernelPath || e.Result.OutcomeUnobserved:
				seen = append(seen, "a kernel-hook record with no outcome")
				continue
			case e.Capability != capability.KindFileRead:
				return res, fmt.Errorf("the open of %s was reported as %s, not %s", path, e.Capability, capability.KindFileRead)
			case e.Result.Succeeded || e.Result.Errno != "ENOENT":
				return res, fmt.Errorf("the open of %s was reported with result %+v, not ENOENT", path, e.Result)
			}
			res.Passed = true
			res.Latency = d.now().Sub(start)
			res.Detail = fmt.Sprintf("a failed open of %s was reported by the %s probe with ENOENT", path, SelfTestProbe)
			reaped = true
			_ = wait()
			return res, nil
		}
	}
}

// selfTestPassed reports whether the startup self-test established that the
// critical probe reports. Nothing is governed until it has.
func (d *Daemon) selfTestPassed() (ipc.SelfTestResult, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.selfTestResult, d.selfTestResult.Passed
}

func randomTag() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
