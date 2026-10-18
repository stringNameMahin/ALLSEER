// Command allseerd is the ALLSEER governance daemon.
//
// It loads the BPF object, refuses to start if the attribution floor does not
// attach, and serves the control socket that allseer-shim and allseerctl use.
// It must run as root: loading probes, writing the filter map and managing
// session cgroups all need it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/audit"
	"github.com/stringNameMahin/ALLSEER/internal/buildinfo"
	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/internal/daemon"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == selfTestArg {
		os.Exit(selfTestChild(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("allseerd", flag.ContinueOnError)
	var (
		cfgPath     = fs.String("config", "", "YAML configuration file (defaults apply when empty)")
		socket      = fs.String("socket", "", "Override daemon.socket_path")
		object      = fs.String("object", "", "Override telemetry.object_path")
		rules       = fs.String("rules", "", "Override policy.rule_set_path")
		sensitivity = fs.String("sensitivity", "", "Override risk.sensitivity_path")
		auditPath   = fs.String("audit", "", "Override audit.path")
		mode        = fs.String("mode", "", "Override policy.default_mode")
		cgroupBase  = fs.String("cgroup-base", "", "Directory session cgroups are created in")
		check       = fs.Bool("check", false, "Validate configuration and exit")
		version     = fs.Bool("version", false, "Print version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Println(buildinfo.String())
		return 0
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.FileLoader{}.Load(context.Background(), *cfgPath)
	if err != nil {
		log.Error("loading configuration", "err", err)
		return 1
	}
	override(&cfg.Daemon.SocketPath, *socket)
	override(&cfg.Telemetry.ObjectPath, *object)
	override(&cfg.Policy.RuleSetPath, *rules)
	override(&cfg.Risk.SensitivityPath, *sensitivity)
	override(&cfg.Audit.Path, *auditPath)
	if *mode != "" {
		cfg.Policy.DefaultMode = policy.Mode(*mode)
	}
	issues := config.Validate(cfg)
	for _, i := range issues {
		if i.Fatal {
			log.Error("configuration", "field", i.Field, "problem", i.Message)
		} else {
			log.Warn("configuration", "field", i.Field, "problem", i.Message)
		}
	}
	if len(config.Fatal(issues)) > 0 {
		return 1
	}
	if *check {
		fmt.Println("configuration OK")
		return 0
	}

	if err := preflight(cfg); err != nil {
		log.Error("preflight failed; refusing to govern", "err", err)
		return 1
	}

	// SIGHUP shuts down rather than reloading: this build refuses policy
	// reload outright, and the default action for an unhandled SIGHUP kills
	// the daemon without ending its sessions, which leaves governed agents
	// running unobserved.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	rs, err := policy.NewLoader().Load(ctx, cfg.Policy.RuleSetPath)
	if err != nil {
		log.Error("loading rule set", "err", err)
		return 1
	}
	pe, err := policy.NewEngine(rs)
	if err != nil {
		log.Error("building policy engine", "err", err)
		return 1
	}
	oracle, err := risk.LoadResourceOracle(cfg.Risk.SensitivityPath)
	if err != nil {
		log.Error("loading sensitivity list", "err", err)
		return 1
	}
	re, err := risk.NewEngineWithOracle(oracle)
	if err != nil {
		log.Error("building risk engine", "err", err)
		return 1
	}
	sink, err := audit.Open(cfg.Audit)
	if err != nil {
		log.Error("opening audit log", "err", err)
		return 1
	}
	defer sink.Close()

	mgr, err := containment.NewManager(*cgroupBase)
	if err != nil {
		log.Error("session cgroups", "err", err)
		return 1
	}
	caps := mgr.Capabilities()
	if !caps.Freeze {
		log.Error("cgroup.freeze is unavailable; sessions could not be contained")
		return 1
	}
	reportSweep(log, mgr)

	tel, err := newTelemetry(ctx, cfg.Telemetry)
	if err != nil {
		log.Error("telemetry failed to start; refusing to govern", "err", err)
		return 1
	}
	defer tel.Close()
	reportCoverage(log, tel.Coverage())

	d, err := daemon.New(daemon.Options{
		Config:    cfg,
		Telemetry: tel,
		Groups:    daemon.CgroupGroups{M: mgr},
		Host:      daemon.ProcHost{},
		Policy:    pe,
		Risk:      re,
		Audit:     sink,
		Resolvers: daemon.Resolvers("/etc/resolv.conf"),
		Logger:    log,
		Version:   buildinfo.String(),
		Prober:    selfTestProber,
	})
	if err != nil {
		log.Error("building daemon", "err", err)
		return 1
	}

	// Before the control socket exists, so no session can be created on
	// telemetry that has not been shown to report. SelfTest logs the detail.
	if _, err := d.SelfTest(ctx); err != nil {
		return 1
	}

	srv := &ipc.SocketServer{Path: cfg.Daemon.SocketPath, Mode: os.FileMode(cfg.Daemon.SocketMode), Handler: d}
	if err := srv.Listen(); err != nil {
		log.Error("control socket", "err", err)
		return 1
	}
	go func() {
		if err := srv.Serve(ctx); err != nil {
			log.Error("control socket stopped", "err", err)
		}
	}()
	log.Info("allseerd ready", "socket", cfg.Daemon.SocketPath, "mode", cfg.Policy.DefaultMode,
		"audit", cfg.Audit.Path, "enforcer", daemon.MechanismCgroup, "cgroups", mgr.Base())

	runErr := d.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	d.Shutdown(shutdownCtx)
	if runErr != nil {
		log.Error("governance stopped", "err", runErr)
		return 1
	}
	log.Info("allseerd stopped")
	return 0
}

func override(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

// preflight fails with an actionable message rather than with an errno from
// deep inside libbpf.
func preflight(cfg *config.Config) error {
	var problems []string
	if os.Geteuid() != 0 {
		problems = append(problems, "must run as root (loading BPF and managing cgroups need CAP_BPF and CAP_SYS_ADMIN)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		problems = append(problems, "kernel BTF is missing at /sys/kernel/btf/vmlinux (CO-RE needs CONFIG_DEBUG_INFO_BTF)")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		problems = append(problems, "no cgroup v2 unified hierarchy at /sys/fs/cgroup")
	}
	if _, err := os.Stat(cfg.Telemetry.ObjectPath); err != nil {
		problems = append(problems, fmt.Sprintf("BPF object %s: %v (build it with make bpf)", cfg.Telemetry.ObjectPath, err))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// reportSweep clears the empty session cgroups a previous daemon left behind
// and reports the ones that still hold processes. A populated leftover is a
// process tree nothing is governing any more, so it is reported at error level
// rather than cleaned up: the base may be shared with a running daemon, and
// killing somebody else's live session would be worse than naming this one.
func reportSweep(log *slog.Logger, mgr *containment.Manager) {
	res, err := mgr.Sweep()
	if err != nil {
		log.Error("sweeping leftover session cgroups", "base", mgr.Base(), "err", err)
		return
	}
	if len(res.Removed) > 0 {
		log.Info("removed empty session cgroups left by an earlier daemon",
			"base", mgr.Base(), "removed", res.Removed)
	}
	for _, name := range res.Populated {
		log.Error("a leftover session cgroup still holds processes; nothing is governing them",
			"base", mgr.Base(), "session", name)
	}
}

func reportCoverage(log *slog.Logger, cov telemetry.Coverage) {
	attached := 0
	for _, p := range cov.Probes {
		if p.Attached {
			attached++
		} else {
			log.Error("probe not attached: blind spot", "probe", p.Name, "family", p.Family, "err", p.Error)
		}
	}
	log.Info("telemetry coverage", "probes_attached", attached, "observable", cov.Observable,
		"unobservable", cov.Unobservable, "unsupported", cov.Unsupported, "degraded", cov.Degraded)

	// An observable kind is not a fully watched one. Naming the entry points
	// nothing reports keeps "observable" from reading as "nothing gets past
	// this", which for network egress is the difference between watching
	// connect and watching every way out.
	for _, g := range cov.EntryPoints {
		if len(g.Missing) > 0 {
			log.Warn("capability is observed through some entry points but not all",
				"capability", g.Kind, "observed", g.Observed, "unwatched", g.Missing)
		}
		if len(g.SuccessOnly) > 0 {
			log.Warn("entry points recorded only when the kernel permits the operation",
				"capability", g.Kind, "success_only", g.SuccessOnly)
		}
	}
}
