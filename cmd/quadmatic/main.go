package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"quadmatic/internal/apply"
	"quadmatic/internal/config"
	"quadmatic/internal/manifest"
	"quadmatic/internal/metrics"
	"quadmatic/internal/quadlet"
	"quadmatic/pkg/users"
)

const (
	defaultConfigPath   = "/etc/quadmatic/config.toml"
	metricsShutdownWait = 5 * time.Second
)

type reconcileRunner interface {
	Reconcile(ctx context.Context, opts apply.ReconcileOptions) (*apply.Result, error)
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printTopUsage(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		printTopUsage(stdout)
		return 0
	case "daemon":
		return runDaemon(ctx, args[1:], stdout, stderr)
	case "apply":
		return runApply(ctx, args[1:], stdout, stderr)
	case "validate":
		return runValidate(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n\n", args[0])
		printTopUsage(stderr)
		return 2
	}
}

func printTopUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: quadmatic <command> [flags]

Commands:
  daemon     Run the periodic GitOps reconciliation daemon and optional /metrics server
  apply      Run a single reconciliation pass (or --dry-run plan)
  validate   Offline validation for manifests, collisions, templates, and quadlets

Run "quadmatic <command> --help" for command-specific flags.
`)
}

func parseSubcommandFlags(fs *flag.FlagSet, args []string, header string, stdout, stderr io.Writer) (helpShown bool, ok bool) {
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, header)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return true, true
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n\n%s", err, header)
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		return false, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: unexpected positional argument(s): %s\n\n%s", strings.Join(fs.Args(), " "), header)
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		return false, false
	}
	return false, true
}

func runDaemon(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to host config.toml")

	header := "Usage: quadmatic daemon [--config /etc/quadmatic/config.toml]\n\nFlags:\n"
	if helpShown, ok := parseSubcommandFlags(fs, args, header, stdout, stderr); !ok {
		return 2
	} else if helpShown {
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config %q: %v\n", *configPath, err)
		return 1
	}

	return runDaemonWithFactory(ctx, cfg, stdout, stderr, nil)
}

func runDaemonWithFactory(
	ctx context.Context,
	cfg *config.HostConfig,
	_ io.Writer,
	stderr io.Writer,
	factory func(*config.HostConfig) reconcileRunner,
) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	rec := metrics.NewRecorder(cfg.Hostname)

	var (
		srv      *http.Server
		srvErrCh chan error
	)
	if cfg.MetricsListen != "" {
		var err error
		srv, err = metrics.NewServer(cfg.MetricsListen, rec)
		if err != nil {
			fmt.Fprintf(stderr, "configure metrics server %q: %v\n", cfg.MetricsListen, err)
			return 1
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			fmt.Fprintf(stderr, "bind metrics server %q: %v\n", srv.Addr, err)
			return 1
		}
		srvErrCh = make(chan error, 1)
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				srvErrCh <- err
			}
		}()
		logger.Info("metrics server listening", "addr", ln.Addr().String())
	}

	var engine reconcileRunner
	if factory != nil {
		engine = factory(cfg)
	} else {
		engine = apply.NewEngine(apply.EngineDeps{
			Config: cfg,
			Logger: logger,
		})
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)

	runOnce := func() {
		// Finish an active reconcile pass cleanly if shutdown arrives mid-run.
		reconcileCtx := context.WithoutCancel(sigCtx)
		res, err := engine.Reconcile(reconcileCtx, apply.ReconcileOptions{})
		rec.RecordResult(res, err)
		if err != nil {
			failedStage := ""
			rolledBack := false
			if res != nil {
				failedStage = res.FailedStage
				rolledBack = res.RolledBack
			}
			logger.Error("reconcile failed", "stage", failedStage, "rolled_back", rolledBack, "err", err)
			return
		}
		logger.Info("reconcile completed",
			"sha", res.AppliedSHA,
			"drift", res.DriftDetected,
			"rootless_units", res.ManagedUnitsRootless,
			"rootful_units", res.ManagedUnitsRootful,
			"duration", res.Duration,
		)
	}

	if sigCtx.Err() == nil {
		runOnce()
	}

	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var srvRuntimeErr error
	for sigCtx.Err() == nil {
		select {
		case <-sigCtx.Done():
		case err := <-srvErrCh:
			srvRuntimeErr = err
			logger.Error("metrics server failed", "err", err)
			stopSignals()
		case <-ticker.C:
			if sigCtx.Err() == nil {
				runOnce()
			}
		case <-sighupCh:
			if sigCtx.Err() == nil {
				logger.Info("received SIGHUP, triggering immediate reconcile")
				runOnce()
			}
		}
	}

	if srv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownWait)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "shutdown metrics server: %v\n", err)
			return 1
		}
	}
	if srvRuntimeErr != nil {
		fmt.Fprintf(stderr, "metrics server failed: %v\n", srvRuntimeErr)
		return 1
	}
	return 0
}

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to host config.toml")
	dryRun := fs.Bool("dry-run", false, "plan and validate without mutating the host")
	allowNonFF := fs.Bool("allow-non-ff", false, "allow validly signed non-fast-forward Git updates")
	repoPath := fs.String("repo-path", "", "apply from a local Git repository instead of fetching over SSH")
	noVerify := fs.Bool("no-verify", false, "skip SSH commit signature verification (local --repo-path dev only)")

	header := "Usage: quadmatic apply [--config /etc/quadmatic/config.toml] [--dry-run] [--allow-non-ff] [--repo-path <dir>] [--no-verify]\n\nFlags:\n"
	if helpShown, ok := parseSubcommandFlags(fs, args, header, stdout, stderr); !ok {
		return 2
	} else if helpShown {
		return 0
	}

	if *noVerify && strings.TrimSpace(*repoPath) == "" {
		fmt.Fprintln(stderr, "error: --no-verify is only valid together with --repo-path")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config %q: %v\n", *configPath, err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	engine := apply.NewEngine(apply.EngineDeps{
		Config: cfg,
		Logger: logger,
	})

	res, err := engine.Reconcile(ctx, apply.ReconcileOptions{
		DryRun:        *dryRun,
		AllowNonFF:    *allowNonFF,
		LocalRepoPath: *repoPath,
		NoVerify:      *noVerify,
	})
	if res != nil && res.PlanSummary != "" {
		fmt.Fprint(stdout, res.PlanSummary)
		if !strings.HasSuffix(res.PlanSummary, "\n") {
			fmt.Fprintln(stdout)
		}
	}
	if err != nil {
		if res != nil && res.FailedStage != "" {
			fmt.Fprintf(stderr, "apply failed at stage %s (rolled_back=%v): %v\n", res.FailedStage, res.RolledBack, err)
		} else {
			fmt.Fprintf(stderr, "apply failed: %v\n", err)
		}
		return 1
	}
	return 0
}

func runValidate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	repoPathFlag := fs.String("repo-path", "", "path to local quadmatic Git repository (required)")
	hostFlag := fs.String("host", "", "specific hostname to validate (defaults to all hosts/*.toml)")

	header := "Usage: quadmatic validate --repo-path <dir> [--host <hostname>]\n\nFlags:\n"
	if helpShown, ok := parseSubcommandFlags(fs, args, header, stdout, stderr); !ok {
		return 2
	} else if helpShown {
		return 0
	}

	repoPath := strings.TrimSpace(*repoPathFlag)
	if repoPath == "" {
		fmt.Fprintf(stderr, "error: --repo-path is required\n\n%s", header)
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		return 2
	}
	repoInfo, err := os.Stat(repoPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate repo %q: %v\n", repoPath, err)
		return 1
	}
	if !repoInfo.IsDir() {
		fmt.Fprintf(stderr, "validate repo %q: not a directory\n", repoPath)
		return 1
	}

	reg, err := users.LoadRegistry(filepath.Join(repoPath, "users.toml"))
	if err != nil {
		fmt.Fprintf(stderr, "validate users.toml: %v\n", err)
		return 1
	}

	hosts, err := collectValidateHosts(repoPath, strings.TrimSpace(*hostFlag))
	if err != nil {
		fmt.Fprintf(stderr, "discover hosts: %v\n", err)
		return 1
	}

	var qVal *quadlet.Validator
	if info, statErr := os.Stat(quadlet.DefaultQuadletBinary); statErr == nil && !info.IsDir() {
		qVal = quadlet.NewValidator(quadlet.DefaultQuadletBinary, nil)
	}

	hadError := false
	for _, hostname := range hosts {
		resolved, err := manifest.LoadHost(repoPath, hostname, reg)
		if err != nil {
			fmt.Fprintf(stderr, "validate %s: %v\n", hostname, err)
			hadError = true
			continue
		}
		if err := manifest.Validate(resolved, repoPath); err != nil {
			fmt.Fprintf(stderr, "validate %s: %v\n", hostname, err)
			hadError = true
			continue
		}
		rendered, err := manifest.RenderHost(resolved, manifest.RenderEnv{DryRun: true})
		if err != nil {
			fmt.Fprintf(stderr, "validate %s: %v\n", hostname, err)
			hadError = true
			continue
		}

		var units map[string]quadlet.GeneratedUnit
		if qVal != nil {
			units, err = qVal.ValidateHost(ctx, rendered)
			if err != nil {
				fmt.Fprintf(stderr, "validate %s: %v\n", hostname, err)
				hadError = true
				continue
			}
		}

		quadletCount, dataCount := countRenderedFiles(rendered)
		if qVal != nil {
			fmt.Fprintf(stdout, "OK %s: %d component(s), %d quadlet file(s), %d data file(s), %d generated unit(s)\n",
				hostname, len(rendered.Components), quadletCount, dataCount, len(units))
		} else {
			fmt.Fprintf(stdout, "OK %s: %d component(s), %d quadlet file(s), %d data file(s) (quadlet dry-run skipped: %s not found)\n",
				hostname, len(rendered.Components), quadletCount, dataCount, quadlet.DefaultQuadletBinary)
		}
		if rendered.UsedPlaceholderDNS {
			fmt.Fprintf(stdout, "Note (%s): placeholder DNS (%s) used for dns_from_dhcp components during offline validation\n",
				hostname, manifest.PlaceholderDNS)
		}
	}

	if hadError {
		return 1
	}
	return 0
}

func collectValidateHosts(repoPath, targetHost string) ([]string, error) {
	if targetHost != "" {
		return []string{targetHost}, nil
	}

	hostsDir := filepath.Join(repoPath, "hosts")
	entries, err := os.ReadDir(hostsDir)
	if err != nil {
		return nil, fmt.Errorf("read hosts directory %q: %w", hostsDir, err)
	}

	var hosts []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".toml") && len(name) > len(".toml") {
			hosts = append(hosts, strings.TrimSuffix(name, ".toml"))
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no host manifests (*.toml) found in %q", hostsDir)
	}
	slices.Sort(hosts)
	return hosts, nil
}

func countRenderedFiles(rendered *manifest.RenderedHost) (quadlets, data int) {
	for _, comp := range rendered.Components {
		for _, f := range comp.Files {
			switch f.Kind {
			case manifest.FileKindQuadlet:
				quadlets++
			case manifest.FileKindData:
				data++
			}
		}
	}
	return quadlets, data
}
