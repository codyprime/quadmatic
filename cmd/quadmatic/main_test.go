package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"quadmatic/internal/apply"
	"quadmatic/internal/config"
)

func TestValidateSubcommandPassesValidRepoAndFailsCollision(t *testing.T) {
	repoDir := t.TempDir()
	writeRepoFiles(t, repoDir, map[string]string{
		"users.toml": `
[users.openwebui]
uid = 2001

[users.caddy]
uid = 2002
`,
		"hosts/services-02.toml": `
hostname = "services-02"

[vars]
domain = "lan.example.com"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`,
		"components/open-webui/component.toml": `
[ports]
http = { port = 8080, protocol = "tcp", host_ip = "127.0.0.1" }
`,
		"components/open-webui/open-webui.container": `[Container]
Image=ghcr.io/open-webui/open-webui:main
`,
		"components/open-webui/open-webui.volume": "[Volume]\n",
		"components/caddy/component.toml": `
[ports]
http = { port = 80, protocol = "tcp" }
`,
		"components/caddy/caddy.container.tmpl": `[Container]
Image=docker.io/library/caddy:2
Volume={{ .Component.DataDir }}/Caddyfile:/etc/caddy/Caddyfile:ro
`,
		"components/caddy/files/Caddyfile.tmpl": `chat.{{ index .Host.Vars "domain" }} {
  reverse_proxy 127.0.0.1:{{ (index .Host.Components "open-webui").Ports.http.Port }}
}
`,
	})

	// 1. Validate specific host -> exit 0.
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"validate", "--repo-path", repoDir, "--host", "services-02"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate --host services-02 failed (code=%d)\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "services-02") {
		t.Fatalf("expected stdout summary to mention services-02, got:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr on valid repo, got:\n%s", stderr.String())
	}

	// 2. Validate without --host discovers all hosts/*.toml -> exit 0.
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"validate", "--repo-path", repoDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate (all hosts) failed (code=%d)\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "services-02") {
		t.Fatalf("expected stdout summary to mention services-02, got:\n%s", stdout.String())
	}

	// 2b. Validate a rootless [component.network] + dns_from_dhcp = true host offline.
	netRepoDir := t.TempDir()
	writeRepoFiles(t, netRepoDir, map[string]string{
		"users.toml": `
[users.openwebui]
uid = 2001
`,
		"hosts/services-02.toml": `
hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns_from_dhcp = true
tcp_ports = ["8080:8080"]
`,
		"components/open-webui/open-webui.container.tmpl": `[Container]
Image=ghcr.io/open-webui/open-webui:main
Network={{ .Net.PastaArgs }}
{{- range .Net.DNS }}
DNS={{ . }}
{{- end }}
`,
	})
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"validate", "--repo-path", netRepoDir, "--host", "services-02"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate network host failed (code=%d)\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "192.0.2.53") {
		t.Fatalf("expected placeholder DNS note in validate stdout, got:\n%s", stdout.String())
	}

	// 3. Introduce a default-VRF port collision -> exit non-zero with clear stderr message.
	writeRepoFiles(t, repoDir, map[string]string{
		"components/caddy/component.toml": `
[ports]
http = { port = 8080, protocol = "tcp" }
`,
	})
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"validate", "--repo-path", repoDir, "--host", "services-02"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit on port collision, got 0\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "collision") || !strings.Contains(stderr.String(), "8080") {
		t.Fatalf("expected port collision error on stderr, got:\n%s", stderr.String())
	}

	// 4. Restore valid port, break quadlet syntax if /usr/libexec/podman/quadlet exists -> exit non-zero.
	if _, err := os.Stat("/usr/libexec/podman/quadlet"); err == nil {
		writeRepoFiles(t, repoDir, map[string]string{
			"components/caddy/component.toml": `
[ports]
http = { port = 80, protocol = "tcp" }
`,
			"components/open-webui/open-webui.container": "[Container]\nContainerName=missing-image\n",
		})
		stdout.Reset()
		stderr.Reset()
		code = run(context.Background(), []string{"validate", "--repo-path", repoDir, "--host", "services-02"}, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("expected non-zero exit when quadlet --dryrun rejects invalid unit")
		}
		if stderr.Len() == 0 {
			t.Fatalf("expected quadlet validation error on stderr")
		}
	}
}

func TestApplyDryRunSubcommandWithLocalRepo(t *testing.T) {
	base := t.TempDir()
	repoDir := filepath.Join(base, "repo")
	stateFile := filepath.Join(base, "state", "state.json")
	bareDir := filepath.Join(base, "bare.git")

	signingKey := filepath.Join(base, "signing_ed25519")
	generateTestSSHKey(t, signingKey)
	pubBytes, err := os.ReadFile(signingKey + ".pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	allowedSigners := filepath.Join(base, "allowed-signers")
	if err := os.WriteFile(allowedSigners, []byte("ci@example.lan "+strings.TrimSpace(string(pubBytes))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deployKey := filepath.Join(base, "deploy_key")
	knownHosts := filepath.Join(base, "known_hosts")
	if err := os.WriteFile(deployKey, []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("git.example.lan ssh-ed25519 AAAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mustGitCmd(t, "", "init", "-b", "main", repoDir)
	mustGitCmd(t, repoDir, "config", "user.name", "CI Signer")
	mustGitCmd(t, repoDir, "config", "user.email", "ci@example.lan")
	mustGitCmd(t, repoDir, "config", "gpg.format", "ssh")

	writeRepoFiles(t, repoDir, map[string]string{
		"users.toml": `
[users.openwebui]
uid = 2001

[users.caddy]
uid = 2002
`,
		"hosts/services-02.toml": `
hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`,
		"components/open-webui/component.toml": `
[ports]
http = { port = 8080, protocol = "tcp", host_ip = "127.0.0.1" }
`,
		"components/open-webui/open-webui.container": `[Container]
Image=ghcr.io/open-webui/open-webui:main
`,
		"components/open-webui/open-webui.volume": "[Volume]\n",
		"components/caddy/component.toml": `
[ports]
http = { port = 80, protocol = "tcp" }
`,
		"components/caddy/caddy.container": `[Container]
Image=docker.io/library/caddy:2
`,
	})
	mustGitCmd(t, repoDir, "add", "-A")
	mustGitCmd(t, repoDir, "-c", "user.signingkey="+signingKey, "commit", "-S", "-m", "signed initial commit")

	cfgPath := filepath.Join(base, "config.toml")
	cfgContent := fmt.Sprintf(`
hostname = "services-02"
repo_url = "ssh://git@git.example.lan/homelab/quadlets.git"
ssh_key = %q
ssh_known_hosts = %q
allowed_signers = %q
state_file = %q
repo_dir = %q
`, deployKey, knownHosts, allowedSigners, stateFile, bareDir)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Signed commit with --dry-run prints plan and exits 0 without mutating host.
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"apply",
		"--config", cfgPath,
		"--repo-path", repoDir,
		"--dry-run",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apply --dry-run failed (code=%d)\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	planOut := stdout.String()
	for _, want := range []string{"Host: services-02", "open-webui", "caddy", "Files:", "Units:"} {
		if !strings.Contains(planOut, want) {
			t.Fatalf("expected %q in apply --dry-run stdout, got:\n%s", want, planOut)
		}
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("apply --dry-run must not write state file %q, stat err=%v", stateFile, err)
	}

	// 2. Unsigned commit fails signature verification unless --no-verify is passed.
	writeRepoFiles(t, repoDir, map[string]string{
		"components/caddy/README.txt": "unsigned change\n",
	})
	mustGitCmd(t, repoDir, "add", "-A")
	mustGitCmd(t, repoDir, "commit", "--no-gpg-sign", "-m", "unsigned commit")

	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{
		"apply",
		"--config", cfgPath,
		"--repo-path", repoDir,
		"--dry-run",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected apply --dry-run to reject unsigned commit without --no-verify")
	}

	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{
		"apply",
		"--config", cfgPath,
		"--repo-path", repoDir,
		"--dry-run",
		"--no-verify",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected apply --dry-run --no-verify to pass (code=%d)\nstderr:\n%s", code, stderr.String())
	}

	// 3. --no-verify without --repo-path must be rejected.
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"apply", "--config", cfgPath, "--no-verify"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected --no-verify without --repo-path to be rejected")
	}
}

type stubReconcileEngine struct {
	fn func(ctx context.Context, opts apply.ReconcileOptions) (*apply.Result, error)
}

func (s *stubReconcileEngine) Reconcile(ctx context.Context, opts apply.ReconcileOptions) (*apply.Result, error) {
	return s.fn(ctx, opts)
}

func TestDaemonFailsFastOnBusyMetricsPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ephemeral port: %v", err)
	}
	defer ln.Close()

	base := t.TempDir()
	cfgPath := writeTestConfig(t, base, ln.Addr().String(), "5m")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	code := run(ctx, []string{"daemon", "--config", cfgPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected daemon to fail fast on already-bound metrics port %s", ln.Addr().String())
	}
	if stderr.Len() == 0 {
		t.Fatalf("expected bind error on stderr")
	}
}

func TestDaemonLoopSIGHUPSerializationMetricsAndGracefulShutdown(t *testing.T) {
	metricsAddr := reserveFreeLocalAddr(t)
	base := t.TempDir()
	cfgPath := writeTestConfig(t, base, metricsAddr, "25ms")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	var calls atomic.Int32
	var active atomic.Int32
	var maxConcurrent atomic.Int32
	firstDone := make(chan struct{})
	inFlightStarted := make(chan struct{}, 4)
	releaseInFlight := make(chan struct{})

	eng := &stubReconcileEngine{
		fn: func(_ context.Context, _ apply.ReconcileOptions) (*apply.Result, error) {
			cur := active.Add(1)
			defer active.Add(-1)
			for {
				prev := maxConcurrent.Load()
				if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
					break
				}
			}

			n := calls.Add(1)
			if n == 1 {
				close(firstDone)
			}
			if n == 2 {
				select {
				case inFlightStarted <- struct{}{}:
				default:
				}
				<-releaseInFlight
			}
			return &apply.Result{
				AppliedSHA:           fmt.Sprintf("sha-%d", n),
				ManagedUnitsRootless: 2,
				ManagedUnitsRootful:  1,
				Duration:             10 * time.Millisecond,
			}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	doneCh := make(chan int, 1)
	go func() {
		doneCh <- runDaemonWithFactory(ctx, cfg, &stdout, &stderr, func(*config.HostConfig) reconcileRunner {
			return eng
		})
	}()

	select {
	case <-firstDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for initial daemon reconcile; stderr=%s", stderr.String())
	}

	// Verify /metrics is live and reflects the initial reconcile.
	var bodyStr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + metricsAddr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(b), `sha="sha-1"`) {
				bodyStr = string(b)
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(bodyStr, `quadmatic_last_sync_success 1`) || !strings.Contains(bodyStr, `sha="sha-1"`) {
		t.Fatalf("expected metrics output with sha-1 and success=1, got:\n%s", bodyStr)
	}

	// Wait for 2nd reconcile (from ticker or SIGHUP) to enter in-flight state, send SIGHUP concurrently,
	// then cancel ctx while still in-flight to verify graceful shutdown waits for active reconcile.
	select {
	case <-inFlightStarted:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for second reconcile")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	time.Sleep(40 * time.Millisecond)

	// Cancel context while 2nd reconcile is still blocked; daemon must wait until releaseInFlight!
	cancel()
	select {
	case code := <-doneCh:
		t.Fatalf("daemon exited prematurely (code=%d) before active reconcile completed", code)
	case <-time.After(40 * time.Millisecond):
	}

	close(releaseInFlight)

	select {
	case code := <-doneCh:
		if code != 0 {
			t.Fatalf("daemon exited with non-zero code %d\nstderr:\n%s", code, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for graceful daemon shutdown")
	}

	if gotMax := maxConcurrent.Load(); gotMax != 1 {
		t.Fatalf("max concurrent reconciles = %d, want 1 (reconciles must be serialized)", gotMax)
	}
	if _, err := http.Get("http://" + metricsAddr + "/metrics"); err == nil {
		t.Fatalf("expected metrics HTTP server to be shut down after daemon exit")
	}
}

func TestDaemonMetricsDisabledWhenListenEmpty(t *testing.T) {
	base := t.TempDir()
	cfgPath := writeTestConfig(t, base, "", "1h")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	ran := make(chan struct{})
	eng := &stubReconcileEngine{
		fn: func(_ context.Context, _ apply.ReconcileOptions) (*apply.Result, error) {
			select {
			case <-ran:
			default:
				close(ran)
			}
			return nil, errors.New("simulated sync error")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	doneCh := make(chan int, 1)
	go func() {
		doneCh <- runDaemonWithFactory(ctx, cfg, &stdout, &stderr, func(*config.HostConfig) reconcileRunner {
			return eng
		})
	}()

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for initial reconcile")
	}
	cancel()

	select {
	case code := <-doneCh:
		if code != 0 {
			t.Fatalf("expected clean shutdown code 0 even after reconcile error, got %d; stderr=%s", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for daemon shutdown")
	}
}

func TestCLIHelpAndBadArguments(t *testing.T) {
	cases := []struct {
		args     []string
		wantZero bool
	}{
		{args: []string{"--help"}, wantZero: true},
		{args: []string{"validate", "--help"}, wantZero: true},
		{args: []string{"apply", "--help"}, wantZero: true},
		{args: []string{"daemon", "--help"}, wantZero: true},
		{args: nil, wantZero: false},
		{args: []string{"unknown-cmd"}, wantZero: false},
		{args: []string{"validate"}, wantZero: false}, // missing --repo-path
	}

	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), tc.args, &stdout, &stderr)
		if tc.wantZero && code != 0 {
			t.Errorf("args=%v got code=%d, want 0; stderr=%s", tc.args, code, stderr.String())
		}
		if !tc.wantZero && code == 0 {
			t.Errorf("args=%v got code=0, want non-zero; stdout=%s", tc.args, stdout.String())
		}
	}
}

func writeRepoFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}
}

func writeTestConfig(t *testing.T, base, metricsListen, pollInterval string) string {
	t.Helper()
	for _, name := range []string{"deploy_key", "known_hosts", "allowed-signers"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte("stub\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(base, "config.toml")
	content := fmt.Sprintf(`
hostname = "services-02"
repo_url = "ssh://git@git.example.lan/homelab/quadlets.git"
poll_interval = %q
ssh_key = %q
ssh_known_hosts = %q
allowed_signers = %q
metrics_listen = %q
state_file = %q
repo_dir = %q
`, pollInterval,
		filepath.Join(base, "deploy_key"),
		filepath.Join(base, "known_hosts"),
		filepath.Join(base, "allowed-signers"),
		metricsListen,
		filepath.Join(base, "state.json"),
		filepath.Join(base, "repo.git"),
	)
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func reserveFreeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func generateTestSSHKey(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %q failed: %v\n%s", path, err, string(out))
	}
}

func mustGitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	var full []string
	if dir != "" {
		full = append(full, "-C", dir)
	}
	full = append(full, args...)
	cmd := exec.Command("git", full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", full, err, string(out))
	}
}
