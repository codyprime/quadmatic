package quadlet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"quadmatic/internal/manifest"
)

type recordedCall struct {
	env        []string
	name       string
	args       []string
	stageDir   string
	stageFiles []string
}

type fakeCommandRunner struct {
	calls []recordedCall
	fn    func(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error)
}

func (f *fakeCommandRunner) RunEnv(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
	stageDir := envValue(env, "QUADLET_UNIT_DIRS")
	var staged []string
	if stageDir != "" {
		entries, err := os.ReadDir(stageDir)
		if err == nil {
			for _, e := range entries {
				staged = append(staged, e.Name())
			}
			slices.Sort(staged)
		}
	}
	f.calls = append(f.calls, recordedCall{
		env:        slices.Clone(env),
		name:       name,
		args:       slices.Clone(args),
		stageDir:   stageDir,
		stageFiles: staged,
	})
	if f.fn != nil {
		return f.fn(ctx, env, name, args...)
	}
	return nil, nil, nil
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func envCount(env []string, key string) int {
	prefix := key + "="
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			count++
		}
	}
	return count
}

func sha256HexString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func TestParseDryRunOutputSplitsUnitsAndHashes(t *testing.T) {
	raw := `quadlet-generator[10]: unrelated preamble line
---open-webui-volume.service---
[X-Volume]

[Unit]
RequiresMountsFor=%t/containers

[Service]
ExecStart=/usr/bin/podman volume create --ignore systemd-open-webui
Type=oneshot

---open-webui.service---
[Unit]
Description=Open WebUI
Requires=open-webui-volume.service

[X-Container]
Image=ghcr.io/open-webui/open-webui:main
Secret=webui_secret,type=env,target=WEBUI_SECRET_KEY
Secret=shared_api_key,type=mount,target=/run/secrets/api

[Service]
ExecStart=/usr/bin/podman run --name systemd-%N --secret webui_secret,type=env,target=WEBUI_SECRET_KEY --secret=extra_token ghcr.io/open-webui/open-webui:main
`

	got := ParseDryRunOutput("openwebui", []byte(raw))
	gotAgain := ParseDryRunOutput("openwebui", []byte(raw))

	if len(got) != 2 {
		t.Fatalf("expected 2 units, got %d: %#v", len(got), got)
	}

	volKey := "openwebui/open-webui-volume.service"
	vol, ok := got[volKey]
	if !ok {
		t.Fatalf("missing unit key %q", volKey)
	}
	if vol.Scope != "openwebui" || vol.UnitName != "open-webui-volume.service" {
		t.Fatalf("unexpected metadata for volume unit: %#v", vol)
	}
	if vol.SHA256 == "" || vol.SHA256 != sha256HexString(vol.Content) {
		t.Fatalf("volume SHA256 mismatch: got %q, want %q", vol.SHA256, sha256HexString(vol.Content))
	}
	if len(vol.SecretRefs) != 0 {
		t.Fatalf("expected no secret refs on volume unit, got %v", vol.SecretRefs)
	}
	if !strings.Contains(vol.Content, "[X-Volume]\n\n[Unit]") {
		t.Fatalf("expected interior blank line preserved in volume content, got:\n%s", vol.Content)
	}

	appKey := "openwebui/open-webui.service"
	app, ok := got[appKey]
	if !ok {
		t.Fatalf("missing unit key %q", appKey)
	}
	if app.Scope != "openwebui" || app.UnitName != "open-webui.service" {
		t.Fatalf("unexpected metadata for app unit: %#v", app)
	}
	if app.SHA256 != gotAgain[appKey].SHA256 {
		t.Fatalf("SHA256 not deterministic: %q vs %q", app.SHA256, gotAgain[appKey].SHA256)
	}
	if app.SHA256 != sha256HexString(app.Content) {
		t.Fatalf("app SHA256 mismatch: got %q, want %q", app.SHA256, sha256HexString(app.Content))
	}

	wantSecrets := []string{"extra_token", "shared_api_key", "webui_secret"}
	if !reflect.DeepEqual(app.SecretRefs, wantSecrets) {
		t.Fatalf("SecretRefs = %v, want %v", app.SecretRefs, wantSecrets)
	}

	empty := ParseDryRunOutput("rootful", []byte("no unit delimiters here\n"))
	if len(empty) != 0 {
		t.Fatalf("expected empty map for output without headers, got %#v", empty)
	}
}

func TestValidateHostInvokesGeneratorPerScope(t *testing.T) {
	t.Setenv("QUADLET_UNIT_DIRS", "/should/be/overridden")

	host := &manifest.RenderedHost{
		Hostname: "services-02",
		Components: []manifest.RenderedComponent{
			{
				Name:    "caddy",
				Rootful: true,
				UID:     0,
				Files: []manifest.RenderedFile{
					{
						RelPath:  "caddy.container",
						DestPath: "/etc/containers/systemd/caddy.container",
						Kind:     manifest.FileKindQuadlet,
						Content:  []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
					},
					{
						RelPath:  "Caddyfile",
						DestPath: "/etc/quadmatic/data/caddy/Caddyfile",
						Kind:     manifest.FileKindData,
						Content:  []byte(":80 {\n  respond \"ok\"\n}\n"),
					},
				},
			},
			{
				Name:    "open-webui",
				User:    "openwebui",
				UID:     2001,
				Rootful: false,
				Files: []manifest.RenderedFile{
					{
						RelPath:  "open-webui.container",
						DestPath: "/etc/containers/systemd/users/2001/open-webui.container",
						Kind:     manifest.FileKindQuadlet,
						Content:  []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:main\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
					},
					{
						RelPath:  "open-webui.volume",
						DestPath: "/etc/containers/systemd/users/2001/open-webui.volume",
						Kind:     manifest.FileKindQuadlet,
						Content:  []byte("[Volume]\n"),
					},
				},
			},
		},
	}

	runner := &fakeCommandRunner{
		fn: func(_ context.Context, env []string, _ string, args ...string) ([]byte, []byte, error) {
			stageDir := envValue(env, "QUADLET_UNIT_DIRS")
			if slices.Contains(args, "--user") {
				out := fmt.Sprintf(`---open-webui-volume.service---
[Unit]
SourcePath=%s/open-webui.volume

[Service]
ExecStart=/usr/bin/podman volume create --ignore systemd-open-webui

---open-webui.service---
[Unit]
SourcePath=%s/open-webui.container

[Service]
ExecStart=/usr/bin/podman run --name systemd-%%N ghcr.io/open-webui/open-webui:main
`, stageDir, stageDir)
				return []byte(out), nil, nil
			}
			out := fmt.Sprintf(`---caddy.service---
[Unit]
SourcePath=%s/caddy.container

[Service]
ExecStart=/usr/bin/podman run --name systemd-%%N docker.io/library/caddy:2
`, stageDir)
			return []byte(out), nil, nil
		},
	}

	v := NewValidator("/custom/quadlet", runner)
	units, err := v.ValidateHost(context.Background(), host)
	if err != nil {
		t.Fatalf("ValidateHost returned unexpected error: %v", err)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 generator calls (one per scope), got %d", len(runner.calls))
	}

	// Scopes are processed in deterministic sorted order: "openwebui" then "rootful".
	rootlessCall := runner.calls[0]
	if rootlessCall.name != "/custom/quadlet" {
		t.Fatalf("expected binary /custom/quadlet, got %q", rootlessCall.name)
	}
	if !reflect.DeepEqual(rootlessCall.args, []string{"--dryrun", "--user"}) {
		t.Fatalf("rootless args = %v, want [--dryrun --user]", rootlessCall.args)
	}
	if rootlessCall.stageDir == "" || rootlessCall.stageDir == "/should/be/overridden" {
		t.Fatalf("rootless QUADLET_UNIT_DIRS not overridden: %q", rootlessCall.stageDir)
	}
	if envCount(rootlessCall.env, "QUADLET_UNIT_DIRS") != 1 {
		t.Fatalf("expected exactly one QUADLET_UNIT_DIRS in env, got %d", envCount(rootlessCall.env, "QUADLET_UNIT_DIRS"))
	}
	if !reflect.DeepEqual(rootlessCall.stageFiles, []string{"open-webui.container", "open-webui.volume"}) {
		t.Fatalf("rootless staged files = %v", rootlessCall.stageFiles)
	}
	if _, statErr := os.Stat(rootlessCall.stageDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected rootless temp stage dir %q to be cleaned up, stat err=%v", rootlessCall.stageDir, statErr)
	}

	rootfulCall := runner.calls[1]
	if !reflect.DeepEqual(rootfulCall.args, []string{"--dryrun"}) {
		t.Fatalf("rootful args = %v, want [--dryrun]", rootfulCall.args)
	}
	if !reflect.DeepEqual(rootfulCall.stageFiles, []string{"caddy.container"}) {
		t.Fatalf("rootful staged files = %v (data file must not be staged)", rootfulCall.stageFiles)
	}
	if _, statErr := os.Stat(rootfulCall.stageDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected rootful temp stage dir %q to be cleaned up, stat err=%v", rootfulCall.stageDir, statErr)
	}

	if len(units) != 3 {
		t.Fatalf("expected 3 generated units, got %d: %#v", len(units), units)
	}
	owu, ok := units["openwebui/open-webui.service"]
	if !ok {
		t.Fatalf("missing openwebui/open-webui.service in %#v", units)
	}
	if !reflect.DeepEqual(owu.SecretRefs, []string{"webui_secret"}) {
		t.Fatalf("expected source quadlet secret ref [webui_secret], got %v", owu.SecretRefs)
	}
	if _, ok := units["rootful/caddy.service"]; !ok {
		t.Fatalf("missing rootful/caddy.service in %#v", units)
	}

	// Non-zero generator exit must fail ValidateHost and clean up stage dir.
	failRunner := &fakeCommandRunner{
		fn: func(_ context.Context, _ []string, _ string, _ ...string) ([]byte, []byte, error) {
			return nil, []byte("converting \"bad.container\": no Image or Rootfs key specified"), errors.New("exit status 1")
		},
	}
	vFail := NewValidator("", failRunner)
	_, err = vFail.ValidateHost(context.Background(), host)
	if err == nil {
		t.Fatalf("expected ValidateHost to fail when generator exits non-zero")
	}
	if !strings.Contains(err.Error(), "no Image or Rootfs key specified") {
		t.Fatalf("expected stderr details in error, got: %v", err)
	}
	if len(failRunner.calls) != 1 {
		t.Fatalf("expected 1 call before aborting on error, got %d", len(failRunner.calls))
	}
	if _, statErr := os.Stat(failRunner.calls[0].stageDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected failed stage dir %q to be cleaned up", failRunner.calls[0].stageDir)
	}

	// Empty host (no quadlets) returns empty map without invoking runner.
	noOpRunner := &fakeCommandRunner{}
	emptyUnits, err := NewValidator("", noOpRunner).ValidateHost(context.Background(), &manifest.RenderedHost{Hostname: "empty"})
	if err != nil {
		t.Fatalf("unexpected error on empty host: %v", err)
	}
	if len(emptyUnits) != 0 || len(noOpRunner.calls) != 0 {
		t.Fatalf("expected 0 units and 0 runner calls, got %d units, %d calls", len(emptyUnits), len(noOpRunner.calls))
	}

	// Nil host returns error.
	if _, err := NewValidator("", noOpRunner).ValidateHost(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil RenderedHost")
	}
}

func TestRealQuadletDryRunIntegration(t *testing.T) {
	if _, err := os.Stat(DefaultQuadletBinary); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("%s not installed on host; skipping real quadlet integration test", DefaultQuadletBinary)
		}
		t.Fatalf("stat %s: %v", DefaultQuadletBinary, err)
	}

	v := NewValidator("", nil)
	if v.binaryPath != DefaultQuadletBinary {
		t.Fatalf("default binaryPath = %q, want %q", v.binaryPath, DefaultQuadletBinary)
	}

	validHost := &manifest.RenderedHost{
		Hostname: "services-02",
		Components: []manifest.RenderedComponent{
			{
				Name:    "open-webui",
				User:    "openwebui",
				UID:     2001,
				Rootful: false,
				Files: []manifest.RenderedFile{
					{
						RelPath:  "open-webui.volume",
						DestPath: "/etc/containers/systemd/users/2001/open-webui.volume",
						Kind:     manifest.FileKindQuadlet,
						Content:  []byte("[Volume]\n"),
					},
					{
						RelPath:  "open-webui.container",
						DestPath: "/etc/containers/systemd/users/2001/open-webui.container",
						Kind:     manifest.FileKindQuadlet,
						Content: []byte(`[Unit]
Description=Open WebUI

[Container]
Image=ghcr.io/open-webui/open-webui:main
Volume=open-webui.volume:/app/backend/data
Secret=webui_secret,type=env,target=WEBUI_SECRET_KEY

[Service]
Restart=always
`),
					},
				},
			},
		},
	}

	units1, err := v.ValidateHost(context.Background(), validHost)
	if err != nil {
		t.Fatalf("ValidateHost failed on valid quadlets: %v", err)
	}
	units2, err := v.ValidateHost(context.Background(), validHost)
	if err != nil {
		t.Fatalf("second ValidateHost failed: %v", err)
	}

	for _, unitName := range []string{"open-webui.service", "open-webui-volume.service"} {
		key := filepath.ToSlash(filepath.Join("openwebui", unitName))
		u1, ok := units1[key]
		if !ok {
			t.Fatalf("missing generated unit %q; keys=%v", key, sortedMapKeys(units1))
		}
		if len(u1.SHA256) != 64 {
			t.Fatalf("expected 64-char SHA256 for %q, got %q", key, u1.SHA256)
		}
		u2 := units2[key]
		if u1.SHA256 != u2.SHA256 {
			t.Fatalf("non-deterministic SHA256 across runs for %q: %q vs %q", key, u1.SHA256, u2.SHA256)
		}
	}

	if got := units1["openwebui/open-webui.service"].SecretRefs; !reflect.DeepEqual(got, []string{"webui_secret"}) {
		t.Fatalf("open-webui.service SecretRefs = %v, want [webui_secret]", got)
	}

	invalidHost := &manifest.RenderedHost{
		Hostname: "services-02",
		Components: []manifest.RenderedComponent{
			{
				Name:    "broken",
				User:    "brokenuser",
				UID:     2002,
				Rootful: false,
				Files: []manifest.RenderedFile{
					{
						RelPath:  "broken.container",
						DestPath: "/etc/containers/systemd/users/2002/broken.container",
						Kind:     manifest.FileKindQuadlet,
						Content:  []byte("[Container]\nContainerName=missing-image\n"),
					},
				},
			},
		},
	}

	if _, err := v.ValidateHost(context.Background(), invalidHost); err == nil {
		t.Fatalf("expected real quadlet generator to reject .container missing Image=")
	}
}

func sortedMapKeys(m map[string]GeneratedUnit) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
