package manifest_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quadmatic/internal/manifest"
	"quadmatic/pkg/users"
)

type testRepo struct {
	root string
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	return &testRepo{root: t.TempDir()}
}

func (r *testRepo) writeFile(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func (r *testRepo) parseRegistry(t *testing.T, tomlData string) *users.Registry {
	t.Helper()
	reg, err := users.ParseRegistry([]byte(tomlData))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}
	return reg
}

func findComponent(t *testing.T, comps []manifest.ResolvedComponent, name string) manifest.ResolvedComponent {
	t.Helper()
	for _, c := range comps {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %q not found", name)
	return manifest.ResolvedComponent{}
}

func findRenderedComponent(t *testing.T, comps []manifest.RenderedComponent, name string) manifest.RenderedComponent {
	t.Helper()
	for _, c := range comps {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("rendered component %q not found", name)
	return manifest.RenderedComponent{}
}

func findRenderedFile(t *testing.T, files []manifest.RenderedFile, rel string) manifest.RenderedFile {
	t.Helper()
	for _, f := range files {
		if f.RelPath == rel {
			return f
		}
	}
	t.Fatalf("rendered file %q not found in %+v", rel, files)
	return manifest.RenderedFile{}
}

func TestLoadAndMergeHostComponentOverrides(t *testing.T) {
	r := newTestRepo(t)
	reg := r.parseRegistry(t, `
[users.openwebui]
uid = 2001

[users.caddy]
uid = 2002
`)

	r.writeFile(t, "secrets/open-webui-secret-key.age", "age-ciphertext-placeholder")

	r.writeFile(t, "components/open-webui/component.toml", `
[vars]
image_tag = "main"
welcome_msg = "base"

[ports]
http = { port = 8080, protocol = "tcp" }
metrics = 9090

[network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]
tcp_ports = ["8080:8080"]

[secrets]
webui_secret_key = "secrets/open-webui-secret-key.age"

[files."config.yaml"]
mode = "0600"
`)
	r.writeFile(t, "components/open-webui/open-webui.container.tmpl", "[Container]\nImage=ghcr.io/open-webui/open-webui:{{ .Component.Vars.image_tag }}\n")
	r.writeFile(t, "components/open-webui/open-webui.volume", "[Volume]\n")
	r.writeFile(t, "components/open-webui/files/config.yaml", "msg: default\n")
	r.writeFile(t, "components/open-webui/files/nested/extra.conf.tmpl", "domain={{ .Host.Vars.domain }}\n")

	r.writeFile(t, "components/frigate/component.toml", `
[ports]
web = 5000
`)
	r.writeFile(t, "components/frigate/frigate.container", "[Container]\nImage=ghcr.io/blakeblackshear/frigate:stable\n")
	r.writeFile(t, "components/frigate/files/frigate.yml", "mqtt:\n  enabled: false\n")

	r.writeFile(t, "hosts/services-02.toml", `
hostname = "services-02"

[vars]
listen_addr = "10.0.3.12"
domain = "lan.example.com"

[[component]]
name = "open-webui"
user = "openwebui"

[component.vars]
image_tag = "v0.6.0"
extra = "host-val"

[component.ports]
http = { port = 8081, host_ip = "10.0.3.12" }
admin = 8443

[component.network]
mac = "02:51:4d:00:07:d2"
ipv6 = true
outbound_guard = false

[[component]]
name = "frigate"
rootful = true
reason = "USB Coral passthrough"
`)

	resolved, err := manifest.LoadHost(r.root, "services-02", reg)
	if err != nil {
		t.Fatalf("LoadHost failed: %v", err)
	}
	if err := manifest.Validate(resolved, r.root); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if resolved.Hostname != "services-02" {
		t.Fatalf("expected hostname services-02, got %q", resolved.Hostname)
	}
	if resolved.Vars["domain"] != "lan.example.com" {
		t.Fatalf("expected host var domain, got %#v", resolved.Vars["domain"])
	}

	ow := findComponent(t, resolved.Components, "open-webui")
	if ow.Rootful {
		t.Fatalf("expected open-webui rootless")
	}
	if ow.User != "openwebui" || ow.UID != 2001 {
		t.Fatalf("unexpected open-webui identity: user=%q uid=%d", ow.User, ow.UID)
	}
	if ow.DataDir != "/var/home/openwebui/.config/quadmatic/open-webui" {
		t.Fatalf("unexpected rootless DataDir: %q", ow.DataDir)
	}
	if ow.Vars["image_tag"] != "v0.6.0" || ow.Vars["welcome_msg"] != "base" || ow.Vars["extra"] != "host-val" {
		t.Fatalf("unexpected merged vars: %#v", ow.Vars)
	}
	if got := ow.Ports["http"]; got.Port != 8081 || got.Protocol != "tcp" || got.HostIP != "10.0.3.12" {
		t.Fatalf("unexpected merged http port: %+v", got)
	}
	if got := ow.Ports["metrics"]; got.Port != 9090 || got.Protocol != "tcp" || got.HostIP != "0.0.0.0" {
		t.Fatalf("unexpected preserved metrics port: %+v", got)
	}
	if got := ow.Ports["admin"]; got.Port != 8443 || got.Protocol != "tcp" || got.HostIP != "0.0.0.0" {
		t.Fatalf("unexpected added admin port: %+v", got)
	}
	if ow.Network == nil {
		t.Fatalf("expected merged Network non-nil")
	}
	if ow.Network.VLAN != 30 || ow.Network.MAC != "02:51:4d:00:07:d2" || ow.Network.MacvlanMode != "private" {
		t.Fatalf("unexpected merged network basics: %+v", ow.Network)
	}
	if !ow.Network.IPv6 {
		t.Fatalf("expected overridden ipv6=true")
	}
	if ow.Network.OutboundGuard == nil || *ow.Network.OutboundGuard {
		t.Fatalf("expected overridden outbound_guard=false, got %v", ow.Network.OutboundGuard)
	}

	fr := findComponent(t, resolved.Components, "frigate")
	if !fr.Rootful || fr.UID != 0 || fr.User != "" {
		t.Fatalf("unexpected frigate rootful fields: %+v", fr)
	}
	if fr.DataDir != "/etc/quadmatic/data/frigate" {
		t.Fatalf("unexpected rootful DataDir: %q", fr.DataDir)
	}
	if fr.Network != nil {
		t.Fatalf("expected nil network for frigate, got %+v", fr.Network)
	}

	t.Run("rejects unknown key and mismatched hostname", func(t *testing.T) {
		r2 := newTestRepo(t)
		r2.writeFile(t, "hosts/bad.toml", "hostname = \"other\"\n")
		if _, err := manifest.LoadHost(r2.root, "bad", reg); err == nil {
			t.Fatal("expected error for mismatched hostname")
		}

		r2.writeFile(t, "hosts/unknown.toml", "unknown_field = 1\n")
		if _, err := manifest.LoadHost(r2.root, "unknown", reg); err == nil {
			t.Fatal("expected error for unknown host key")
		}

		r2.writeFile(t, "components/badport/component.toml", "[ports]\nhttp = { port = 8080, bad_field = 1 }\n")
		r2.writeFile(t, "hosts/badport.toml", "[[component]]\nname = \"badport\"\nuser = \"openwebui\"\n")
		if _, err := manifest.LoadHost(r2.root, "badport", reg); err == nil {
			t.Fatal("expected error for unknown field inside port table")
		}

		r2.writeFile(t, "components/badcomp/component.toml", "unknown_comp_key = true\n")
		r2.writeFile(t, "hosts/badcomp.toml", "[[component]]\nname = \"badcomp\"\nuser = \"openwebui\"\n")
		if _, err := manifest.LoadHost(r2.root, "badcomp", reg); err == nil {
			t.Fatal("expected error for unknown top-level key in component.toml")
		}

		r2.writeFile(t, "components/badcompnet/component.toml", "[network]\nvlan = 10\nbogus_net_key = 1\n")
		r2.writeFile(t, "hosts/badcompnet.toml", "[[component]]\nname = \"badcompnet\"\nuser = \"openwebui\"\n")
		if _, err := manifest.LoadHost(r2.root, "badcompnet", reg); err == nil {
			t.Fatal("expected error for unknown key in component.toml [network]")
		}

		r2.writeFile(t, "components/okcomp/component.toml", "")
		r2.writeFile(t, "hosts/badhostnet.toml", "[[component]]\nname = \"okcomp\"\nuser = \"openwebui\"\n[component.network]\nvlan = 10\nbogus_host_net = true\n")
		if _, err := manifest.LoadHost(r2.root, "badhostnet", reg); err == nil {
			t.Fatal("expected error for unknown key in host [component.network]")
		}
	})

	t.Run("nested vars tables and network dns override mode switch", func(t *testing.T) {
		r2 := newTestRepo(t)
		r2.writeFile(t, "components/app/component.toml", `
[network]
vlan = 10
mac = "02:51:4d:00:07:aa"
dns_from_dhcp = true
`)
		r2.writeFile(t, "components/app/app.container.tmpl", "cert={{ .Host.Vars.tls.cert }}\n")
		r2.writeFile(t, "hosts/nested.toml", `
[vars.tls]
cert = "/etc/ssl/cert.pem"

[[component]]
name = "app"
user = "openwebui"
[component.network]
dns = ["10.10.0.1"]
`)
		h, err := manifest.LoadHost(r2.root, "nested", reg)
		if err != nil {
			t.Fatalf("LoadHost nested failed: %v", err)
		}
		if err := manifest.Validate(h, r2.root); err != nil {
			t.Fatalf("Validate nested failed: %v", err)
		}
		app := findComponent(t, h.Components, "app")
		if app.Network.DNSFromDHCP {
			t.Fatalf("expected host explicit dns override to clear inherited dns_from_dhcp")
		}
		rendered, err := manifest.RenderHost(h, manifest.RenderEnv{DryRun: false})
		if err != nil {
			t.Fatalf("RenderHost nested failed: %v", err)
		}
		f := findRenderedFile(t, findRenderedComponent(t, rendered.Components, "app").Files, "app.container")
		if string(f.Content) != "cert=/etc/ssl/cert.pem\n" {
			t.Fatalf("unexpected nested vars render: %q", string(f.Content))
		}
	})
}

func TestValidatePortCollisionsAndNetworkExclusion(t *testing.T) {
	t.Run("wildcard and specific IP collide on same port and proto in default VRF", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, "[users.a]\nuid = 2001\n[users.b]\nuid = 2002\n")
		r.writeFile(t, "components/comp-a/component.toml", "[ports]\nhttp = 8080\n")
		r.writeFile(t, "components/comp-a/a.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "components/comp-b/component.toml", "[ports]\nhttp = { port = 8080, protocol = \"tcp\", host_ip = \"10.0.3.12\" }\n")
		r.writeFile(t, "components/comp-b/b.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "comp-a"
user = "a"

[[component]]
name = "comp-b"
user = "b"
`)
		h, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(h, r.root); err == nil {
			t.Fatal("expected port collision error between 0.0.0.0:8080/tcp and 10.0.3.12:8080/tcp")
		}
	})

	t.Run("distinct specific IPs or protocols do not collide", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, "[users.a]\nuid = 2001\n[users.b]\nuid = 2002\n[users.c]\nuid = 2003\n")
		r.writeFile(t, "components/comp-a/component.toml", "[ports]\nhttp = { port = 8080, host_ip = \"10.0.3.12\" }\n")
		r.writeFile(t, "components/comp-a/a.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "components/comp-b/component.toml", "[ports]\nhttp = { port = 8080, host_ip = \"10.0.3.13\" }\n")
		r.writeFile(t, "components/comp-b/b.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "components/comp-c/component.toml", "[ports]\ndns = { port = 8080, protocol = \"udp\", host_ip = \"10.0.3.12\" }\n")
		r.writeFile(t, "components/comp-c/c.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "comp-a"
user = "a"

[[component]]
name = "comp-b"
user = "b"

[[component]]
name = "comp-c"
user = "c"
`)
		h, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(h, r.root); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("network component ports excluded from default-VRF collision check", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, "[users.a]\nuid = 2001\n[users.b]\nuid = 2002\n")
		r.writeFile(t, "components/comp-a/component.toml", "[ports]\nhttp = 8080\n")
		r.writeFile(t, "components/comp-a/a.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "components/comp-b/component.toml", "[ports]\nhttp = 8080\n")
		r.writeFile(t, "components/comp-b/b.container", "[Container]\nImage=alpine\n")
		r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "comp-a"
user = "a"

[[component]]
name = "comp-b"
user = "b"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]
tcp_ports = ["8080:8080"]
`)
		h, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(h, r.root); err != nil {
			t.Fatalf("expected network component to be excluded from default-VRF port collision, got: %v", err)
		}
	})
}

func TestValidateNetworkConstraints(t *testing.T) {
	baseRegistry := "[users.u1]\nuid = 2001\n[users.u2]\nuid = 2002\n[users.longuid]\nuid = 123456789012\nsubuid_start = 3000000\n"

	cases := []struct {
		name      string
		setupRepo func(t *testing.T, r *testRepo)
		wantErr   string
	}{
		{
			name: "rejects duplicate MACs across components",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "components/c2/c2.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]

[[component]]
name = "c2"
user = "u2"
[component.network]
vlan = 30
mac = "02-51-4D-00-07-D1"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "duplicate MAC",
		},
		{
			name: "rejects multicast MAC",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "01:00:5e:00:00:01"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "multicast",
		},
		{
			name: "rejects invalid MAC",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "not-a-mac"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "MAC",
		},
		{
			name: "rejects more than one network component for same rootless user",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "components/c2/c2.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]

[[component]]
name = "c2"
user = "u1"
[component.network]
vlan = 31
mac = "02:51:4d:00:07:d2"
dns = ["10.0.31.1"]
`)
			},
			wantErr: "at most one",
		},
		{
			name: "rejects rootless network without dns or dns_from_dhcp",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
`)
			},
			wantErr: "dns",
		},
		{
			name: "rejects rootful without reason",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
rootful = true
`)
			},
			wantErr: "reason",
		},
		{
			name: "rejects quadlet filename collision between two components sharing a user",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/shared.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "components/c2/shared.container.tmpl", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"

[[component]]
name = "c2"
user = "u1"
`)
			},
			wantErr: "shared.container",
		},
		{
			name: "rejects out-of-range VLAN",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 4095
mac = "02:51:4d:00:07:d1"
macvlan_mode = "private"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "VLAN",
		},
		{
			name: "rejects invalid macvlan_mode",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
macvlan_mode = "vepa"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "macvlan_mode",
		},
		{
			name: "rejects qmv-<uid> exceeding 15 characters",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "longuid"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]
`)
			},
			wantErr: "15 characters",
		},
		{
			name: "rejects invalid tcp_ports",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]
tcp_ports = ["8080,9090"]
`)
			},
			wantErr: "tcp_ports",
		},
		{
			name: "rejects invalid udp_ports",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.0.30.1"]
udp_ports = ["9000-8000"]
`)
			},
			wantErr: "udp_ports",
		},
		{
			name: "rejects conflicting file overrides for foo.conf and foo.conf.tmpl",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", `
[files."foo.conf"]
mode = "0600"

[files."foo.conf.tmpl"]
mode = "0640"
`)
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "components/c1/files/foo.conf.tmpl", "hello={{ .Host.Hostname }}\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "u1"
`)
			},
			wantErr: "conflicting file overrides",
		},
		{
			name: "rejects rootless component without user or missing user in registry",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "c1"
user = "nobody_in_reg"
`)
			},
			wantErr: "registry",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRepo(t)
			reg := r.parseRegistry(t, baseRegistry)
			tc.setupRepo(t, r)
			h, err := manifest.LoadHost(r.root, "node", reg)
			if err != nil {
				t.Fatalf("LoadHost failed unexpectedly: %v", err)
			}
			err = manifest.Validate(h, r.root)
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	t.Run("allows rootful network component without dns", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, baseRegistry)
		r.writeFile(t, "components/frigate/frigate.network", "[Network]\nDriver=macvlan\n")
		r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "frigate"
rootful = true
reason = "L2 mDNS"
[component.network]
vlan = 40
mac = "02:51:4d:00:07:e1"
`)
		h, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(h, r.root); err != nil {
			t.Fatalf("expected rootful network component without dns to pass validation, got: %v", err)
		}
	})
}

func TestValidateRejectsPathTraversal(t *testing.T) {
	regData := "[users.u1]\nuid = 2001\n"

	cases := []struct {
		name      string
		wantErr   string
		setupRepo func(t *testing.T, r *testRepo)
	}{
		{
			name:    "secret path escaping repo with dot-dot",
			wantErr: "rejected",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", "[secrets]\nkey = \"../outside.age\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "secret path using absolute path",
			wantErr: "must be relative",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", "[secrets]\nkey = \"/etc/shadow\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "file override escaping with ../../etc/passwd",
			wantErr: "rejected",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", "[files.\"../../etc/passwd\"]\nmode = \"0600\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "file override with absolute path",
			wantErr: "must be relative",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", "[files.\"/etc/passwd\"]\nmode = \"0600\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink secret pointing outside repo",
			wantErr: "escapes repo",
			setupRepo: func(t *testing.T, r *testRepo) {
				outside := filepath.Join(t.TempDir(), "outside.age")
				if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(r.root, "secrets"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(r.root, "secrets/escape.age")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "components/c1/component.toml", "[secrets]\nkey = \"secrets/escape.age\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink data file pointing outside files dir",
			wantErr: "escapes",
			setupRepo: func(t *testing.T, r *testRepo) {
				outside := filepath.Join(t.TempDir(), "passwd")
				if err := os.WriteFile(outside, []byte("root:x:0:0"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(r.root, "components/c1/files"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(r.root, "components/c1/files/leak")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink quadlet file pointing outside component dir",
			wantErr: "escapes",
			setupRepo: func(t *testing.T, r *testRepo) {
				outside := filepath.Join(t.TempDir(), "evil.container")
				if err := os.WriteFile(outside, []byte("[Container]\nImage=alpine\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(r.root, "components/c1"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(r.root, "components/c1/c1.container")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "missing secret file fails validation",
			wantErr: "missing.age",
			setupRepo: func(t *testing.T, r *testRepo) {
				r.writeFile(t, "components/c1/component.toml", "[secrets]\nkey = \"secrets/missing.age\"\n")
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink hosts directory escaping repo fails",
			wantErr: "escapes repo root",
			setupRepo: func(t *testing.T, r *testRepo) {
				outsideHosts := t.TempDir()
				if err := os.WriteFile(filepath.Join(outsideHosts, "node.toml"), []byte("[[component]]\nname = \"c1\"\nuser = \"u1\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideHosts, filepath.Join(r.root, "hosts")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
			},
		},
		{
			name:    "symlink host manifest file escaping repo fails",
			wantErr: "escapes repo root",
			setupRepo: func(t *testing.T, r *testRepo) {
				outsideHost := filepath.Join(t.TempDir(), "node.toml")
				if err := os.WriteFile(outsideHost, []byte("[[component]]\nname = \"c1\"\nuser = \"u1\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(r.root, "hosts"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideHost, filepath.Join(r.root, "hosts/node.toml")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
			},
		},
		{
			name:    "symlink components directory escaping repo fails",
			wantErr: "escapes repo root",
			setupRepo: func(t *testing.T, r *testRepo) {
				outsideComps := t.TempDir()
				if err := os.MkdirAll(filepath.Join(outsideComps, "c1"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(outsideComps, "c1/c1.container"), []byte("[Container]\nImage=alpine\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideComps, filepath.Join(r.root, "components")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink component directory escaping repo fails",
			wantErr: "escapes repo root",
			setupRepo: func(t *testing.T, r *testRepo) {
				outsideComp := t.TempDir()
				if err := os.MkdirAll(filepath.Join(r.root, "components"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideComp, filepath.Join(r.root, "components/c1")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
		{
			name:    "symlink component.toml escaping repo fails",
			wantErr: "escapes repo root",
			setupRepo: func(t *testing.T, r *testRepo) {
				outsideTOML := filepath.Join(t.TempDir(), "component.toml")
				if err := os.WriteFile(outsideTOML, []byte("[ports]\nhttp = 8080\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "components/c1/c1.container", "[Container]\nImage=alpine\n")
				if err := os.Symlink(outsideTOML, filepath.Join(r.root, "components/c1/component.toml")); err != nil {
					t.Fatal(err)
				}
				r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"c1\"\nuser = \"u1\"\n")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRepo(t)
			reg := r.parseRegistry(t, regData)
			tc.setupRepo(t, r)
			h, err := manifest.LoadHost(r.root, "node", reg)
			if err == nil {
				err = manifest.Validate(h, r.root)
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	t.Run("Validate directly rejects escaping components symlink even without LoadHost", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, regData)
		outsideComps := t.TempDir()
		if err := os.MkdirAll(filepath.Join(outsideComps, "c1"), 0o755); err != nil {
			t.Fatal(err)
		}
		outsideQuadlet := filepath.Join(outsideComps, "c1/c1.container")
		if err := os.WriteFile(outsideQuadlet, []byte("[Container]\nImage=alpine\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideComps, filepath.Join(r.root, "components")); err != nil {
			t.Fatal(err)
		}
		synthetic := &manifest.ResolvedHost{
			Hostname: "node",
			Registry: reg,
			Components: []manifest.ResolvedComponent{
				{
					Name: "c1",
					User: "u1",
					UID:  2001,
					QuadletFiles: []manifest.SourceFile{
						{
							RelPath:       "c1.container",
							SourceRelPath: "c1.container",
							SourceAbsPath: filepath.Join(r.root, "components/c1/c1.container"),
						},
					},
				},
			},
		}
		err := manifest.Validate(synthetic, r.root)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "escapes repo root") {
			t.Fatalf("expected Validate to reject escaping components symlink, got: %v", err)
		}
	})
}

func TestRenderTemplatesAndPastaArgs(t *testing.T) {
	t.Run("BuildPastaArgs ipv4-only and ipv6", func(t *testing.T) {
		netV4 := &manifest.NetworkSpec{
			TCPPorts: []string{"8080:8080"},
		}
		gotV4 := manifest.BuildPastaArgs("qm-2001", netV4)
		wantV4 := "pasta:--no-map-gw,--map-host-loopback,none,--ipv4-only,-i,qm-2001,--outbound-if4,qm-2001,-t,%qm-2001/8080:8080"
		if gotV4 != wantV4 {
			t.Fatalf("BuildPastaArgs v4 mismatch:\n got: %s\nwant: %s", gotV4, wantV4)
		}

		netV6 := &manifest.NetworkSpec{
			IPv6:     true,
			TCPPorts: []string{"8080:8080"},
			UDPPorts: []string{"5353:5353"},
		}
		gotV6 := manifest.BuildPastaArgs("qm-2001", netV6)
		wantV6 := "pasta:--no-map-gw,--map-host-loopback,none,-i,qm-2001,--outbound-if4,qm-2001,--outbound-if6,qm-2001,-t,%qm-2001/8080:8080,-u,%qm-2001/5353:5353"
		if gotV6 != wantV6 {
			t.Fatalf("BuildPastaArgs v6 mismatch:\n got: %s\nwant: %s", gotV6, wantV6)
		}
	})

	t.Run("renders rootless, rootful, Caddy .Host.Components, and placeholder DNS", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, `
[users.openwebui]
uid = 2001

[users.caddy]
uid = 2002
`)
		r.writeFile(t, "components/open-webui/component.toml", `
[ports]
http = 8080

[files."config.yaml"]
mode = "0600"
`)
		r.writeFile(t, "components/open-webui/open-webui.container.tmpl", `[Container]
Image=ghcr.io/open-webui/open-webui:main
Network={{ .Net.PastaArgs }}
{{- range .Net.DNS }}
DNS={{ . }}
{{- end }}
# parent={{ .Net.ParentInterface }} vrf={{ .Net.VRF }} mac={{ .Net.MAC }}
`)
		r.writeFile(t, "components/open-webui/open-webui.volume", "[Volume]\n")
		r.writeFile(t, "components/open-webui/files/config.yaml", "host: {{ not-rendered }}\n")

		r.writeFile(t, "components/caddy/component.toml", `
[ports]
https = 443
`)
		r.writeFile(t, "components/caddy/caddy.container.tmpl", `[Container]
Image=docker.io/library/caddy:2
Volume={{ .Component.DataDir }}/Caddyfile:/etc/caddy/Caddyfile:ro,Z
`)
		r.writeFile(t, "components/caddy/files/Caddyfile.tmpl", `{{ (index .Host.Components "open-webui").Name }}.{{ .Host.Vars.domain }} {
	reverse_proxy {{ .Host.Vars.listen_addr }}:{{ (index .Host.Components "open-webui").Ports.http.Port }}
}
`)

		r.writeFile(t, "components/frigate/component.toml", "")
		r.writeFile(t, "components/frigate/frigate.network.tmpl", `[Network]
Driver=macvlan
InterfaceName={{ .Net.ParentInterface }}
# vlan={{ .Net.VLAN }} mac={{ .Net.MAC }}
`)
		r.writeFile(t, "components/frigate/files/frigate.yml", "cameras: {}\n")

		r.writeFile(t, "hosts/services-02.toml", `
hostname = "services-02"

[vars]
domain = "lan.example.com"
listen_addr = "10.0.3.12"

[[component]]
name = "open-webui"
user = "openwebui"
[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns_from_dhcp = true
tcp_ports = ["8080:8080"]

[[component]]
name = "caddy"
user = "caddy"

[[component]]
name = "frigate"
rootful = true
reason = "USB Coral passthrough"
[component.network]
vlan = 40
mac = "02:51:4d:00:07:e1"
`)

		resolved, err := manifest.LoadHost(r.root, "services-02", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(resolved, r.root); err != nil {
			t.Fatalf("Validate failed: %v", err)
		}

		// Dry-run render without live DNS should use placeholder 192.0.2.53.
		renderedDry, err := manifest.RenderHost(resolved, manifest.RenderEnv{
			ParentIfaces: map[int]string{30: "enp3s0.30"},
			DryRun:       true,
		})
		if err != nil {
			t.Fatalf("RenderHost dry-run failed: %v", err)
		}
		if !renderedDry.UsedPlaceholderDNS {
			t.Fatalf("expected UsedPlaceholderDNS=true in dry-run without live DNS")
		}

		owDry := findRenderedComponent(t, renderedDry.Components, "open-webui")
		owUnit := findRenderedFile(t, owDry.Files, "open-webui.container")
		if owUnit.Kind != "quadlet" {
			t.Fatalf("expected quadlet Kind, got %q", owUnit.Kind)
		}
		if owUnit.DestPath != "/etc/containers/systemd/users/2001/open-webui.container" {
			t.Fatalf("unexpected rootless quadlet DestPath: %q", owUnit.DestPath)
		}
		if owUnit.Mode != 0o644 || owUnit.OwnerUID != 0 || owUnit.OwnerGID != 0 {
			t.Fatalf("unexpected quadlet metadata: mode=%o uid=%d gid=%d", owUnit.Mode, owUnit.OwnerUID, owUnit.OwnerGID)
		}
		wantSum := fmt.Sprintf("%x", sha256.Sum256(owUnit.Content))
		if owUnit.SHA256 != wantSum {
			t.Fatalf("SHA256 mismatch: got %q, want %q", owUnit.SHA256, wantSum)
		}
		owText := string(owUnit.Content)
		if !strings.Contains(owText, "Network=pasta:--no-map-gw,--map-host-loopback,none,--ipv4-only,-i,qm-2001,--outbound-if4,qm-2001,-t,%qm-2001/8080:8080") {
			t.Fatalf("missing expected pasta args in:\n%s", owText)
		}
		if !strings.Contains(owText, "DNS=192.0.2.53") {
			t.Fatalf("missing placeholder DNS in:\n%s", owText)
		}
		if !strings.Contains(owText, "parent=enp3s0.30 vrf=qmv-2001 mac=02:51:4d:00:07:d1") {
			t.Fatalf("missing parent/vrf/mac in:\n%s", owText)
		}

		owVol := findRenderedFile(t, owDry.Files, "open-webui.volume")
		if owVol.Kind != "quadlet" || owVol.DestPath != "/etc/containers/systemd/users/2001/open-webui.volume" {
			t.Fatalf("unexpected static volume metadata: %+v", owVol)
		}

		owCfg := findRenderedFile(t, owDry.Files, "config.yaml")
		if owCfg.Kind != "data" {
			t.Fatalf("expected data Kind, got %q", owCfg.Kind)
		}
		if owCfg.DestPath != "/var/home/openwebui/.config/quadmatic/open-webui/config.yaml" {
			t.Fatalf("unexpected data DestPath: %q", owCfg.DestPath)
		}
		if owCfg.Mode != 0o600 || owCfg.OwnerUID != 2001 || owCfg.OwnerGID != 2001 {
			t.Fatalf("unexpected data file metadata: mode=%o uid=%d gid=%d", owCfg.Mode, owCfg.OwnerUID, owCfg.OwnerGID)
		}
		if string(owCfg.Content) != "host: {{ not-rendered }}\n" {
			t.Fatalf("non-.tmpl file should not be template-evaluated, got %q", string(owCfg.Content))
		}

		caddyComp := findRenderedComponent(t, renderedDry.Components, "caddy")
		caddyFile := findRenderedFile(t, caddyComp.Files, "Caddyfile")
		if caddyFile.Mode != 0o640 || caddyFile.OwnerUID != 2002 || caddyFile.OwnerGID != 2002 {
			t.Fatalf("unexpected default data file metadata: mode=%o uid=%d gid=%d", caddyFile.Mode, caddyFile.OwnerUID, caddyFile.OwnerGID)
		}
		if !strings.Contains(string(caddyFile.Content), "open-webui.lan.example.com") || !strings.Contains(string(caddyFile.Content), "reverse_proxy 10.0.3.12:8080") {
			t.Fatalf("unexpected rendered Caddyfile:\n%s", string(caddyFile.Content))
		}

		frComp := findRenderedComponent(t, renderedDry.Components, "frigate")
		frNet := findRenderedFile(t, frComp.Files, "frigate.network")
		if frNet.DestPath != "/etc/containers/systemd/frigate.network" || frNet.Kind != "quadlet" || frNet.OwnerUID != 0 {
			t.Fatalf("unexpected rootful quadlet metadata: %+v", frNet)
		}
		if !strings.Contains(string(frNet.Content), "InterfaceName=qm-vlan40") || !strings.Contains(string(frNet.Content), "vlan=40 mac=02:51:4d:00:07:e1") {
			t.Fatalf("unexpected rootful frigate.network:\n%s", string(frNet.Content))
		}
		frCfg := findRenderedFile(t, frComp.Files, "frigate.yml")
		if frCfg.DestPath != "/etc/quadmatic/data/frigate/frigate.yml" || frCfg.Mode != 0o640 || frCfg.OwnerUID != 0 || frCfg.OwnerGID != 0 {
			t.Fatalf("unexpected rootful data metadata: %+v", frCfg)
		}

		// Non-dry-run with live DNS clears UsedPlaceholderDNS and renders real DNS.
		renderedLive, err := manifest.RenderHost(resolved, manifest.RenderEnv{
			LiveDNS: map[string][]string{"open-webui": {"10.0.30.5"}},
			DryRun:  false,
		})
		if err != nil {
			t.Fatalf("RenderHost live failed: %v", err)
		}
		if renderedLive.UsedPlaceholderDNS {
			t.Fatalf("expected UsedPlaceholderDNS=false when live DNS provided")
		}
		owLive := findRenderedFile(t, findRenderedComponent(t, renderedLive.Components, "open-webui").Files, "open-webui.container")
		if !strings.Contains(string(owLive.Content), "DNS=10.0.30.5") || strings.Contains(string(owLive.Content), "192.0.2.53") {
			t.Fatalf("unexpected live DNS render:\n%s", string(owLive.Content))
		}

		// Non-dry-run without live DNS must fail rather than writing placeholder DNS.
		if _, err := manifest.RenderHost(resolved, manifest.RenderEnv{DryRun: false}); err == nil {
			t.Fatal("expected error when dns_from_dhcp=true in non-dry-run without live DNS")
		}
	})

	t.Run("missingkey=error fails on undefined variable", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, "[users.u1]\nuid = 2001\n")
		r.writeFile(t, "components/app/app.container.tmpl", "[Container]\nImage={{ .Host.Vars.undefined_var }}\n")
		r.writeFile(t, "hosts/node.toml", "[[component]]\nname = \"app\"\nuser = \"u1\"\n")
		resolved, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(resolved, r.root); err != nil {
			t.Fatalf("Validate failed: %v", err)
		}
		if _, err := manifest.RenderHost(resolved, manifest.RenderEnv{DryRun: true}); err == nil {
			t.Fatal("expected missingkey=error failure for undefined template key")
		}
	})

	t.Run("vlan 0 uses trunk_interface placeholder unless ParentIfaces[0] set", func(t *testing.T) {
		r := newTestRepo(t)
		reg := r.parseRegistry(t, "[users.u1]\nuid = 2001\n")
		r.writeFile(t, "components/app/app.container.tmpl", "parent={{ .Net.ParentInterface }}\n")
		r.writeFile(t, "hosts/node.toml", `
[[component]]
name = "app"
user = "u1"
[component.network]
mac = "02:51:4d:00:07:d1"
dns = ["10.0.0.1"]
`)
		resolved, err := manifest.LoadHost(r.root, "node", reg)
		if err != nil {
			t.Fatalf("LoadHost failed: %v", err)
		}
		if err := manifest.Validate(resolved, r.root); err != nil {
			t.Fatalf("Validate failed: %v", err)
		}
		renderedDefault, err := manifest.RenderHost(resolved, manifest.RenderEnv{DryRun: true})
		if err != nil {
			t.Fatalf("RenderHost default failed: %v", err)
		}
		gotDefault := string(findRenderedFile(t, renderedDefault.Components[0].Files, "app.container").Content)
		if gotDefault != "parent=trunk_interface\n" {
			t.Fatalf("expected trunk_interface placeholder, got %q", gotDefault)
		}

		renderedExplicit, err := manifest.RenderHost(resolved, manifest.RenderEnv{
			ParentIfaces: map[int]string{0: "enp3s0"},
			DryRun:       true,
		})
		if err != nil {
			t.Fatalf("RenderHost explicit failed: %v", err)
		}
		gotExplicit := string(findRenderedFile(t, renderedExplicit.Components[0].Files, "app.container").Content)
		if gotExplicit != "parent=enp3s0\n" {
			t.Fatalf("expected enp3s0 parent, got %q", gotExplicit)
		}
	})
}
