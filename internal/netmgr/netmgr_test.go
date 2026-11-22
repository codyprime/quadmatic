package netmgr_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"quadmatic/internal/manifest"
	"quadmatic/internal/netmgr"
	"quadmatic/internal/state"
)

type recordedCmd struct {
	stdin string
	name  string
	args  []string
}

type fakeNMConn struct {
	name  string
	props map[string]string
}

type fakeDevice struct {
	device string
	typ    string
	conn   string
	parent string
	vlanID int
}

type fakeSysctl struct {
	values map[string]string
	errs   map[string]error
}

func (s *fakeSysctl) ReadSysctl(path string) (string, error) {
	if s.errs != nil {
		if err, ok := s.errs[path]; ok {
			return "", err
		}
	}
	if s.values != nil {
		if v, ok := s.values[path]; ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("sysctl %q not found", path)
}

func newZeroL3mdevSysctl() *fakeSysctl {
	return &fakeSysctl{
		values: map[string]string{
			"/proc/sys/net/ipv4/tcp_l3mdev_accept": "0\n",
			"/proc/sys/net/ipv4/udp_l3mdev_accept": "0\n",
		},
	}
}

type fakeRunner struct {
	calls        []recordedCmd
	conns        map[string]*fakeNMConn
	active       map[string]bool
	unmanagedDev []fakeDevice
	dnsByIface   map[string]string
	dnsPolls     map[string]int
	dnsReadyAt   map[string]int
	routes       map[int][]string
	nftTable     string
	nftCounters  bool
	failHook     func(stdin []byte, name string, args []string) ([]byte, error)
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		conns:      make(map[string]*fakeNMConn),
		active:     make(map[string]bool),
		dnsByIface: make(map[string]string),
		dnsPolls:   make(map[string]int),
		dnsReadyAt: make(map[string]int),
		routes:     make(map[int][]string),
	}
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCmd{
		stdin: string(stdin),
		name:  name,
		args:  slices.Clone(args),
	})
	if f.failHook != nil {
		if out, err := f.failHook(stdin, name, args); err != nil {
			return out, err
		}
	}

	switch name {
	case "nmcli":
		return f.handleNMCLI(args)
	case "ip":
		return f.handleIP(args)
	case "nft":
		return f.handleNFT(string(stdin), args)
	default:
		return nil, fmt.Errorf("unexpected binary %q", name)
	}
}

func (f *fakeRunner) handleNMCLI(args []string) ([]byte, error) {
	// Parse optional leading flags: -t, -f <fields>, -g <fields>
	var terse bool
	var fields string
	var getValues string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-t":
			terse = true
			i++
		case "-f":
			if i+1 < len(args) {
				fields = args[i+1]
				i += 2
			} else {
				i++
			}
		case "-g":
			if i+1 < len(args) {
				getValues = args[i+1]
				i += 2
			} else {
				i++
			}
		default:
			goto doneFlags
		}
	}
doneFlags:
	rest := args[i:]
	if len(rest) == 0 {
		return nil, errors.New("empty nmcli args")
	}

	switch rest[0] {
	case "device":
		if len(rest) == 1 && terse && fields == "DEVICE,TYPE,CONNECTION" {
			var lines []string
			for _, d := range f.unmanagedDev {
				lines = append(lines, fmt.Sprintf("%s:%s:%s", d.device, d.typ, d.conn))
			}
			for name, c := range f.conns {
				if f.active[name] {
					lines = append(lines, fmt.Sprintf("%s:%s:%s", c.props["connection.interface-name"], c.props["connection.type"], name))
				}
			}
			return []byte(strings.Join(lines, "\n")), nil
		}
		if len(rest) >= 3 && rest[1] == "show" && getValues == "IP4.DNS" {
			ifname := rest[2]
			f.dnsPolls[ifname]++
			if readyAt := f.dnsReadyAt[ifname]; readyAt > 0 && f.dnsPolls[ifname] < readyAt {
				return []byte(""), nil
			}
			return []byte(f.dnsByIface[ifname]), nil
		}
		return nil, fmt.Errorf("unsupported nmcli device args: %v", args)

	case "connection":
		if len(rest) < 2 {
			return nil, fmt.Errorf("unsupported nmcli connection args: %v", args)
		}
		sub := rest[1]
		switch sub {
		case "show":
			// nmcli -t -f NAME connection show
			if len(rest) == 2 && terse && fields == "NAME" {
				var names []string
				for _, d := range f.unmanagedDev {
					if d.conn != "" && d.conn != "--" {
						names = append(names, d.conn)
					}
				}
				for name := range f.conns {
					names = append(names, name)
				}
				return []byte(strings.Join(names, "\n")), nil
			}
			// nmcli -t -f NAME connection show --active
			if len(rest) == 3 && rest[2] == "--active" && terse && fields == "NAME" {
				var names []string
				for _, d := range f.unmanagedDev {
					if d.conn != "" && d.conn != "--" {
						names = append(names, d.conn)
					}
				}
				for name, up := range f.active {
					if up {
						names = append(names, name)
					}
				}
				return []byte(strings.Join(names, "\n")), nil
			}
			if len(rest) >= 3 {
				id := rest[len(rest)-1]
				if getValues == "vlan.parent,vlan.id" {
					for _, d := range f.unmanagedDev {
						if d.conn == id {
							return []byte(fmt.Sprintf("%s\n%d\n", d.parent, d.vlanID)), nil
						}
					}
					if c, ok := f.conns[id]; ok && c.props["connection.type"] == "vlan" {
						return []byte(fmt.Sprintf("%s\n%s\n", c.props["vlan.parent"], c.props["vlan.id"])), nil
					}
					return []byte("Error: no such connection profile"), fmt.Errorf("exit status 10")
				}
				c, ok := f.conns[id]
				if !ok {
					return []byte(fmt.Sprintf("Error: %s - no such connection profile.", id)), fmt.Errorf("exit status 10")
				}
				var lines []string
				for k, v := range c.props {
					lines = append(lines, fmt.Sprintf("%s:%s", k, strings.ReplaceAll(v, ":", `\:`)))
				}
				slices.Sort(lines)
				return []byte(strings.Join(lines, "\n")), nil
			}

		case "add":
			props := parseNMCLIAddProps(rest[2:])
			conName := props["connection.id"]
			if conName == "" {
				return nil, errors.New("nmcli connection add missing con-name")
			}
			f.conns[conName] = &fakeNMConn{name: conName, props: props}
			return []byte(fmt.Sprintf("Connection '%s' successfully added.", conName)), nil

		case "modify":
			if len(rest) < 3 {
				return nil, errors.New("nmcli connection modify missing id")
			}
			conName := rest[2]
			c, ok := f.conns[conName]
			if !ok {
				return []byte(fmt.Sprintf("Error: %s - no such connection profile.", conName)), fmt.Errorf("exit status 10")
			}
			applyNMCLIModifyProps(c.props, rest[3:])
			return nil, nil

		case "up":
			if len(rest) < 3 {
				return nil, errors.New("nmcli connection up missing id")
			}
			conName := rest[2]
			if _, ok := f.conns[conName]; !ok {
				return []byte(fmt.Sprintf("Error: %s - no such connection profile.", conName)), fmt.Errorf("exit status 10")
			}
			f.active[conName] = true
			return nil, nil

		case "delete":
			if len(rest) < 3 {
				return nil, errors.New("nmcli connection delete missing id")
			}
			conName := rest[2]
			if _, ok := f.conns[conName]; !ok {
				return []byte(fmt.Sprintf("Error: %s - no such connection profile.", conName)), fmt.Errorf("exit status 10")
			}
			delete(f.conns, conName)
			delete(f.active, conName)
			return nil, nil
		}
	}

	return nil, fmt.Errorf("unsupported nmcli command: %v", args)
}

func parseNMCLIAddProps(args []string) map[string]string {
	props := make(map[string]string)
	for i := 0; i+1 < len(args); i += 2 {
		k, v := args[i], args[i+1]
		switch k {
		case "type":
			props["connection.type"] = v
		case "con-name":
			props["connection.id"] = v
		case "ifname":
			props["connection.interface-name"] = v
		case "autoconnect":
			props["connection.autoconnect"] = v
		case "dev":
			switch props["connection.type"] {
			case "vlan":
				props["vlan.parent"] = v
			case "macvlan":
				props["macvlan.parent"] = v
			}
		case "id":
			props["vlan.id"] = v
		case "table":
			props["vrf.table"] = v
		case "mode":
			props["macvlan.mode"] = v
		case "controller", "master":
			props["connection.controller"] = v
		case "ethernet.cloned-mac-address", "802-3-ethernet.cloned-mac-address":
			props["802-3-ethernet.cloned-mac-address"] = v
		default:
			props[k] = v
		}
	}
	return props
}

func applyNMCLIModifyProps(props map[string]string, args []string) {
	for i := 0; i+1 < len(args); i += 2 {
		k, v := args[i], args[i+1]
		switch k {
		case "ethernet.cloned-mac-address":
			props["802-3-ethernet.cloned-mac-address"] = v
		case "connection.master":
			props["connection.controller"] = v
		default:
			props[k] = v
		}
	}
}

func (f *fakeRunner) handleIP(args []string) ([]byte, error) {
	if len(args) >= 2 && args[0] == "route" {
		switch args[1] {
		case "replace":
			tableID, route := extractIPRouteAndTable(args[2:])
			f.routes[tableID] = []string{route}
			return nil, nil
		case "del":
			tableID, _ := extractIPRouteAndTable(args[2:])
			delete(f.routes, tableID)
			return nil, nil
		case "show":
			tableID := 0
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "table" {
					tableID, _ = strconv.Atoi(args[i+1])
				}
			}
			return []byte(strings.Join(f.routes[tableID], "\n")), nil
		}
	}
	if len(args) >= 5 && args[0] == "-d" && args[1] == "-o" && args[2] == "link" && args[3] == "show" {
		devName := args[len(args)-1]
		for _, d := range f.unmanagedDev {
			if d.device == devName {
				return []byte(fmt.Sprintf("5: %s@%s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 vlan protocol 802.1Q id %d", d.device, d.parent, d.vlanID)), nil
			}
		}
		return []byte("Device does not exist."), errors.New("exit status 1")
	}
	return nil, fmt.Errorf("unsupported ip command: %v", args)
}

func extractIPRouteAndTable(args []string) (int, string) {
	var parts []string
	tableID := 0
	for i := 0; i < len(args); i++ {
		if args[i] == "table" && i+1 < len(args) {
			tableID, _ = strconv.Atoi(args[i+1])
			i++
			continue
		}
		parts = append(parts, args[i])
	}
	return tableID, strings.Join(parts, " ")
}

func (f *fakeRunner) handleNFT(stdin string, args []string) ([]byte, error) {
	if len(args) >= 4 && args[0] == "list" && args[1] == "table" && args[2] == "inet" && args[3] == "quadmatic" {
		if f.nftTable == "" {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		out := f.nftTable
		if f.nftCounters {
			out = strings.ReplaceAll(out, "counter drop", "counter packets 42 bytes 3528 drop")
		}
		return []byte(out), nil
	}
	if len(args) >= 4 && args[0] == "delete" && args[1] == "table" && args[2] == "inet" && args[3] == "quadmatic" {
		if f.nftTable == "" {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		f.nftTable = ""
		return nil, nil
	}
	if len(args) >= 2 && args[0] == "-f" && args[1] == "-" {
		idx := strings.Index(stdin, "table inet quadmatic {")
		if idx >= 0 {
			f.nftTable = strings.TrimSpace(stdin[idx:]) + "\n"
			return nil, nil
		}
		if strings.Contains(stdin, "delete table inet quadmatic") {
			f.nftTable = ""
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected nft script:\n%s", stdin)
	}
	return nil, fmt.Errorf("unsupported nft command: %v", args)
}

func boolPtr(b bool) *bool { return &b }

func TestCheckKernelInvariantsRejectsNonZeroL3mdevAccept(t *testing.T) {
	runner := newFakeRunner()

	t.Run("both zero passes", func(t *testing.T) {
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		if err := r.CheckKernelInvariants(); err != nil {
			t.Fatalf("CheckKernelInvariants unexpected error: %v", err)
		}
	})

	t.Run("tcp_l3mdev_accept=1 fails", func(t *testing.T) {
		sc := newZeroL3mdevSysctl()
		sc.values["/proc/sys/net/ipv4/tcp_l3mdev_accept"] = "1\n"
		r := netmgr.NewReconciler("enp3s0", runner, sc)
		if err := r.CheckKernelInvariants(); err == nil {
			t.Fatal("expected error when tcp_l3mdev_accept is 1")
		}
	})

	t.Run("udp_l3mdev_accept=1 fails", func(t *testing.T) {
		sc := newZeroL3mdevSysctl()
		sc.values["/proc/sys/net/ipv4/udp_l3mdev_accept"] = "1\n"
		r := netmgr.NewReconciler("enp3s0", runner, sc)
		if err := r.CheckKernelInvariants(); err == nil {
			t.Fatal("expected error when udp_l3mdev_accept is 1")
		}
	})

	t.Run("read failure fails", func(t *testing.T) {
		sc := newZeroL3mdevSysctl()
		sc.errs = map[string]error{"/proc/sys/net/ipv4/tcp_l3mdev_accept": errors.New("permission denied")}
		r := netmgr.NewReconciler("enp3s0", runner, sc)
		if err := r.CheckKernelInvariants(); err == nil {
			t.Fatal("expected error when sysctl read fails")
		}
	})
}

func TestApplyRootlessCreatesVLANVRFMacvlanAndNFTGuard(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()
	runner.dnsReadyAt["qm-2001"] = 2
	runner.dnsByIface["qm-2001"] = "10.30.0.1 | 10.30.0.2\n"

	host := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name: "open-webui",
				User: "openwebui",
				UID:  2001,
				Network: &manifest.NetworkSpec{
					VLAN:          30,
					MAC:           "02:51:4D:00:07:D1",
					MacvlanMode:   "private",
					DNSFromDHCP:   true,
					OutboundGuard: boolPtr(true),
				},
				QuadletFiles: []manifest.SourceFile{
					{RelPath: "open-webui.container"},
					{RelPath: "open-webui.volume"},
					{RelPath: "open-webui.image"},
				},
			},
		},
	}

	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
	owned, liveDNS, nftHash, err := r.Apply(ctx, host, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("Apply unexpected error: %v", err)
	}

	// Verify owned records and <= 15 char ifnames.
	wantRecords := []state.ManagedNetworkRecord{
		{ConnectionName: "qm-vlan30", Kind: "vlan", Owned: true, Component: "open-webui", Scope: "openwebui"},
		{ConnectionName: "qmv-2001", Kind: "vrf", Owned: true, Component: "open-webui", Scope: "openwebui"},
		{ConnectionName: "qm-2001", Kind: "macvlan", Owned: true, Component: "open-webui", Scope: "openwebui"},
	}
	if !slices.Equal(owned, wantRecords) {
		t.Fatalf("owned = %+v, want %+v", owned, wantRecords)
	}
	for _, rec := range owned {
		if len(rec.ConnectionName) > 15 {
			t.Fatalf("ifname %q exceeds 15 chars", rec.ConnectionName)
		}
	}

	// Verify VLAN profile.
	vlanConn := runner.conns["qm-vlan30"]
	if vlanConn == nil {
		t.Fatal("qm-vlan30 was not created")
	}
	if vlanConn.props["vlan.parent"] != "enp3s0" || vlanConn.props["vlan.id"] != "30" ||
		vlanConn.props["ipv4.method"] != "disabled" || vlanConn.props["ipv6.method"] != "disabled" {
		t.Fatalf("unexpected qm-vlan30 props: %+v", vlanConn.props)
	}

	// Verify VRF profile and unreachable default route.
	vrfConn := runner.conns["qmv-2001"]
	if vrfConn == nil {
		t.Fatal("qmv-2001 was not created")
	}
	if vrfConn.props["vrf.table"] != "12001" ||
		vrfConn.props["ipv4.method"] != "disabled" || vrfConn.props["ipv6.method"] != "disabled" {
		t.Fatalf("unexpected qmv-2001 props: %+v", vrfConn.props)
	}
	if gotRoutes := runner.routes[12001]; len(gotRoutes) != 1 || !strings.Contains(gotRoutes[0], "unreachable default") || !strings.Contains(gotRoutes[0], "metric 8192") {
		t.Fatalf("unexpected table 12001 routes: %v", gotRoutes)
	}

	// Verify macvlan profile.
	mvConn := runner.conns["qm-2001"]
	if mvConn == nil {
		t.Fatal("qm-2001 was not created")
	}
	if mvConn.props["macvlan.parent"] != "qm-vlan30" ||
		mvConn.props["macvlan.mode"] != "private" ||
		mvConn.props["connection.controller"] != "qmv-2001" ||
		strings.ToLower(mvConn.props["802-3-ethernet.cloned-mac-address"]) != "02:51:4d:00:07:d1" ||
		mvConn.props["ipv4.method"] != "auto" ||
		mvConn.props["ipv4.route-table"] != "12001" ||
		mvConn.props["ipv4.ignore-auto-dns"] != "yes" ||
		mvConn.props["ipv6.method"] != "disabled" {
		t.Fatalf("unexpected qm-2001 props: %+v", mvConn.props)
	}

	// Verify live DHCP DNS polling succeeded and populated by component name.
	if !slices.Equal(liveDNS["open-webui"], []string{"10.30.0.1", "10.30.0.2"}) {
		t.Fatalf("liveDNS = %+v, want [10.30.0.1 10.30.0.2]", liveDNS)
	}

	// Verify nftables table inet quadmatic uses socket cgroupv2 (never skuid),
	// scopes to open-webui.service (not .image/.volume), and matches hash.
	if runner.nftTable == "" {
		t.Fatal("expected table inet quadmatic to be applied")
	}
	if !strings.Contains(runner.nftTable, "table inet quadmatic") {
		t.Fatalf("missing table inet quadmatic in:\n%s", runner.nftTable)
	}
	if !strings.Contains(runner.nftTable, "socket cgroupv2 level 5 \"user.slice/user-2001.slice/user@2001.service/app.slice/open-webui.service\"") {
		t.Fatalf("missing expected socket cgroupv2 match in:\n%s", runner.nftTable)
	}
	if strings.Contains(runner.nftTable, "skuid") {
		t.Fatalf("nftables ruleset must NEVER use skuid:\n%s", runner.nftTable)
	}
	if strings.Contains(runner.nftTable, "open-webui-image") || strings.Contains(runner.nftTable, "open-webui-volume") {
		t.Fatalf("nftables ruleset must not guard .image/.volume helper units:\n%s", runner.nftTable)
	}
	if !strings.Contains(runner.nftTable, "qm-2001") || !strings.Contains(runner.nftTable, "qmv-2001") || !strings.Contains(runner.nftTable, "drop") {
		t.Fatalf("nftables ruleset must allow qm-2001/qmv-2001 and drop other egress:\n%s", runner.nftTable)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(runner.nftTable)))
	if nftHash != wantHash {
		t.Fatalf("nftHash = %q, want %q", nftHash, wantHash)
	}

	// Verify DetectDrift returns false when packet counters are non-zero on live table.
	runner.nftCounters = true
	drifted, err := r.DetectDrift(ctx, host, owned)
	if err != nil {
		t.Fatalf("DetectDrift unexpected error: %v", err)
	}
	if drifted {
		t.Fatal("DetectDrift reported drift even though only packet/byte counters changed")
	}
}

func TestApplyRootfulOnlyEnsuresParentVLAN(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()

	host := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name:    "home-assistant",
				Rootful: true,
				Reason:  "L2 mDNS discovery",
				Network: &manifest.NetworkSpec{
					VLAN:          40,
					MAC:           "02:51:4d:00:00:40",
					OutboundGuard: boolPtr(true),
				},
			},
		},
	}

	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
	owned, liveDNS, nftHash, err := r.Apply(ctx, host, nil, time.Second)
	if err != nil {
		t.Fatalf("Apply unexpected error: %v", err)
	}
	want := []state.ManagedNetworkRecord{
		{ConnectionName: "qm-vlan40", Kind: "vlan", Owned: true, Component: "home-assistant", Scope: "rootful"},
	}
	if !slices.Equal(owned, want) {
		t.Fatalf("owned = %+v, want %+v", owned, want)
	}
	if len(liveDNS) != 0 {
		t.Fatalf("expected empty liveDNS for rootful component, got %+v", liveDNS)
	}
	if nftHash != "" || runner.nftTable != "" {
		t.Fatalf("expected no nftables ruleset for rootful component, got hash=%q table=%q", nftHash, runner.nftTable)
	}
	if len(runner.conns) != 1 || runner.conns["qm-vlan40"] == nil {
		t.Fatalf("expected only qm-vlan40 connection, got %+v", runner.conns)
	}
	if len(runner.routes) != 0 {
		t.Fatalf("expected zero VRF routes for rootful component, got %+v", runner.routes)
	}
}

func TestReuseUnmanagedManagementVLANAndNeverPruneIt(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()
	runner.unmanagedDev = []fakeDevice{
		{
			device: "enp3s0.3",
			typ:    "vlan",
			conn:   "enp3s0.3",
			parent: "enp3s0",
			vlanID: 3,
		},
	}

	hostWithComp := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name: "open-webui",
				User: "openwebui",
				UID:  2001,
				Network: &manifest.NetworkSpec{
					VLAN:        3,
					MAC:         "02:51:4d:00:07:d1",
					MacvlanMode: "private",
					DNS:         []string{"10.0.3.1"},
				},
			},
		},
	}

	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

	parents, err := r.ResolveVLANParents(ctx, hostWithComp)
	if err != nil {
		t.Fatalf("ResolveVLANParents error: %v", err)
	}
	if parents[3] != "enp3s0.3" {
		t.Fatalf("parents[3] = %q, want enp3s0.3", parents[3])
	}

	owned, _, _, err := r.Apply(ctx, hostWithComp, nil, time.Second)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	wantOwned := []state.ManagedNetworkRecord{
		{ConnectionName: "enp3s0.3", Kind: "vlan", Owned: false, Component: "open-webui", Scope: "openwebui"},
		{ConnectionName: "qmv-2001", Kind: "vrf", Owned: true, Component: "open-webui", Scope: "openwebui"},
		{ConnectionName: "qm-2001", Kind: "macvlan", Owned: true, Component: "open-webui", Scope: "openwebui"},
	}
	if !slices.Equal(owned, wantOwned) {
		t.Fatalf("owned = %+v, want %+v", owned, wantOwned)
	}
	if runner.conns["qm-vlan3"] != nil {
		t.Fatal("should not create qm-vlan3 when enp3s0.3 already exists on enp3s0")
	}
	if runner.conns["qm-2001"].props["macvlan.parent"] != "enp3s0.3" {
		t.Fatalf("macvlan parent = %q, want enp3s0.3", runner.conns["qm-2001"].props["macvlan.parent"])
	}

	// Remove the component on next Apply.
	runner.calls = nil
	hostEmpty := &manifest.ResolvedHost{Hostname: "services-02"}
	newOwned, _, nftHash, err := r.Apply(ctx, hostEmpty, owned, time.Second)
	if err != nil {
		t.Fatalf("Apply prune error: %v", err)
	}
	if len(newOwned) != 0 {
		t.Fatalf("expected empty newOwned, got %+v", newOwned)
	}
	if nftHash != "" || runner.nftTable != "" {
		t.Fatalf("expected nftables table removed, got hash=%q table=%q", nftHash, runner.nftTable)
	}
	if runner.conns["qm-2001"] != nil || runner.conns["qmv-2001"] != nil {
		t.Fatalf("expected qm-2001 and qmv-2001 pruned, remaining: %+v", runner.conns)
	}

	// Verify deletion order (macvlan -> vrf) and that enp3s0.3 was NEVER deleted or modified.
	var deleteTargets []string
	for _, call := range runner.calls {
		if call.name == "nmcli" && len(call.args) >= 3 && call.args[0] == "connection" {
			if call.args[1] == "delete" {
				deleteTargets = append(deleteTargets, call.args[2])
			}
			if (call.args[1] == "delete" || call.args[1] == "modify") && call.args[2] == "enp3s0.3" {
				t.Fatalf("must NEVER call nmcli connection %s on unmanaged enp3s0.3", call.args[1])
			}
		}
	}
	if !slices.Equal(deleteTargets, []string{"qm-2001", "qmv-2001"}) {
		t.Fatalf("delete order = %v, want [qm-2001 qmv-2001]", deleteTargets)
	}
}

func TestRestoreRollbackDeletesNewConnectionsAndRestoresSnapshot(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()
	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

	// Commit 1 succeeds with component A (UID 2001, VLAN 30).
	host1 := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name: "app-a",
				User: "appa",
				UID:  2001,
				Network: &manifest.NetworkSpec{
					VLAN: 30,
					MAC:  "02:51:4d:00:07:d1",
					DNS:  []string{"10.30.0.1"},
				},
			},
		},
	}
	owned1, _, _, err := r.Apply(ctx, host1, nil, time.Second)
	if err != nil {
		t.Fatalf("Commit 1 Apply error: %v", err)
	}

	snap, err := r.Snapshot(ctx, owned1)
	if err != nil {
		t.Fatalf("Snapshot error: %v", err)
	}
	if snap.NFTablesRuleset == "" {
		t.Fatal("expected Snapshot to capture existing nftables ruleset")
	}

	// Commit 2 modifies app-a MAC and adds app-b (UID 2002, VLAN 40), then fails during Apply
	// when bringing up qm-2002. Pre-flight ruling requires newOwned to still list created profiles!
	runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
		if name == "nmcli" && slices.Equal(args, []string{"connection", "up", "qm-2002"}) {
			return []byte("Error: dhcp failed"), errors.New("exit status 4")
		}
		return nil, nil
	}

	host2 := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name: "app-a",
				User: "appa",
				UID:  2001,
				Network: &manifest.NetworkSpec{
					VLAN: 30,
					MAC:  "02:51:4d:00:07:ff",
					DNS:  []string{"10.30.0.1"},
				},
			},
			{
				Name: "app-b",
				User: "appb",
				UID:  2002,
				Network: &manifest.NetworkSpec{
					VLAN: 40,
					MAC:  "02:51:4d:00:07:d2",
					DNS:  []string{"10.40.0.1"},
				},
			},
		},
	}

	partialOwned, _, _, err := r.Apply(ctx, host2, owned1, time.Second)
	if err == nil {
		t.Fatal("expected Commit 2 Apply to fail when qm-2002 up fails")
	}
	var partialNames []string
	for _, rec := range partialOwned {
		partialNames = append(partialNames, rec.ConnectionName)
	}
	for _, wantName := range []string{"qm-vlan30", "qm-vlan40", "qmv-2001", "qm-2001", "qmv-2002", "qm-2002"} {
		if !slices.Contains(partialNames, wantName) {
			t.Fatalf("partialOwned %v missing %q created prior to failure", partialNames, wantName)
		}
	}

	// Clear fail hook and restore snapshot.
	runner.failHook = nil
	if err := r.Restore(ctx, snap, partialOwned); err != nil {
		t.Fatalf("Restore error: %v", err)
	}

	// Newly created profiles from Commit 2 must be deleted.
	for _, gone := range []string{"qm-vlan40", "qmv-2002", "qm-2002"} {
		if runner.conns[gone] != nil {
			t.Fatalf("expected %q to be deleted during rollback, still present", gone)
		}
	}
	// Previous profiles and nftables ruleset must be restored.
	for _, kept := range []string{"qm-vlan30", "qmv-2001", "qm-2001"} {
		if runner.conns[kept] == nil || !runner.active[kept] {
			t.Fatalf("expected %q to be restored and active", kept)
		}
	}
	if gotMAC := strings.ToLower(runner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]); gotMAC != "02:51:4d:00:07:d1" {
		t.Fatalf("qm-2001 MAC = %q after rollback, want 02:51:4d:00:07:d1", gotMAC)
	}
	if !strings.Contains(runner.nftTable, "user-2001.slice") || strings.Contains(runner.nftTable, "user-2002.slice") {
		t.Fatalf("nftables ruleset not restored properly:\n%s", runner.nftTable)
	}
}

func TestSnapshotAndRestoreWhenNFTablesAbsent(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()
	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

	// Clean host: Snapshot succeeds even when table inet quadmatic does not exist yet.
	snap, err := r.Snapshot(ctx, nil)
	if err != nil {
		t.Fatalf("Snapshot on clean host error: %v", err)
	}
	if snap.NFTablesRuleset != "" {
		t.Fatalf("expected empty NFTablesRuleset, got %q", snap.NFTablesRuleset)
	}

	host := &manifest.ResolvedHost{
		Hostname: "services-02",
		Components: []manifest.ResolvedComponent{
			{
				Name: "open-webui",
				User: "openwebui",
				UID:  2001,
				Network: &manifest.NetworkSpec{
					VLAN: 30,
					MAC:  "02:51:4d:00:07:d1",
					DNS:  []string{"10.30.0.1"},
				},
			},
		},
	}
	created, _, _, err := r.Apply(ctx, host, nil, time.Second)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	if err := r.Restore(ctx, snap, created); err != nil {
		t.Fatalf("Restore error: %v", err)
	}
	if len(runner.conns) != 0 {
		t.Fatalf("expected all newly created connections removed, got %+v", runner.conns)
	}
	if runner.nftTable != "" {
		t.Fatalf("expected table inet quadmatic removed on bootstrap rollback, got:\n%s", runner.nftTable)
	}
}

func TestApplyValidationAndDHCPTimeoutAndDrift(t *testing.T) {
	ctx := context.Background()

	t.Run("DHCP timeout returns partial newOwned", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "open-webui",
					User: "openwebui",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN:        30,
						MAC:         "02:51:4d:00:07:d1",
						DNSFromDHCP: true,
					},
				},
			},
		}
		owned, _, _, err := r.Apply(ctx, host, nil, 60*time.Millisecond)
		if err == nil {
			t.Fatal("expected DHCP timeout error")
		}
		if len(owned) != 3 {
			t.Fatalf("expected 3 partial owned records on DHCP timeout, got %+v", owned)
		}
	})

	t.Run("ResolveVLANParents ignores own qm-vlan and wrong trunk", func(t *testing.T) {
		runner := newFakeRunner()
		runner.unmanagedDev = []fakeDevice{
			{device: "enp4s0.30", typ: "vlan", conn: "enp4s0.30", parent: "enp4s0", vlanID: 30},
			{device: "qm-vlan30", typ: "vlan", conn: "qm-vlan30", parent: "enp3s0", vlanID: 30},
		}
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app",
					User: "app",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:d1",
						DNS:  []string{"10.30.0.1"},
					},
				},
				{
					Name: "trunk-direct",
					User: "direct",
					UID:  2002,
					Network: &manifest.NetworkSpec{
						VLAN: 0,
						MAC:  "02:51:4d:00:07:d2",
						DNS:  []string{"10.0.3.1"},
					},
				},
			},
		}
		parents, err := r.ResolveVLANParents(ctx, host)
		if err != nil {
			t.Fatalf("ResolveVLANParents error: %v", err)
		}
		if parents[30] != "qm-vlan30" {
			t.Fatalf("parents[30] = %q, want qm-vlan30", parents[30])
		}
		if parents[0] != "enp3s0" {
			t.Fatalf("parents[0] = %q, want enp3s0", parents[0])
		}
	})

	t.Run("DetectDrift catches missing unreachable route and modified profile and nft drift", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app",
					User: "app",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:d1",
						DNS:  []string{"10.30.0.1"},
					},
				},
			},
		}
		owned, _, _, err := r.Apply(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("Apply error: %v", err)
		}

		drifted, err := r.DetectDrift(ctx, host, owned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift = (%v, %v), want (false, nil)", drifted, err)
		}

		// Delete unreachable route out-of-band.
		delete(runner.routes, 12001)
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift after route delete = (%v, %v), want (true, nil)", drifted, err)
		}

		// Re-apply heals it.
		owned, _, _, err = r.Apply(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("Apply heal error: %v", err)
		}
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift after heal = (%v, %v), want (false, nil)", drifted, err)
		}

		// Modify nftables out-of-band.
		runner.nftTable = "table inet quadmatic {\n}\n"
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift after nft drift = (%v, %v), want (true, nil)", drifted, err)
		}
	})
}

func TestIPv6CustomCgroupPatternIdempotencyAndEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("ipv6 bridge mode custom cgroup pattern and idempotent second Apply", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		if err := r.SetCgroupPattern("user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}/container"); err != nil {
			t.Fatalf("SetCgroupPattern error: %v", err)
		}
		if err := r.SetCgroupPattern("../escape"); err == nil {
			t.Fatal("expected invalid cgroup pattern to fail")
		}

		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "stack",
					User: "stack",
					UID:  2005,
					Network: &manifest.NetworkSpec{
						VLAN:          50,
						MAC:           "02:51:4d:00:20:05",
						MacvlanMode:   "bridge",
						DNS:           []string{"10.50.0.1"},
						IPv6:          true,
						OutboundGuard: boolPtr(true),
					},
					QuadletFiles: []manifest.SourceFile{
						{RelPath: "stack.pod.tmpl"},
						{RelPath: "web.container"},
					},
				},
			},
		}

		owned, _, _, err := r.Apply(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("Apply error: %v", err)
		}
		mv := runner.conns["qm-2005"]
		if mv == nil {
			t.Fatal("expected qm-2005")
		}
		if mv.props["macvlan.mode"] != "bridge" ||
			mv.props["ipv6.method"] != "auto" ||
			mv.props["ipv6.route-table"] != "12005" ||
			mv.props["ipv6.ignore-auto-dns"] != "yes" {
			t.Fatalf("unexpected ipv6/bridge props: %+v", mv.props)
		}
		if !strings.Contains(runner.nftTable, `socket cgroupv2 level 6 "user.slice/user-2005.slice/user@2005.service/app.slice/stack-pod.service/container"`) {
			t.Fatalf("missing level 6 .pod cgroup rule in:\n%s", runner.nftTable)
		}
		if !strings.Contains(runner.nftTable, `socket cgroupv2 level 6 "user.slice/user-2005.slice/user@2005.service/app.slice/web.service/container"`) {
			t.Fatalf("missing level 6 .container cgroup rule in:\n%s", runner.nftTable)
		}

		// Simulate NM returning "2 (bridge)" on connection show and verify second Apply is a no-op for NM add/modify/up.
		mv.props["macvlan.mode"] = "2 (bridge)"
		runner.calls = nil
		owned2, _, _, err := r.Apply(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("second Apply error: %v", err)
		}
		if !slices.Equal(owned2, owned) {
			t.Fatalf("owned2 = %+v, want %+v", owned2, owned)
		}
		for _, call := range runner.calls {
			if call.name == "nmcli" && len(call.args) >= 2 && call.args[0] == "connection" {
				switch call.args[1] {
				case "add", "modify", "up", "delete":
					t.Fatalf("expected idempotent Apply not to call nmcli connection %s, got %v", call.args[1], call.args)
				}
			}
		}
	})

	t.Run("outbound_guard=false omits nftables and empty trunk allowed when no networks", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("", runner, newZeroL3mdevSysctl())
		emptyHost := &manifest.ResolvedHost{Hostname: "services-02"}
		owned, _, hash, err := r.Apply(ctx, emptyHost, nil, time.Second)
		if err != nil {
			t.Fatalf("Apply empty host with empty trunk error: %v", err)
		}
		if len(owned) != 0 || hash != "" {
			t.Fatalf("expected empty result, got owned=%+v hash=%q", owned, hash)
		}

		// With outbound_guard=false and existing table inet quadmatic, table is removed.
		runner2 := newFakeRunner()
		runner2.nftTable = "table inet quadmatic {\n}\n"
		r2 := netmgr.NewReconciler("enp3s0", runner2, newZeroL3mdevSysctl())
		hostNoGuard := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "unguarded",
					User: "unguarded",
					UID:  2009,
					Network: &manifest.NetworkSpec{
						VLAN:          20,
						MAC:           "02:51:4d:00:20:09",
						DNS:           []string{"10.20.0.1"},
						OutboundGuard: boolPtr(false),
					},
				},
			},
		}
		_, _, hash2, err := r2.Apply(ctx, hostNoGuard, nil, time.Second)
		if err != nil {
			t.Fatalf("Apply unguarded error: %v", err)
		}
		if hash2 != "" || runner2.nftTable != "" {
			t.Fatalf("expected nftables removed when outbound_guard=false, got hash=%q table=%q", hash2, runner2.nftTable)
		}
	})

	t.Run("kernel-only VLAN device (-- connection) reused and stray qmv detected as drift", func(t *testing.T) {
		runner := newFakeRunner()
		runner.unmanagedDev = []fakeDevice{
			{device: "enp3s0.3", typ: "vlan", conn: "--", parent: "enp3s0", vlanID: 3},
		}
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app",
					User: "app",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN: 3,
						MAC:  "02:51:4d:00:07:d1",
						DNS:  []string{"10.0.3.1"},
					},
				},
			},
		}
		owned, _, _, err := r.Apply(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("Apply error: %v", err)
		}
		if owned[0].ConnectionName != "enp3s0.3" || owned[0].Owned {
			t.Fatalf("expected unmanaged enp3s0.3, got %+v", owned[0])
		}

		// Stray qmv-9999 connection must trigger DetectDrift.
		runner.conns["qmv-9999"] = &fakeNMConn{name: "qmv-9999", props: map[string]string{"connection.type": "vrf"}}
		drifted, err := r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift with stray qmv-9999 = (%v, %v), want (true, nil)", drifted, err)
		}
	})

	t.Run("Restore supports INI keyfile format and ReadLiveDNS deduplicates", func(t *testing.T) {
		runner := newFakeRunner()
		runner.dnsByIface["qm-2001"] = "10.30.0.1 | -- | 10.30.0.2 | 10.30.0.1 | bad-ip"
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		dns, err := r.ReadLiveDNS(ctx, "qm-2001")
		if err != nil {
			t.Fatalf("ReadLiveDNS error: %v", err)
		}
		if !slices.Equal(dns, []string{"10.30.0.1", "10.30.0.2"}) {
			t.Fatalf("ReadLiveDNS = %v, want [10.30.0.1 10.30.0.2]", dns)
		}

		snap := &netmgr.Snapshot{
			Profiles: map[string]string{
				"qm-vlan30": "[connection]\nid=qm-vlan30\ntype=vlan\ninterface-name=qm-vlan30\n\n[vlan]\nparent=enp3s0\nid=30\n\n[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=disabled\n",
			},
		}
		if err := r.Restore(ctx, snap, nil); err != nil {
			t.Fatalf("Restore keyfile snapshot error: %v", err)
		}
		if runner.conns["qm-vlan30"] == nil || runner.conns["qm-vlan30"].props["vlan.id"] != "30" {
			t.Fatalf("expected qm-vlan30 restored from keyfile, got %+v", runner.conns["qm-vlan30"])
		}
	})

	t.Run("rejects invalid ifname and missing trunk and enforces <=15 char UID limit", func(t *testing.T) {
		runner := newFakeRunner()
		rNoTrunk := netmgr.NewReconciler("", runner, newZeroL3mdevSysctl())
		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app",
					User: "app",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:d1",
						DNS:  []string{"10.30.0.1"},
					},
				},
			},
		}
		if _, _, _, err := rNoTrunk.Apply(ctx, host, nil, time.Second); err == nil {
			t.Fatal("expected error when trunk_interface is empty")
		}

		rLongUID := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		hostLongUID := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app",
					User: "app",
					UID:  123456789012, // qmv-123456789012 is 16 chars > 15
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:d1",
						DNS:  []string{"10.30.0.1"},
					},
				},
			},
		}
		if _, _, _, err := rLongUID.Apply(ctx, hostLongUID, nil, time.Second); err == nil {
			t.Fatal("expected error when VRF interface name exceeds 15 characters")
		}
	})
}
