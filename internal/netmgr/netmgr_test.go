package netmgr_test

import (
	"context"
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

type fakeIPRule struct {
	prio int
	text string
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
	calls          []recordedCmd
	conns          map[string]*fakeNMConn
	active         map[string]bool
	unmanagedDev   []fakeDevice
	rawVLANShowOut map[string]string
	rawIPLinkOut   map[string]string
	dnsByIface     map[string]string
	dnsPolls       map[string]int
	dnsReadyAt     map[string]int
	routes         map[int][]string
	routes6        map[int][]string
	rules          []fakeIPRule
	rules6         []fakeIPRule
	failHook       func(stdin []byte, name string, args []string) ([]byte, error)
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		conns:          make(map[string]*fakeNMConn),
		active:         make(map[string]bool),
		rawVLANShowOut: make(map[string]string),
		rawIPLinkOut:   make(map[string]string),
		dnsByIface:     make(map[string]string),
		dnsPolls:       make(map[string]int),
		dnsReadyAt:     make(map[string]int),
		routes:         make(map[int][]string),
		routes6:        make(map[int][]string),
		rules: []fakeIPRule{
			{prio: 0, text: "from all lookup local"},
			{prio: 32766, text: "from all lookup main"},
			{prio: 32767, text: "from all lookup default"},
		},
		rules6: []fakeIPRule{
			{prio: 0, text: "from all lookup local"},
			{prio: 32766, text: "from all lookup main"},
		},
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
	default:
		return nil, fmt.Errorf("unexpected binary %q", name)
	}
}

func (f *fakeRunner) handleNMCLI(args []string) ([]byte, error) {
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
					if raw, ok := f.rawVLANShowOut[id]; ok {
						return []byte(raw), nil
					}
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
			c, ok := f.conns[conName]
			if !ok {
				return []byte(fmt.Sprintf("Error: %s - no such connection profile.", conName)), fmt.Errorf("exit status 10")
			}
			f.active[conName] = true
			if c.props["connection.type"] == "vrf" {
				f.ensureFakeL3mdevRule(false)
				f.ensureFakeL3mdevRule(true)
			}
			return nil, nil

		case "down":
			if len(rest) < 3 {
				return nil, errors.New("nmcli connection down missing id")
			}
			conName := rest[2]
			c, ok := f.conns[conName]
			if !ok {
				return []byte(fmt.Sprintf("Error: %s - no such connection profile.", conName)), fmt.Errorf("exit status 10")
			}
			if !f.active[conName] {
				return []byte(fmt.Sprintf("Error: Connection '%s' is not an active connection.", conName)), fmt.Errorf("exit status 10")
			}
			delete(f.active, conName)
			if c.props["connection.type"] == "vrf" {
				for portName, portConn := range f.conns {
					if portConn.props["connection.controller"] == conName {
						delete(f.active, portName)
					}
				}
			}
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

func (f *fakeRunner) ensureFakeL3mdevRule(isV6 bool) {
	store := &f.rules
	if isV6 {
		store = &f.rules6
	}
	for _, r := range *store {
		if r.text == "from all lookup [l3mdev-table]" {
			return
		}
	}
	*store = append(*store, fakeIPRule{prio: 1000, text: "from all lookup [l3mdev-table]"})
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
	isV6 := false
	if len(args) > 0 && args[0] == "-6" {
		isV6 = true
		args = args[1:]
	}
	if len(args) >= 2 && args[0] == "rule" {
		return f.handleIPRule(isV6, args[1:])
	}
	routeStore := f.routes
	if isV6 {
		routeStore = f.routes6
	}
	if len(args) >= 2 && args[0] == "route" {
		switch args[1] {
		case "replace":
			tableID, route := extractIPRouteAndTable(args[2:])
			routeStore[tableID] = []string{route}
			return nil, nil
		case "del":
			tableID, _ := extractIPRouteAndTable(args[2:])
			delete(routeStore, tableID)
			return nil, nil
		case "show":
			tableID := 0
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "table" {
					tableID, _ = strconv.Atoi(args[i+1])
				}
			}
			return []byte(strings.Join(routeStore[tableID], "\n")), nil
		}
	}
	if len(args) >= 5 && args[0] == "-d" && args[1] == "-o" && args[2] == "link" && args[3] == "show" {
		devName := args[len(args)-1]
		if raw, ok := f.rawIPLinkOut[devName]; ok {
			return []byte(raw), nil
		}
		for _, d := range f.unmanagedDev {
			if d.device == devName {
				return []byte(fmt.Sprintf("5: %s@%s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 vlan protocol 802.1Q id %d", d.device, d.parent, d.vlanID)), nil
			}
		}
		return []byte("Device does not exist."), errors.New("exit status 1")
	}
	return nil, fmt.Errorf("unsupported ip command: %v", args)
}

func (f *fakeRunner) handleIPRule(isV6 bool, args []string) ([]byte, error) {
	store := &f.rules
	if isV6 {
		store = &f.rules6
	}
	switch args[0] {
	case "show", "list":
		sorted := slices.Clone(*store)
		slices.SortStableFunc(sorted, func(a, b fakeIPRule) int {
			return a.prio - b.prio
		})
		lines := make([]string, 0, len(sorted))
		for _, r := range sorted {
			lines = append(lines, fmt.Sprintf("%d:\t%s", r.prio, r.text))
		}
		return []byte(strings.Join(lines, "\n")), nil

	case "add":
		prio := -1
		table := ""
		for i := 1; i+1 < len(args); i += 2 {
			switch args[i] {
			case "prio", "pref", "priority":
				p, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, err
				}
				prio = p
			case "table", "lookup":
				table = args[i+1]
			}
		}
		if prio < 0 || table == "" {
			return nil, fmt.Errorf("unsupported ip rule add args: %v", args)
		}
		text := "from all lookup " + table
		for _, r := range *store {
			if r.prio == prio && r.text == text {
				return []byte("RTNETLINK answers: File exists"), errors.New("exit status 2")
			}
		}
		*store = append(*store, fakeIPRule{prio: prio, text: text})
		return nil, nil

	case "del":
		prio := -1
		table := ""
		for i := 1; i+1 < len(args); i += 2 {
			switch args[i] {
			case "prio", "pref", "priority":
				p, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, err
				}
				prio = p
			case "table", "lookup":
				table = args[i+1]
			}
		}
		if prio < 0 {
			return nil, fmt.Errorf("unsupported ip rule del args: %v", args)
		}
		for i, r := range *store {
			if r.prio == prio && (table == "" || strings.HasSuffix(r.text, "lookup "+table)) {
				*store = append((*store)[:i], (*store)[i+1:]...)
				return nil, nil
			}
		}
		return []byte("RTNETLINK answers: No such file or directory"), errors.New("exit status 2")

	default:
		return nil, fmt.Errorf("unsupported ip rule command: %v", args)
	}
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

func findCallIndex(calls []recordedCmd, name string, args ...string) int {
	for i, c := range calls {
		if c.name == name && slices.Equal(c.args, args) {
			return i
		}
	}
	return -1
}

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

func TestApplyProfilesRootlessCreatesVLANVRFMacvlanAndVRFRules(t *testing.T) {
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
					VLAN:        30,
					MAC:         "02:51:4D:00:07:D1",
					MacvlanMode: "private",
					DNSFromDHCP: true,
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
	owned, liveDNS, mutated, err := r.ApplyProfiles(ctx, host, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("ApplyProfiles unexpected error: %v", err)
	}

	// Verify owned records, <= 15 char ifnames, and mutated component tracking.
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
	if !mutated["open-webui"] {
		t.Fatalf("expected mutatedComponents[open-webui]=true, got %+v", mutated)
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
		mvConn.props["connection.port-type"] != "vrf" ||
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

	// Verify safe order of IPv4 l3mdev-before-local rule mutation (add 32765 BEFORE del 0 table local)
	// and that IPv6 rules were NOT touched when ipv6=false.
	addIdx := findCallIndex(runner.calls, "ip", "rule", "add", "prio", "32765", "table", "local")
	delIdx := findCallIndex(runner.calls, "ip", "rule", "del", "prio", "0", "table", "local")
	if addIdx < 0 || delIdx < 0 || addIdx >= delIdx {
		t.Fatalf("expected ip rule add prio 32765 before del prio 0, got addIdx=%d delIdx=%d calls=%+v", addIdx, delIdx, runner.calls)
	}
	if slices.Contains(runner.rules, fakeIPRule{prio: 0, text: "from all lookup local"}) {
		t.Fatalf("expected prio 0 local rule removed, got %+v", runner.rules)
	}
	if !slices.Contains(runner.rules, fakeIPRule{prio: 32765, text: "from all lookup local"}) {
		t.Fatalf("expected prio 32765 local rule added, got %+v", runner.rules)
	}
	for _, call := range runner.calls {
		if call.name == "ip" && len(call.args) >= 2 && call.args[0] == "-6" && call.args[1] == "rule" {
			t.Fatalf("did not expect ip -6 rule call when ipv6=false, got %v", call)
		}
	}

	// Idempotent second ApplyProfiles must not call nmcli add/modify/up/delete or ip rule add/del.
	runner.calls = nil
	_, _, mutated2, err := r.ApplyProfiles(ctx, host, owned, 2*time.Second)
	if err != nil {
		t.Fatalf("second ApplyProfiles error: %v", err)
	}
	if len(mutated2) != 0 {
		t.Fatalf("expected empty mutatedComponents on idempotent pass, got %+v", mutated2)
	}
	for _, call := range runner.calls {
		if call.name == "ip" && len(call.args) >= 2 && call.args[0] == "rule" && (call.args[1] == "add" || call.args[1] == "del") {
			t.Fatalf("expected idempotent ApplyProfiles not to mutate ip rule, got %v", call)
		}
		if call.name == "nmcli" && len(call.args) >= 2 && call.args[0] == "connection" {
			switch call.args[1] {
			case "add", "modify", "up", "delete":
				t.Fatalf("expected idempotent ApplyProfiles not to call nmcli connection %s, got %v", call.args[1], call.args)
			}
		}
	}

	drifted, err := r.DetectDrift(ctx, host, owned)
	if err != nil || drifted {
		t.Fatalf("DetectDrift = (%v, %v), want (false, nil)", drifted, err)
	}
}

func TestL3mdevBeforeLocalRuleHardeningAndDrift(t *testing.T) {
	ctx := context.Background()

	t.Run("aborts before del prio 0 if add prio 32765 fails", func(t *testing.T) {
		runner := newFakeRunner()
		runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
			if name == "ip" && slices.Equal(args, []string{"rule", "add", "prio", "32765", "table", "local"}) {
				return []byte("operation not permitted"), errors.New("exit status 2")
			}
			return nil, nil
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
			},
		}

		_, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err == nil {
			t.Fatal("expected ApplyProfiles to fail when ip rule add prio 32765 fails")
		}
		if idx := findCallIndex(runner.calls, "ip", "rule", "del", "prio", "0", "table", "local"); idx >= 0 {
			t.Fatalf("must NEVER run ip rule del prio 0 table local when add prio 32765 fails")
		}
		if !slices.Contains(runner.rules, fakeIPRule{prio: 0, text: "from all lookup local"}) {
			t.Fatalf("expected prio 0 local rule preserved when add fails, got %+v", runner.rules)
		}
	})

	t.Run("IPv4 and IPv6 rule drift detection and auto-healing", func(t *testing.T) {
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
						IPv6: true,
					},
				},
			},
		}

		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles error: %v", err)
		}
		add4 := findCallIndex(runner.calls, "ip", "rule", "add", "prio", "32765", "table", "local")
		del4 := findCallIndex(runner.calls, "ip", "rule", "del", "prio", "0", "table", "local")
		add6 := findCallIndex(runner.calls, "ip", "-6", "rule", "add", "prio", "32765", "table", "local")
		del6 := findCallIndex(runner.calls, "ip", "-6", "rule", "del", "prio", "0", "table", "local")
		if add4 < 0 || del4 < 0 || add4 >= del4 {
			t.Fatalf("invalid IPv4 rule mutation order: add=%d del=%d", add4, del4)
		}
		if add6 < 0 || del6 < 0 || add6 >= del6 {
			t.Fatalf("invalid IPv6 rule mutation order: add=%d del=%d", add6, del6)
		}

		// Idempotent second run must not mutate IPv4 or IPv6 rules.
		runner.calls = nil
		if _, _, _, err := r.ApplyProfiles(ctx, host, owned, time.Second); err != nil {
			t.Fatalf("second ApplyProfiles error: %v", err)
		}
		for _, call := range runner.calls {
			if call.name == "ip" && slices.Contains(call.args, "rule") && (slices.Contains(call.args, "add") || slices.Contains(call.args, "del")) {
				t.Fatalf("expected idempotent IPv4/IPv6 ip rule check, got %v", call)
			}
		}

		// Reintroduce prio 0 on IPv4 out-of-band -> DetectDrift returns true -> ApplyProfiles heals.
		runner.rules = append(runner.rules, fakeIPRule{prio: 0, text: "from all lookup local"})
		drifted, err := r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift after IPv4 prio 0 reappearance = (%v, %v), want (true, nil)", drifted, err)
		}
		runner.calls = nil
		_, _, mutated, err := r.ApplyProfiles(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles IPv4 rule heal error: %v", err)
		}
		if len(mutated) != 0 {
			t.Fatalf("expected no component restart needed when only ip rule healed, got %+v", mutated)
		}
		if findCallIndex(runner.calls, "ip", "rule", "add", "prio", "32765", "table", "local") >= 0 {
			t.Fatal("should not re-add prio 32765 when already present")
		}
		if findCallIndex(runner.calls, "ip", "rule", "del", "prio", "0", "table", "local") < 0 {
			t.Fatal("expected del prio 0 table local to heal reintroduced IPv4 rule")
		}
		if drifted, err := r.DetectDrift(ctx, host, owned); err != nil || drifted {
			t.Fatalf("DetectDrift after IPv4 heal = (%v, %v), want (false, nil)", drifted, err)
		}

		// Reset IPv6 rules back to prio 0 without prio 32765 -> DetectDrift returns true -> ApplyProfiles heals.
		runner.rules6 = []fakeIPRule{
			{prio: 0, text: "from all lookup local"},
			{prio: 1000, text: "from all lookup [l3mdev-table]"},
			{prio: 32766, text: "from all lookup main"},
		}
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift after IPv6 rule reset = (%v, %v), want (true, nil)", drifted, err)
		}
		runner.calls = nil
		if _, _, _, err := r.ApplyProfiles(ctx, host, owned, time.Second); err != nil {
			t.Fatalf("ApplyProfiles IPv6 rule heal error: %v", err)
		}
		add6 = findCallIndex(runner.calls, "ip", "-6", "rule", "add", "prio", "32765", "table", "local")
		del6 = findCallIndex(runner.calls, "ip", "-6", "rule", "del", "prio", "0", "table", "local")
		if add6 < 0 || del6 < 0 || add6 >= del6 {
			t.Fatalf("expected safe IPv6 rule heal order add<del, got add=%d del=%d", add6, del6)
		}
		if drifted, err := r.DetectDrift(ctx, host, owned); err != nil || drifted {
			t.Fatalf("DetectDrift after IPv6 heal = (%v, %v), want (false, nil)", drifted, err)
		}
	})
}

func TestApplyProfilesRootfulOnlyEnsuresParentVLAN(t *testing.T) {
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
					VLAN: 40,
					MAC:  "02:51:4d:00:00:40",
				},
			},
		},
	}

	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
	owned, liveDNS, mutated, err := r.ApplyProfiles(ctx, host, nil, time.Second)
	if err != nil {
		t.Fatalf("ApplyProfiles unexpected error: %v", err)
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
	if !mutated["home-assistant"] {
		t.Fatalf("expected mutated[home-assistant]=true, got %+v", mutated)
	}
	if len(runner.conns) != 1 || runner.conns["qm-vlan40"] == nil {
		t.Fatalf("expected only qm-vlan40 connection, got %+v", runner.conns)
	}
	if len(runner.routes) != 0 {
		t.Fatalf("expected zero VRF routes for rootful component, got %+v", runner.routes)
	}
	for _, call := range runner.calls {
		if call.name == "ip" && slices.Contains(call.args, "rule") {
			t.Fatalf("rootful-only host must not touch ip rule, got %v", call)
		}
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

	owned, _, _, err := r.ApplyProfiles(ctx, hostWithComp, nil, time.Second)
	if err != nil {
		t.Fatalf("ApplyProfiles error: %v", err)
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

	// Remove the component on next ApplyProfiles.
	runner.calls = nil
	hostEmpty := &manifest.ResolvedHost{Hostname: "services-02"}
	newOwned, _, _, err := r.ApplyProfiles(ctx, hostEmpty, owned, time.Second)
	if err != nil {
		t.Fatalf("ApplyProfiles prune error: %v", err)
	}
	if len(newOwned) != 0 {
		t.Fatalf("expected empty newOwned, got %+v", newOwned)
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
	owned1, _, _, err := r.ApplyProfiles(ctx, host1, nil, time.Second)
	if err != nil {
		t.Fatalf("Commit 1 ApplyProfiles error: %v", err)
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

	snap, err := r.Snapshot(ctx, host2, owned1)
	if err != nil {
		t.Fatalf("Snapshot error: %v", err)
	}

	// Commit 2 modifies app-a MAC and adds app-b (UID 2002, VLAN 40), then fails during ApplyProfiles
	// when bringing up qm-2002.
	runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
		if name == "nmcli" && slices.Equal(args, []string{"connection", "up", "qm-2002"}) {
			return []byte("Error: dhcp failed"), errors.New("exit status 4")
		}
		return nil, nil
	}

	partialOwned, _, _, err := r.ApplyProfiles(ctx, host2, owned1, time.Second)
	if err == nil {
		t.Fatal("expected Commit 2 ApplyProfiles to fail when qm-2002 up fails")
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
	// Previous profiles must be restored.
	for _, kept := range []string{"qm-vlan30", "qmv-2001", "qm-2001"} {
		if runner.conns[kept] == nil || !runner.active[kept] {
			t.Fatalf("expected %q to be restored and active", kept)
		}
	}
	if gotMAC := strings.ToLower(runner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]); gotMAC != "02:51:4d:00:07:d1" {
		t.Fatalf("qm-2001 MAC = %q after rollback, want 02:51:4d:00:07:d1", gotMAC)
	}
}

func TestSnapshotAndRestoreCleanHostAndAdoptedProfiles(t *testing.T) {
	ctx := context.Background()

	t.Run("clean host snapshot and restore deletes created connections", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		snap, err := r.Snapshot(ctx, nil, nil)
		if err != nil {
			t.Fatalf("Snapshot on clean host error: %v", err)
		}
		if len(snap.Profiles) != 0 {
			t.Fatalf("expected empty snap.Profiles, got %+v", snap.Profiles)
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
		created, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles error: %v", err)
		}

		if err := r.Restore(ctx, snap, created); err != nil {
			t.Fatalf("Restore error: %v", err)
		}
		if len(runner.conns) != 0 {
			t.Fatalf("expected all newly created connections removed, got %+v", runner.conns)
		}
	})

	t.Run("Snapshot with empty state captures pre-existing live qm profiles and Restore preserves them", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		// Pre-existing live NM profiles from before state.json was lost/reset.
		hostBefore := &manifest.ResolvedHost{
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
		if _, _, _, err := r.ApplyProfiles(ctx, hostBefore, nil, time.Second); err != nil {
			t.Fatalf("initial ApplyProfiles error: %v", err)
		}

		// Simulate lost/empty state.json (prevOwned == nil), while a new commit modifies app-a and adds app-b.
		hostAfter := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "app-a",
					User: "appa",
					UID:  2001,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:ee",
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

		snap, err := r.Snapshot(ctx, hostAfter, nil)
		if err != nil {
			t.Fatalf("Snapshot(ctx, hostAfter, nil) error: %v", err)
		}
		for _, wantKey := range []string{"qm-vlan30", "qmv-2001", "qm-2001"} {
			if _, ok := snap.Profiles[wantKey]; !ok {
				t.Fatalf("expected Snapshot to capture pre-existing live %q when owned=nil, got %v", wantKey, snap.Profiles)
			}
		}
		if _, ok := snap.Profiles["qm-2002"]; ok {
			t.Fatal("did not expect non-existent qm-2002 in Snapshot")
		}

		// Fail while bringing up qm-2002 after mutating qm-2001.
		runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
			if name == "nmcli" && slices.Equal(args, []string{"connection", "up", "qm-2002"}) {
				return []byte("Error: dhcp failed"), errors.New("exit status 4")
			}
			return nil, nil
		}
		partialOwned, _, _, err := r.ApplyProfiles(ctx, hostAfter, nil, time.Second)
		if err == nil {
			t.Fatal("expected ApplyProfiles to fail on qm-2002 up")
		}

		runner.failHook = nil
		if err := r.Restore(ctx, snap, partialOwned); err != nil {
			t.Fatalf("Restore error: %v", err)
		}

		// Newly created app-b profiles must be deleted; pre-existing adopted app-a profiles must be restored, not deleted!
		for _, gone := range []string{"qm-vlan40", "qmv-2002", "qm-2002"} {
			if runner.conns[gone] != nil {
				t.Fatalf("expected newly created %q deleted on Restore", gone)
			}
		}
		for _, kept := range []string{"qm-vlan30", "qmv-2001", "qm-2001"} {
			if runner.conns[kept] == nil || !runner.active[kept] {
				t.Fatalf("expected pre-existing %q preserved and active after Restore", kept)
			}
		}
		if gotMAC := strings.ToLower(runner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]); gotMAC != "02:51:4d:00:07:d1" {
			t.Fatalf("expected adopted qm-2001 MAC restored to 02:51:4d:00:07:d1, got %q", gotMAC)
		}
	})
}

func TestRestoreCollectsAllErrorsAndContinues(t *testing.T) {
	ctx := context.Background()
	runner := newFakeRunner()
	r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

	// Seed two newly created connections to delete (qm-2002, qmv-2002) and two snapshotted
	// connections to restore (qmv-2001, qm-2001).
	runner.conns["qm-2002"] = &fakeNMConn{name: "qm-2002", props: map[string]string{"connection.type": "macvlan"}}
	runner.conns["qmv-2002"] = &fakeNMConn{name: "qmv-2002", props: map[string]string{"connection.type": "vrf"}}
	runner.conns["qm-vlan30"] = &fakeNMConn{
		name: "qm-vlan30",
		props: map[string]string{
			"connection.type":           "vlan",
			"connection.interface-name": "qm-vlan30",
			"vlan.parent":               "enp3s0",
			"vlan.id":                   "30",
			"ipv4.method":               "disabled",
			"ipv6.method":               "disabled",
		},
	}

	snap := &netmgr.Snapshot{
		Profiles: map[string]string{
			"qmv-2001": "connection.id:qmv-2001\nconnection.type:vrf\nconnection.interface-name:qmv-2001\nvrf.table:12001\nipv4.method:disabled\nipv6.method:disabled\n",
			"qm-2001":  "connection.id:qm-2001\nconnection.type:macvlan\nconnection.interface-name:qm-2001\nmacvlan.parent:qm-vlan30\nmacvlan.mode:private\nconnection.controller:qmv-2001\nconnection.port-type:vrf\n802-3-ethernet.cloned-mac-address:02\\:51\\:4d\\:00\\:07\\:d1\nipv4.method:auto\nipv4.route-table:12001\nipv4.ignore-auto-dns:yes\nipv6.method:disabled\n",
		},
	}
	created := []state.ManagedNetworkRecord{
		{ConnectionName: "qm-2002", Kind: "macvlan", Owned: true},
		{ConnectionName: "qmv-2002", Kind: "vrf", Owned: true},
	}

	// Inject failures on:
	// 1. delete qm-2002 (must still delete qmv-2002)
	// 2. listActiveConnectionNames (must still proceed to restore qmv-2001 and qm-2001)
	// 3. up qmv-2001 (must still restore and bring up qm-2001)
	runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
		if name == "nmcli" {
			switch {
			case slices.Equal(args, []string{"connection", "delete", "qm-2002"}):
				return []byte("delete qm-2002 failed"), errors.New("exit status 1")
			case slices.Equal(args, []string{"-t", "-f", "NAME", "connection", "show", "--active"}):
				return []byte("active list failed"), errors.New("exit status 1")
			case slices.Equal(args, []string{"connection", "up", "qmv-2001"}):
				return []byte("up qmv-2001 failed"), errors.New("exit status 4")
			}
		}
		return nil, nil
	}

	err := r.Restore(ctx, snap, created)
	if err == nil {
		t.Fatal("expected Restore to return joined errors")
	}
	errMsg := err.Error()
	for _, wantSub := range []string{"delete qm-2002 failed", "active list failed", "up qmv-2001 failed"} {
		if !strings.Contains(errMsg, wantSub) {
			t.Fatalf("expected joined error to contain %q, got:\n%s", wantSub, errMsg)
		}
	}

	// Even though qm-2002 delete failed, qmv-2002 MUST have been deleted.
	if runner.conns["qmv-2002"] != nil {
		t.Fatal("expected Restore to continue and delete qmv-2002 despite qm-2002 failure")
	}
	// Even though --active and qmv-2001 up failed, qm-2001 MUST have been restored and brought up.
	if runner.conns["qm-2001"] == nil || !runner.active["qm-2001"] {
		t.Fatalf("expected Restore to continue and bring up qm-2001, conns=%+v active=%+v", runner.conns, runner.active)
	}
}

func TestApplyProfilesValidationAndDHCPTimeoutAndDrift(t *testing.T) {
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
		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, 60*time.Millisecond)
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

	t.Run("DetectDrift catches missing unreachable route and modified profile", func(t *testing.T) {
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
		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles error: %v", err)
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
		owned, _, _, err = r.ApplyProfiles(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles heal error: %v", err)
		}
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift after heal = (%v, %v), want (false, nil)", drifted, err)
		}
	})

	t.Run("rejects invalid MAC addresses via shared manifest.NormalizeAndValidateMAC", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())
		for _, badMAC := range []string{"", "not-a-mac", "00:00:00:00:00:00", "01:51:4d:00:07:d1"} {
			host := &manifest.ResolvedHost{
				Hostname: "services-02",
				Components: []manifest.ResolvedComponent{
					{
						Name: "app",
						User: "app",
						UID:  2001,
						Network: &manifest.NetworkSpec{
							VLAN: 30,
							MAC:  badMAC,
							DNS:  []string{"10.30.0.1"},
						},
					},
				},
			}
			if _, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second); err == nil {
				t.Fatalf("expected error for invalid MAC %q", badMAC)
			}
		}
	})
}

func TestIPv6RouteLifecycleAndEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("ipv6 bridge mode and idempotent second ApplyProfiles", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		host := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				{
					Name: "stack",
					User: "stack",
					UID:  2005,
					Network: &manifest.NetworkSpec{
						VLAN:        50,
						MAC:         "02:51:4d:00:20:05",
						MacvlanMode: "bridge",
						DNS:         []string{"10.50.0.1"},
						IPv6:        true,
					},
				},
			},
		}

		owned, _, mutated, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles error: %v", err)
		}
		if !mutated["stack"] {
			t.Fatalf("expected mutated[stack]=true, got %+v", mutated)
		}
		mv := runner.conns["qm-2005"]
		if mv == nil {
			t.Fatal("expected qm-2005")
		}
		if mv.props["macvlan.mode"] != "bridge" ||
			mv.props["connection.port-type"] != "vrf" ||
			mv.props["ipv6.method"] != "auto" ||
			mv.props["ipv6.route-table"] != "12005" ||
			mv.props["ipv6.ignore-auto-dns"] != "yes" {
			t.Fatalf("unexpected ipv6/bridge props: %+v", mv.props)
		}
		if gotR6 := runner.routes6[12005]; len(gotR6) != 1 || !strings.Contains(gotR6[0], "unreachable default") || !strings.Contains(gotR6[0], "metric 8192") {
			t.Fatalf("expected IPv6 unreachable default route in table 12005, got %v", gotR6)
		}

		// Missing IPv6 unreachable route must be flagged by DetectDrift and healed by ApplyProfiles.
		delete(runner.routes6, 12005)
		drifted6, err := r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted6 {
			t.Fatalf("DetectDrift after IPv6 route delete = (%v, %v), want (true, nil)", drifted6, err)
		}
		if owned, _, _, err = r.ApplyProfiles(ctx, host, owned, time.Second); err != nil {
			t.Fatalf("ApplyProfiles heal IPv6 route error: %v", err)
		}
		if gotR6 := runner.routes6[12005]; len(gotR6) != 1 {
			t.Fatalf("expected IPv6 unreachable route healed, got %v", gotR6)
		}

		// Snapshot & Restore preserves IPv6 unreachable route even after deleting it.
		snap, err := r.Snapshot(ctx, host, owned)
		if err != nil {
			t.Fatalf("Snapshot error: %v", err)
		}
		delete(runner.routes6, 12005)
		if err := r.Restore(ctx, snap, owned); err != nil {
			t.Fatalf("Restore error: %v", err)
		}
		if gotR6 := runner.routes6[12005]; len(gotR6) != 1 {
			t.Fatalf("expected IPv6 unreachable route restored, got %v", gotR6)
		}

		// Simulate NM returning "2 (bridge)" on connection show and verify second ApplyProfiles is a no-op.
		mv.props["macvlan.mode"] = "2 (bridge)"
		runner.calls = nil
		owned2, _, mutated2, err := r.ApplyProfiles(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("second ApplyProfiles error: %v", err)
		}
		if len(mutated2) != 0 {
			t.Fatalf("expected empty mutatedComponents on second pass, got %+v", mutated2)
		}
		if !slices.Equal(owned2, owned) {
			t.Fatalf("owned2 = %+v, want %+v", owned2, owned)
		}
		for _, call := range runner.calls {
			if call.name == "nmcli" && len(call.args) >= 2 && call.args[0] == "connection" {
				switch call.args[1] {
				case "add", "modify", "up", "delete":
					t.Fatalf("expected idempotent ApplyProfiles not to call nmcli connection %s, got %v", call.args[1], call.args)
				}
			}
		}

		// Pruning removes both IPv4 and IPv6 unreachable default routes.
		if _, _, _, err := r.ApplyProfiles(ctx, &manifest.ResolvedHost{Hostname: "services-02"}, owned2, time.Second); err != nil {
			t.Fatalf("prune ApplyProfiles error: %v", err)
		}
		if len(runner.routes[12005]) != 0 || len(runner.routes6[12005]) != 0 {
			t.Fatalf("expected both IPv4 and IPv6 routes cleaned up on prune, got v4=%v v6=%v", runner.routes[12005], runner.routes6[12005])
		}
	})

	t.Run("empty trunk allowed when no networks", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("", runner, newZeroL3mdevSysctl())
		emptyHost := &manifest.ResolvedHost{Hostname: "services-02"}
		owned, _, mutated, err := r.ApplyProfiles(ctx, emptyHost, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles empty host with empty trunk error: %v", err)
		}
		if len(owned) != 0 || len(mutated) != 0 {
			t.Fatalf("expected empty result, got owned=%+v mutated=%+v", owned, mutated)
		}
	})

	t.Run("kernel-only VLAN device (-- connection) reused and stale tracked vs untracked drift", func(t *testing.T) {
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
		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles error: %v", err)
		}
		if owned[0].ConnectionName != "enp3s0.3" || owned[0].Owned {
			t.Fatalf("expected unmanaged enp3s0.3, got %+v", owned[0])
		}

		// Untracked qm-9999 / qmv-9999 outside state.json must NOT be flagged as drift or deleted.
		runner.conns["qm-9999"] = &fakeNMConn{name: "qm-9999", props: map[string]string{"connection.type": "macvlan"}}
		runner.conns["qmv-9999"] = &fakeNMConn{name: "qmv-9999", props: map[string]string{"connection.type": "vrf"}}
		drifted, err := r.DetectDrift(ctx, host, owned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift with untracked qm-9999/qmv-9999 = (%v, %v), want (false, nil)", drifted, err)
		}

		// ApplyProfiles must not delete untracked qm-9999/qmv-9999.
		owned, _, _, err = r.ApplyProfiles(ctx, host, owned, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles with untracked profiles error: %v", err)
		}
		if runner.conns["qm-9999"] == nil || runner.conns["qmv-9999"] == nil {
			t.Fatalf("ApplyProfiles must not touch untracked qm-9999/qmv-9999, got %+v", runner.conns)
		}

		// Stale tracked profile in state.json (Owned: true) missing from host and still live in NM
		// MUST be flagged as drift and healed by ApplyProfiles.
		runner.conns["qm-2002"] = &fakeNMConn{name: "qm-2002", props: map[string]string{"connection.type": "macvlan"}}
		staleOwned := append(slices.Clone(owned), state.ManagedNetworkRecord{
			ConnectionName: "qm-2002",
			Kind:           "macvlan",
			Owned:          true,
			Component:      "removed",
			Scope:          "removed",
		})
		drifted, err = r.DetectDrift(ctx, host, staleOwned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift with stale tracked qm-2002 = (%v, %v), want (true, nil)", drifted, err)
		}
		healedOwned, _, _, err := r.ApplyProfiles(ctx, host, staleOwned, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles heal stale error: %v", err)
		}
		if runner.conns["qm-2002"] != nil {
			t.Fatal("expected stale tracked qm-2002 to be pruned by ApplyProfiles")
		}
		drifted, err = r.DetectDrift(ctx, host, healedOwned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift after pruning stale tracked qm-2002 = (%v, %v), want (false, nil)", drifted, err)
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
		if _, _, _, err := rNoTrunk.ApplyProfiles(ctx, host, nil, time.Second); err == nil {
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
		if _, _, _, err := rLongUID.ApplyProfiles(ctx, hostLongUID, nil, time.Second); err == nil {
			t.Fatal("expected error when VRF interface name exceeds 15 characters")
		}
	})
}

func TestUnmanagedVLANFallbackAndPortTypeCompatibility(t *testing.T) {
	ctx := context.Background()

	t.Run("empty or UUID vlan.parent falls back to inspectKernelVLANLink", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			showOut string
		}{
			{name: "empty vlan.parent", showOut: "\n3\n"},
			{name: "UUID vlan.parent", showOut: "5fb06bd0-0bb0-7ffb-45f1-d6edd65f3e03\n3\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				runner := newFakeRunner()
				runner.unmanagedDev = []fakeDevice{
					{device: "enp3s0.3", typ: "vlan", conn: "mgmt-vlan3", parent: "enp3s0", vlanID: 3},
				}
				runner.rawVLANShowOut["mgmt-vlan3"] = tc.showOut

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

				parents, err := r.ResolveVLANParents(ctx, host)
				if err != nil {
					t.Fatalf("ResolveVLANParents error: %v", err)
				}
				if parents[3] != "enp3s0.3" {
					t.Fatalf("parents[3] = %q, want enp3s0.3", parents[3])
				}
			})
		}
	})

	t.Run("inspectKernelVLANLink enforces token delimiter before device@", func(t *testing.T) {
		runner := newFakeRunner()
		runner.unmanagedDev = []fakeDevice{
			{device: "enp3s0.3", typ: "vlan", conn: "--", parent: "enp3s0", vlanID: 3},
		}
		runner.rawIPLinkOut["enp3s0.3"] = "5: bad_enp3s0.3@enp3s0: <BROADCAST> mtu 1500 vlan protocol 802.1Q id 3"

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
		parents, err := r.ResolveVLANParents(ctx, host)
		if err != nil {
			t.Fatalf("ResolveVLANParents error: %v", err)
		}
		if parents[3] != "qm-vlan3" {
			t.Fatalf("expected non-matching prefix to fall back to qm-vlan3, got %q", parents[3])
		}

		runner.rawIPLinkOut["enp3s0.3"] = "5: enp3s0.3@enp3s0: <BROADCAST> mtu 1500 vlan protocol 802.1Q id 3"
		parents, err = r.ResolveVLANParents(ctx, host)
		if err != nil {
			t.Fatalf("ResolveVLANParents error: %v", err)
		}
		if parents[3] != "enp3s0.3" {
			t.Fatalf("expected matching enp3s0.3, got %q", parents[3])
		}
	})

	t.Run("connection.port-type vrf and legacy connection.slave-type compatibility", func(t *testing.T) {
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

		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("ApplyProfiles failed: %v", err)
		}
		mv := runner.conns["qm-2001"]
		if mv.props["connection.port-type"] != "vrf" {
			t.Fatalf("expected connection.port-type=vrf, got %+v", mv.props)
		}

		// Simulate NM returning legacy connection.slave-type=vrf with empty connection.port-type.
		delete(mv.props, "connection.port-type")
		mv.props["connection.slave-type"] = "vrf"
		drifted, err := r.DetectDrift(ctx, host, owned)
		if err != nil || drifted {
			t.Fatalf("DetectDrift with connection.slave-type=vrf = (%v, %v), want (false, nil)", drifted, err)
		}

		// Wrong port-type / slave-type triggers drift and heals to vrf.
		mv.props["connection.slave-type"] = "bridge"
		drifted, err = r.DetectDrift(ctx, host, owned)
		if err != nil || !drifted {
			t.Fatalf("DetectDrift with wrong slave-type = (%v, %v), want (true, nil)", drifted, err)
		}
		if _, _, _, err := r.ApplyProfiles(ctx, host, owned, time.Second); err != nil {
			t.Fatalf("ApplyProfiles heal port-type failed: %v", err)
		}
		if mv.props["connection.port-type"] != "vrf" {
			t.Fatalf("expected healed connection.port-type=vrf, got %+v", mv.props)
		}
	})
}

func TestRestorePreservesPreApplyInactiveProfilesAndCustomPrio0Rule(t *testing.T) {
	ctx := context.Background()

	t.Run("Snapshot records ActiveProfiles and Restore downs newly-activated inactive profiles", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		host := &manifest.ResolvedHost{
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
				{
					Name: "app-b",
					User: "appb",
					UID:  2002,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:d2",
						DNS:  []string{"10.30.0.1"},
					},
				},
			},
		}

		// Apply both components initially.
		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("initial ApplyProfiles failed: %v", err)
		}

		// Simulate operator manually downing qm-2002 (inactive before run) while qm-2001 remains active,
		// and qmv-2002 stays inactive too.
		delete(runner.active, "qm-2002")
		delete(runner.active, "qmv-2002")

		// Next commit changes qm-2001 MAC and modifies qm-2002 MAC, then fails after bringing qm-2002 up.
		host2 := &manifest.ResolvedHost{
			Hostname: "services-02",
			Components: []manifest.ResolvedComponent{
				host.Components[0],
				{
					Name: "app-b",
					User: "appb",
					UID:  2002,
					Network: &manifest.NetworkSpec{
						VLAN: 30,
						MAC:  "02:51:4d:00:07:e2",
						DNS:  []string{"10.30.0.1"},
					},
				},
			},
		}

		snap, err := r.Snapshot(ctx, host2, owned)
		if err != nil {
			t.Fatalf("Snapshot failed: %v", err)
		}
		if !snap.ActiveProfiles["qm-2001"] || !snap.ActiveProfiles["qmv-2001"] || !snap.ActiveProfiles["qm-vlan30"] {
			t.Fatalf("expected active profiles recorded true, got %+v", snap.ActiveProfiles)
		}
		if snap.ActiveProfiles["qm-2002"] || snap.ActiveProfiles["qmv-2002"] {
			t.Fatalf("expected inactive profiles recorded false, got %+v", snap.ActiveProfiles)
		}

		runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
			// Fail right after qm-2002 is brought up during prune/later step.
			if name == "nmcli" && len(args) >= 4 && args[0] == "connection" && args[1] == "up" && args[2] == "qm-2002" {
				// Let qm-2002 activate via fakeRunner, or simulate post-up failure via pruning a stale record.
				return nil, nil
			}
			if name == "nmcli" && len(args) >= 3 && args[0] == "connection" && args[1] == "delete" && args[2] == "qm-stale" {
				return []byte("prune failed"), errors.New("exit status 1")
			}
			return nil, nil
		}
		ownedWithStale := append(slices.Clone(owned), state.ManagedNetworkRecord{
			ConnectionName: "qm-stale", Kind: "macvlan", Owned: true,
		})
		partialOwned, _, _, err := r.ApplyProfiles(ctx, host2, ownedWithStale, time.Second)
		if err == nil {
			t.Fatal("expected ApplyProfiles to fail on stale prune")
		}
		if !runner.active["qm-2002"] || !runner.active["qmv-2002"] {
			t.Fatalf("expected failed apply to have activated qm-2002 and qmv-2002")
		}

		runner.failHook = nil
		runner.calls = nil
		if err := r.Restore(ctx, snap, partialOwned); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}

		// Previously inactive qm-2002 and qmv-2002 must NEVER have `nmcli connection up` called on Restore,
		// and MUST have `nmcli connection down` called in deleteRank order (macvlan -> vrf -> vlan).
		var downOrder []string
		for _, c := range runner.calls {
			if c.name == "nmcli" && len(c.args) >= 3 && c.args[0] == "connection" && c.args[1] == "down" {
				downOrder = append(downOrder, c.args[2])
			}
		}
		if !slices.Equal(downOrder, []string{"qm-2002", "qmv-2002"}) {
			t.Fatalf("down order = %v, want [qm-2002 qmv-2002] (macvlan -> vrf); calls=%+v", downOrder, runner.calls)
		}
		for _, inactiveName := range []string{"qm-2002", "qmv-2002"} {
			if findCallIndex(runner.calls, "nmcli", "connection", "up", inactiveName) >= 0 {
				t.Fatalf("Restore must NOT call nmcli connection up on previously inactive %s", inactiveName)
			}
			if runner.active[inactiveName] {
				t.Fatalf("expected %s to be inactive after Restore", inactiveName)
			}
		}
		if gotMAC := strings.ToLower(runner.conns["qm-2002"].props["802-3-ethernet.cloned-mac-address"]); gotMAC != "02:51:4d:00:07:d2" {
			t.Fatalf("expected qm-2002 MAC restored to 02:51:4d:00:07:d2, got %q", gotMAC)
		}
		// Previously active profiles remain active.
		for _, activeName := range []string{"qm-vlan30", "qmv-2001", "qm-2001"} {
			if !runner.active[activeName] {
				t.Fatalf("expected previously active %s to remain active after Restore", activeName)
			}
		}
	})

	t.Run("Restore downs vlan/vrf/macvlan in deleteRank order, handles re-added autoconnect, and ignores not-active exit 10", func(t *testing.T) {
		runner := newFakeRunner()
		r := netmgr.NewReconciler("enp3s0", runner, newZeroL3mdevSysctl())

		host := &manifest.ResolvedHost{
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
		owned, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second)
		if err != nil {
			t.Fatalf("initial ApplyProfiles failed: %v", err)
		}

		// Mark all three profiles (vlan, vrf, macvlan) inactive before snapshot.
		delete(runner.active, "qm-2001")
		delete(runner.active, "qmv-2001")
		delete(runner.active, "qm-vlan30")

		snap, err := r.Snapshot(ctx, host, owned)
		if err != nil {
			t.Fatalf("Snapshot failed: %v", err)
		}

		// Simulate failed apply that activated qm-vlan30 and qmv-2001, and deleted qm-2001;
		// then during Restore, `nmcli connection add` for qm-2001 (autoconnect=yes) auto-activates it.
		delete(runner.conns, "qm-2001")
		runner.active["qm-vlan30"] = true
		runner.active["qmv-2001"] = true

		runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
			if name == "nmcli" && len(args) >= 4 && args[0] == "connection" && args[1] == "add" && args[3] == "macvlan" {
				// Simulate NM auto-activating newly re-added autoconnect=yes macvlan profile.
				runner.active["qm-2001"] = true
			}
			return nil, nil
		}

		runner.calls = nil
		if err := r.Restore(ctx, snap, owned); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}

		var downOrder []string
		for _, c := range runner.calls {
			if c.name == "nmcli" && len(c.args) >= 3 && c.args[0] == "connection" && c.args[1] == "down" {
				downOrder = append(downOrder, c.args[2])
			}
		}
		if !slices.Equal(downOrder, []string{"qm-2001", "qmv-2001", "qm-vlan30"}) {
			t.Fatalf("down order = %v, want [qm-2001 qmv-2001 qm-vlan30]", downOrder)
		}
		for _, name := range []string{"qm-2001", "qmv-2001", "qm-vlan30"} {
			if runner.active[name] {
				t.Fatalf("expected %s inactive after Restore", name)
			}
		}

		// Simulate `nmcli connection down` returning "not an active connection" (exit 10)
		// (for example, if listActiveConnectionNames fails or profile raced down right before `down`).
		runner.calls = nil
		runner.failHook = func(_ []byte, name string, args []string) ([]byte, error) {
			if name == "nmcli" && len(args) >= 3 && args[0] == "connection" && args[1] == "down" {
				return []byte("Error: Connection is not an active connection."), fmt.Errorf("exit status 10")
			}
			return nil, nil
		}
		if err := r.Restore(ctx, snap, owned); err != nil {
			t.Fatalf("expected Restore to treat not-an-active-connection (exit 10) on down as no-op, got: %v", err)
		}
		// Ensure `down` was actually invoked against the inactive snapshot (since all were inactive,
		// listActiveConnectionNames returns empty unless forced; force active or test with failHook on down).
		runner.active["qm-2001"] = true
		runner.calls = nil
		if err := r.Restore(ctx, snap, owned); err != nil {
			t.Fatalf("expected Restore to treat not-an-active-connection (exit 10) on down as no-op when invoked, got: %v", err)
		}
		if findCallIndex(runner.calls, "nmcli", "connection", "down", "qm-2001") < 0 {
			t.Fatalf("expected nmcli connection down qm-2001 to be invoked, calls=%+v", runner.calls)
		}
	})

	t.Run("del prio 0 table local preserves foreign custom prio 0 rule", func(t *testing.T) {
		runner := newFakeRunner()
		customRule := fakeIPRule{prio: 0, text: "from 192.0.2.0/24 lookup custom"}
		runner.rules = append([]fakeIPRule{customRule}, runner.rules...)

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
		if _, _, _, err := r.ApplyProfiles(ctx, host, nil, time.Second); err != nil {
			t.Fatalf("ApplyProfiles failed: %v", err)
		}
		if findCallIndex(runner.calls, "ip", "rule", "del", "prio", "0", "table", "local") < 0 {
			t.Fatalf("expected ip rule del prio 0 table local call, got %+v", runner.calls)
		}
		if !slices.Contains(runner.rules, customRule) {
			t.Fatalf("expected foreign custom prio 0 rule preserved, got %+v", runner.rules)
		}
		if slices.Contains(runner.rules, fakeIPRule{prio: 0, text: "from all lookup local"}) {
			t.Fatalf("expected prio 0 table local deleted, got %+v", runner.rules)
		}
	})
}
