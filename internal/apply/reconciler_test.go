package apply_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"quadmatic/internal/apply"
	"quadmatic/internal/config"
	"quadmatic/internal/gitops"
	"quadmatic/internal/manifest"
	"quadmatic/internal/netmgr"
	"quadmatic/internal/quadlet"
	"quadmatic/internal/secrets"
	"quadmatic/internal/state"
	"quadmatic/pkg/users"
)

// --- Fake test doubles ---

type fakeUsersReconciler struct {
	planCalls  int
	applyCalls int
	created    map[string]int
	active     []string
	failApply  error
}

func newFakeUsersReconciler() *fakeUsersReconciler {
	return &fakeUsersReconciler{
		created: make(map[string]int),
	}
}

func (f *fakeUsersReconciler) scopeForUID(uid int) string {
	for u, id := range f.created {
		if id == uid {
			return u
		}
	}
	return ""
}

func (f *fakeUsersReconciler) Plan(_ context.Context, reg *users.Registry, activeUsers []string, _ []string) (*users.Plan, error) {
	f.planCalls++
	plan := &users.Plan{}
	for _, u := range activeUsers {
		spec, ok := reg.Users[u]
		if !ok {
			return nil, fmt.Errorf("user %q not in registry", u)
		}
		if _, exists := f.created[u]; !exists {
			plan.Actions = append(plan.Actions, users.Action{
				Kind: users.CreateUser,
				User: u,
				UID:  spec.UID,
			})
		} else {
			plan.Actions = append(plan.Actions, users.Action{
				Kind: users.AdoptUser,
				User: u,
				UID:  spec.UID,
			})
		}
	}
	return plan, nil
}

func (f *fakeUsersReconciler) Apply(ctx context.Context, reg *users.Registry, activeUsers []string, prev []string) (*users.Plan, error) {
	f.applyCalls++
	plan, err := f.Plan(ctx, reg, activeUsers, prev)
	if err != nil {
		return nil, err
	}
	if f.failApply != nil {
		return plan, f.failApply
	}
	f.active = slices.Clone(activeUsers)
	for _, act := range plan.Actions {
		if act.Kind == users.CreateUser {
			f.created[act.User] = act.UID
		}
	}
	return plan, nil
}

type fakeQuadletRunner struct {
	calls int
}

func (f *fakeQuadletRunner) RunEnv(_ context.Context, env []string, _ string, _ ...string) ([]byte, []byte, error) {
	f.calls++
	var stageDir string
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "QUADLET_UNIT_DIRS="); ok {
			stageDir = v
			break
		}
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return nil, []byte(err.Error()), err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)

	var out strings.Builder
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(stageDir, name))
		if err != nil {
			return nil, []byte(err.Error()), err
		}
		unitName := quadletFileToUnitName(name)
		fmt.Fprintf(&out, "---%s---\n[Unit]\nSourcePath=%s/%s\n\n%s\n", unitName, stageDir, name, strings.TrimSpace(string(raw)))
	}
	return []byte(out.String()), nil, nil
}

func quadletFileToUnitName(name string) string {
	switch {
	case strings.HasSuffix(name, ".volume"):
		return strings.TrimSuffix(name, ".volume") + "-volume.service"
	case strings.HasSuffix(name, ".network"):
		return strings.TrimSuffix(name, ".network") + "-network.service"
	case strings.HasSuffix(name, ".pod"):
		return strings.TrimSuffix(name, ".pod") + "-pod.service"
	case strings.HasSuffix(name, ".image"):
		return strings.TrimSuffix(name, ".image") + "-image.service"
	case strings.HasSuffix(name, ".kube"):
		return strings.TrimSuffix(name, ".kube") + ".service"
	case strings.HasSuffix(name, ".build"):
		return strings.TrimSuffix(name, ".build") + "-build.service"
	default:
		return strings.TrimSuffix(name, ".container") + ".service"
	}
}

type fakeSecretRunner struct {
	store map[string]string // "<scope>/<name>" -> plaintext
	calls []string
}

func newFakeSecretRunner() *fakeSecretRunner {
	return &fakeSecretRunner{
		store: make(map[string]string),
	}
}

func (f *fakeSecretRunner) RunWithStdin(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	scope := "rootful"
	podmanArgs := args
	if name == "systemd-run" {
		for _, a := range args {
			if m, ok := strings.CutPrefix(a, "--machine="); ok {
				scope = strings.TrimSuffix(m, "@.host")
			}
		}
		idx := slices.Index(args, "podman")
		if idx >= 0 {
			podmanArgs = args[idx+1:]
		}
	}
	if len(podmanArgs) >= 4 && podmanArgs[0] == "secret" && podmanArgs[1] == "create" {
		secName := podmanArgs[len(podmanArgs)-2]
		key := scope + "/" + secName
		f.store[key] = string(stdin)
		f.calls = append(f.calls, "upsert:"+key)
		return nil, nil
	}
	if len(podmanArgs) >= 3 && podmanArgs[0] == "secret" && podmanArgs[1] == "rm" {
		secName := podmanArgs[len(podmanArgs)-1]
		key := scope + "/" + secName
		delete(f.store, key)
		f.calls = append(f.calls, "remove:"+key)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected secret command: %s %v", name, args)
}

type systemdCall struct {
	op    string
	scope string
	unit  string
}

type fakeSystemd struct {
	calls               []systemdCall
	states              map[string]string               // "<scope>/<unit>" -> state
	types               map[string]string               // "<scope>/<unit>" -> systemd Type=
	results             map[string]string               // "<scope>/<unit>" -> systemd Result=
	overrideActiveState map[string]string               // overrides ActiveState return without clearing
	overrideUnitState   map[string]apply.UnitStatusInfo // overrides full UnitState return
}

func newFakeSystemd() *fakeSystemd {
	return &fakeSystemd{
		states:              make(map[string]string),
		types:               make(map[string]string),
		results:             make(map[string]string),
		overrideActiveState: make(map[string]string),
		overrideUnitState:   make(map[string]apply.UnitStatusInfo),
	}
}

func (f *fakeSystemd) clearCalls() {
	f.calls = nil
}

func (f *fakeSystemd) countCalls(op, scope, unit string) int {
	n := 0
	for _, c := range f.calls {
		if c.op == op && c.scope == scope && c.unit == unit {
			n++
		}
	}
	return n
}

func (f *fakeSystemd) DaemonReload(_ context.Context, scope string) error {
	f.calls = append(f.calls, systemdCall{op: "daemon-reload", scope: scope})
	return nil
}

func (f *fakeSystemd) Start(_ context.Context, scope, unit string) error {
	f.calls = append(f.calls, systemdCall{op: "start", scope: scope, unit: unit})
	f.states[scope+"/"+unit] = "active"
	return nil
}

func (f *fakeSystemd) Stop(_ context.Context, scope, unit string) error {
	f.calls = append(f.calls, systemdCall{op: "stop", scope: scope, unit: unit})
	f.states[scope+"/"+unit] = "inactive"
	return nil
}

func (f *fakeSystemd) Restart(_ context.Context, scope, unit string) error {
	f.calls = append(f.calls, systemdCall{op: "restart", scope: scope, unit: unit})
	f.states[scope+"/"+unit] = "active"
	return nil
}

func (f *fakeSystemd) UnitState(_ context.Context, scope, unit string) (apply.UnitStatusInfo, error) {
	f.calls = append(f.calls, systemdCall{op: "unit-state", scope: scope, unit: unit})
	key := scope + "/" + unit
	if ov, ok := f.overrideUnitState[key]; ok {
		return ov, nil
	}
	st := "inactive"
	if ov, ok := f.overrideActiveState[key]; ok {
		st = ov
	} else if s, ok := f.states[key]; ok {
		st = s
	}
	typ := f.types[key]
	if typ == "" {
		typ = "simple"
	}
	res := f.results[key]
	if res == "" && st == "active" {
		res = "success"
	}
	return apply.UnitStatusInfo{
		ActiveState: st,
		Type:        typ,
		Result:      res,
	}, nil
}

// Stateful fake netmgr.Runner & SysctlReader (mirrored from internal/netmgr/netmgr_test.go)

type fakeSysctl struct {
	values map[string]string
}

func newZeroSysctl() *fakeSysctl {
	return &fakeSysctl{
		values: map[string]string{
			"/proc/sys/net/ipv4/tcp_l3mdev_accept": "0\n",
			"/proc/sys/net/ipv4/udp_l3mdev_accept": "0\n",
		},
	}
}

func (s *fakeSysctl) ReadSysctl(path string) (string, error) {
	if v, ok := s.values[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("missing sysctl %q", path)
}

type fakeNMConn struct {
	props map[string]string
}

type fakeIPRule struct {
	prio int
	text string
}

type fakeNetRunner struct {
	calls      []string
	conns      map[string]*fakeNMConn
	active     map[string]bool
	dnsByIface map[string]string
	routes     map[int][]string
	routes6    map[int][]string
	rules      []fakeIPRule
	rules6     []fakeIPRule
}

func newFakeNetRunner() *fakeNetRunner {
	return &fakeNetRunner{
		conns:      make(map[string]*fakeNMConn),
		active:     make(map[string]bool),
		dnsByIface: make(map[string]string),
		routes:     make(map[int][]string),
		routes6:    make(map[int][]string),
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

func (f *fakeNetRunner) clearCalls() {
	f.calls = nil
}

func (f *fakeNetRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "nmcli":
		return f.handleNMCLI(args)
	case "ip":
		return f.handleIP(args)
	default:
		return nil, fmt.Errorf("unexpected net command %q", name)
	}
}

func (f *fakeNetRunner) handleNMCLI(args []string) ([]byte, error) {
	var terse bool
	var fields, getVal string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-t":
			terse = true
			i++
		case "-f":
			fields = args[i+1]
			i += 2
		case "-g":
			getVal = args[i+1]
			i += 2
		default:
			goto doneFlags
		}
	}
doneFlags:
	rest := args[i:]
	switch rest[0] {
	case "device":
		if len(rest) == 1 && terse && fields == "DEVICE,TYPE,CONNECTION" {
			var lines []string
			for name, c := range f.conns {
				if f.active[name] {
					lines = append(lines, fmt.Sprintf("%s:%s:%s", c.props["connection.interface-name"], c.props["connection.type"], name))
				}
			}
			return []byte(strings.Join(lines, "\n")), nil
		}
		if len(rest) >= 3 && rest[1] == "show" && getVal == "IP4.DNS" {
			ifname := rest[2]
			dns, ok := f.dnsByIface[ifname]
			if !ok {
				if _, exists := f.conns[ifname]; !exists {
					return []byte("Error: Device not found"), errors.New("exit status 10")
				}
				return []byte(""), nil
			}
			return []byte(dns), nil
		}
	case "connection":
		switch rest[1] {
		case "show":
			if len(rest) == 2 && terse && fields == "NAME" {
				var names []string
				for n := range f.conns {
					names = append(names, n)
				}
				slices.Sort(names)
				return []byte(strings.Join(names, "\n")), nil
			}
			if len(rest) == 3 && rest[2] == "--active" && terse && fields == "NAME" {
				var names []string
				for n, up := range f.active {
					if up {
						names = append(names, n)
					}
				}
				slices.Sort(names)
				return []byte(strings.Join(names, "\n")), nil
			}
			if len(rest) >= 3 {
				id := rest[len(rest)-1]
				if getVal == "vlan.parent,vlan.id" {
					if c, ok := f.conns[id]; ok {
						return []byte(fmt.Sprintf("%s\n%s\n", c.props["vlan.parent"], c.props["vlan.id"])), nil
					}
					return []byte("Error: no such connection profile"), errors.New("exit status 10")
				}
				c, ok := f.conns[id]
				if !ok {
					return []byte("Error: no such connection profile"), errors.New("exit status 10")
				}
				var lines []string
				for k, v := range c.props {
					lines = append(lines, fmt.Sprintf("%s:%s", k, strings.ReplaceAll(v, ":", `\:`)))
				}
				slices.Sort(lines)
				return []byte(strings.Join(lines, "\n")), nil
			}
		case "add":
			props := parseNMCLIAdd(rest[2:])
			conName := props["connection.id"]
			f.conns[conName] = &fakeNMConn{props: props}
			return nil, nil
		case "modify":
			conName := rest[2]
			c, ok := f.conns[conName]
			if !ok {
				return []byte("Error: no such connection profile"), errors.New("exit status 10")
			}
			for j := 3; j+1 < len(rest); j += 2 {
				k, v := rest[j], rest[j+1]
				switch k {
				case "ethernet.cloned-mac-address":
					k = "802-3-ethernet.cloned-mac-address"
				case "connection.master":
					k = "connection.controller"
				}
				c.props[k] = v
			}
			return nil, nil
		case "up":
			conName := rest[2]
			c, ok := f.conns[conName]
			if !ok {
				return []byte("Error: no such connection profile"), errors.New("exit status 10")
			}
			f.active[conName] = true
			if c.props["connection.type"] == "vrf" {
				f.ensureFakeL3mdevRule(false)
				f.ensureFakeL3mdevRule(true)
			}
			return nil, nil
		case "down":
			conName := rest[2]
			if _, ok := f.conns[conName]; !ok {
				return []byte("Error: no such connection profile"), errors.New("exit status 10")
			}
			delete(f.active, conName)
			return nil, nil
		case "delete":
			conName := rest[2]
			if _, ok := f.conns[conName]; !ok {
				return []byte("Error: no such connection profile"), errors.New("exit status 10")
			}
			delete(f.conns, conName)
			delete(f.active, conName)
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unsupported nmcli: %v", args)
}

func (f *fakeNetRunner) ensureFakeL3mdevRule(isV6 bool) {
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

func parseNMCLIAdd(args []string) map[string]string {
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
			if props["connection.type"] == "vlan" {
				props["vlan.parent"] = v
			} else {
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

func (f *fakeNetRunner) handleIP(args []string) ([]byte, error) {
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
			tbl, route := extractTable(args[2:])
			routeStore[tbl] = []string{route}
			return nil, nil
		case "del":
			tbl, _ := extractTable(args[2:])
			delete(routeStore, tbl)
			return nil, nil
		case "show":
			tbl := 0
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "table" {
					tbl, _ = strconv.Atoi(args[i+1])
				}
			}
			return []byte(strings.Join(routeStore[tbl], "\n")), nil
		}
	}
	return nil, fmt.Errorf("unsupported ip command: %v", args)
}

func (f *fakeNetRunner) handleIPRule(isV6 bool, args []string) ([]byte, error) {
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

func extractTable(args []string) (int, string) {
	var parts []string
	tbl := 0
	for i := 0; i < len(args); i++ {
		if args[i] == "table" && i+1 < len(args) {
			tbl, _ = strconv.Atoi(args[i+1])
			i++
			continue
		}
		parts = append(parts, args[i])
	}
	return tbl, strings.Join(parts, " ")
}

type spyGitClient struct {
	*gitops.Client
	readAtCommitCalls []string
}

func (s *spyGitClient) ReadFileAtCommit(ctx context.Context, sha, relPath string) ([]byte, error) {
	s.readAtCommitCalls = append(s.readAtCommitCalls, sha+":"+relPath)
	return s.Client.ReadFileAtCommit(ctx, sha, relPath)
}

// --- Test Harness & Git/Age helpers ---

type testEnv struct {
	t           *testing.T
	rootDir     string
	repoDir     string
	stateFile   string
	ageKeyPath  string
	ageIdentity *age.X25519Identity
	cfg         *config.HostConfig
	git         *spyGitClient
	users       *fakeUsersReconciler
	quadlet     *quadlet.Validator
	qRunner     *fakeQuadletRunner
	secretsMgr  *secrets.Manager
	secRunner   *fakeSecretRunner
	netmgr      *netmgr.Reconciler
	netRunner   *fakeNetRunner
	systemd     *fakeSystemd
	engine      *apply.Engine
	chownCalls  []string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	base := t.TempDir()
	rootDir := filepath.Join(base, "rootfs")
	repoDir := filepath.Join(base, "repo")
	stateFile := filepath.Join(base, "state", "state.json")
	ageKeyPath := filepath.Join(base, "age.key")

	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepo(t, repoDir)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	if err := os.WriteFile(ageKeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.HostConfig{
		Hostname:       "services-02",
		RepoURL:        "git@example.lan:homelab/quadlets.git",
		Branch:         "main",
		PollInterval:   5 * time.Minute,
		SSHKey:         filepath.Join(base, "deploy_key"),
		SSHKnownHosts:  filepath.Join(base, "known_hosts"),
		AllowedSigners: filepath.Join(base, "allowed_signers"),
		AgeIdentity:    ageKeyPath,
		TrunkInterface: "enp3s0",
		StateFile:      stateFile,
		RepoDir:        filepath.Join(base, "bare"),
	}

	qRunner := &fakeQuadletRunner{}
	secRunner := newFakeSecretRunner()
	netRunner := newFakeNetRunner()
	usersRec := newFakeUsersReconciler()
	sysd := newFakeSystemd()
	gitClient := &spyGitClient{Client: gitops.NewLocalClient(repoDir, cfg)}

	netRec := netmgr.NewReconciler("enp3s0", netRunner, newZeroSysctl())

	env := &testEnv{
		t:           t,
		rootDir:     rootDir,
		repoDir:     repoDir,
		stateFile:   stateFile,
		ageKeyPath:  ageKeyPath,
		ageIdentity: id,
		cfg:         cfg,
		git:         gitClient,
		users:       usersRec,
		quadlet:     quadlet.NewValidator("/fake/quadlet", qRunner),
		qRunner:     qRunner,
		secretsMgr:  secrets.NewManager(secRunner),
		secRunner:   secRunner,
		netmgr:      netRec,
		netRunner:   netRunner,
		systemd:     sysd,
	}

	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:  cfg,
		Git:     gitClient,
		Users:   usersRec,
		Quadlet: env.quadlet,
		Secrets: env.secretsMgr,
		Netmgr:  env.netmgr,
		Systemd: sysd,
		RootDir: rootDir,
		Chown: func(path string, uid, gid int) error {
			env.chownCalls = append(env.chownCalls, fmt.Sprintf("%s:%d:%d", path, uid, gid))
			return nil
		},
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})
	return env
}

func (e *testEnv) hostPath(dest string) string {
	return filepath.Join(e.rootDir, filepath.FromSlash(strings.TrimPrefix(dest, "/")))
}

func (e *testEnv) encryptSecret(plaintext string) []byte {
	e.t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, e.ageIdentity.Recipient())
	if err != nil {
		e.t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		e.t.Fatalf("age write: %v", err)
	}
	if err := w.Close(); err != nil {
		e.t.Fatalf("age close: %v", err)
	}
	return buf.Bytes()
}

func (e *testEnv) writeRepoFiles(files map[string][]byte) {
	e.t.Helper()
	for rel, content := range files {
		p := filepath.Join(e.repoDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			e.t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *testEnv) commitRepo(msg string) string {
	e.t.Helper()
	runGitCmd(e.t, e.repoDir, "add", "-A")
	runGitCmd(e.t, e.repoDir, "commit", "-m", msg)
	out := runGitCmd(e.t, e.repoDir, "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGitCmd(t, dir, "init", "-b", "main")
	runGitCmd(t, dir, "config", "user.name", "Test Author")
	runGitCmd(t, dir, "config", "user.email", "test@example.lan")
}

func runGitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return string(out)
}

func (e *testEnv) reconcileOpts(timeout time.Duration) apply.ReconcileOptions {
	return apply.ReconcileOptions{
		LocalRepoPath:      e.repoDir,
		NoVerify:           true,
		StartVerifyTimeout: timeout,
	}
}

// --- Required Tests ---

func TestReconcileDryRunMakesZeroMutations(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns_from_dhcp = true
tcp_ports = ["8080:8080"]
`),
		"components/open-webui/component.toml": []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container.tmpl": []byte(`[Container]
Image=ghcr.io/open-webui/open-webui:main
Network={{ .Net.PastaArgs }}
{{- range .Net.DNS }}
DNS={{ . }}
{{- end }}
Secret=webui_secret,type=env,target=WEBUI_SECRET_KEY
`),
		"components/open-webui/files/config.yaml": []byte("theme: dark\n"),
		"secrets/open-webui.age":                  env.encryptSecret("dryrun-secret-value"),
	})
	env.commitRepo("initial commit")

	opts := env.reconcileOpts(50 * time.Millisecond)
	opts.DryRun = true

	res, err := env.engine.Reconcile(context.Background(), opts)
	if err != nil {
		t.Fatalf("DryRun Reconcile failed: %v", err)
	}
	if res.PlanSummary == "" {
		t.Fatalf("expected non-empty PlanSummary")
	}
	for _, want := range []string{
		"open-webui",
		"write /etc/containers/systemd/users/2001/open-webui.container",
		"write /var/home/openwebui/.config/quadmatic/open-webui/config.yaml",
		"upsert openwebui/webui_secret",
		"start openwebui/open-webui.service",
	} {
		if !strings.Contains(res.PlanSummary, want) {
			t.Fatalf("expected PlanSummary to contain %q, got:\n%s", want, res.PlanSummary)
		}
	}
	if res.ManagedUnitsRootless != 1 || res.ManagedUnitsRootful != 0 {
		t.Fatalf("unexpected managed unit counts: rootless=%d rootful=%d", res.ManagedUnitsRootless, res.ManagedUnitsRootful)
	}

	// Zero files written to rootDir or state.json
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")); !os.IsNotExist(err) {
		t.Fatalf("DryRun unexpectedly wrote quadlet file")
	}
	if _, err := os.Stat(env.hostPath("/var/home/openwebui/.config/quadmatic/open-webui/config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("DryRun unexpectedly wrote data file")
	}
	if _, err := os.Stat(env.stateFile); !os.IsNotExist(err) {
		t.Fatalf("DryRun unexpectedly wrote state.json")
	}
	if env.users.applyCalls != 0 {
		t.Fatalf("DryRun unexpectedly called users.Apply (%d times)", env.users.applyCalls)
	}
	if len(env.secRunner.calls) != 0 {
		t.Fatalf("DryRun unexpectedly mutated secrets: %v", env.secRunner.calls)
	}
	if len(env.systemd.calls) != 0 {
		t.Fatalf("DryRun unexpectedly called systemd: %v", env.systemd.calls)
	}
	if len(env.netRunner.conns) != 0 {
		t.Fatalf("DryRun unexpectedly mutated network: conns=%v", env.netRunner.conns)
	}
	for _, c := range env.netRunner.calls {
		if strings.HasPrefix(c, "ip rule add") || strings.HasPrefix(c, "ip rule del") || strings.HasPrefix(c, "ip -6 rule add") || strings.HasPrefix(c, "ip -6 rule del") {
			t.Fatalf("DryRun unexpectedly mutated ip rules: %v", env.netRunner.calls)
		}
	}
}

func TestReconcileMinimalDisruptionAndSecretRotation(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`),
		"components/open-webui/component.toml": []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container": []byte(`[Container]
Image=ghcr.io/open-webui/open-webui:main
Secret=webui_secret,type=env,target=WEBUI_SECRET_KEY
`),
		"components/caddy/component.toml": []byte("[secrets]\ncaddy_token = \"secrets/caddy.age\"\n"),
		"components/caddy/caddy.container": []byte(`[Container]
Image=docker.io/library/caddy:2
Secret=caddy_token,type=env,target=CADDY_TOKEN
`),
		"secrets/open-webui.age": env.encryptSecret("webui-v1"),
		"secrets/caddy.age":      env.encryptSecret("caddy-v1"),
	})
	sha1 := env.commitRepo("commit 1: two components")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("Reconcile 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}
	if res1.ManagedUnitsRootless != 2 || res1.ManagedUnitsRootful != 0 {
		t.Fatalf("unexpected counts: %+v", res1)
	}
	if env.systemd.countCalls("daemon-reload", "openwebui", "") != 1 || env.systemd.countCalls("daemon-reload", "caddy", "") != 1 {
		t.Fatalf("expected daemon-reload on both user scopes, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("start", "openwebui", "open-webui.service") != 1 || env.systemd.countCalls("start", "caddy", "caddy.service") != 1 {
		t.Fatalf("expected both services started, calls=%v", env.systemd.calls)
	}
	if env.secRunner.store["openwebui/webui_secret"] != "webui-v1" || env.secRunner.store["caddy/caddy_token"] != "caddy-v1" {
		t.Fatalf("unexpected secret store after commit 1: %v", env.secRunner.store)
	}

	st1, err := state.Load(env.stateFile)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if st1.AppliedSHA != sha1 {
		t.Fatalf("state.json AppliedSHA = %q, want %q", st1.AppliedSHA, sha1)
	}

	// Commit 2: rotate ONLY open-webui's secret
	env.systemd.clearCalls()
	env.secRunner.calls = nil
	env.writeRepoFiles(map[string][]byte{
		"secrets/open-webui.age": env.encryptSecret("webui-v2"),
	})
	sha2 := env.commitRepo("commit 2: rotate open-webui secret")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("Reconcile 2 failed: %v", err)
	}
	if res2.AppliedSHA != sha2 {
		t.Fatalf("AppliedSHA = %q, want %q", res2.AppliedSHA, sha2)
	}
	if env.secRunner.store["openwebui/webui_secret"] != "webui-v2" {
		t.Fatalf("expected rotated secret webui-v2, got %q", env.secRunner.store["openwebui/webui_secret"])
	}
	if !reflect.DeepEqual(env.secRunner.calls, []string{"upsert:openwebui/webui_secret"}) {
		t.Fatalf("expected ONLY openwebui/webui_secret upsert, got %v", env.secRunner.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected open-webui.service restarted once, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "caddy", "caddy.service") != 0 || env.systemd.countCalls("start", "caddy", "caddy.service") != 0 {
		t.Fatalf("caddy.service must remain untouched on open-webui secret rotation, calls=%v", env.systemd.calls)
	}
}

func TestReconcileAutoHealsDriftWithoutRestartingManuallyStoppedUnit(t *testing.T) {
	env := newTestEnv(t)

	desiredQuadlet := "[Container]\nImage=ghcr.io/open-webui/open-webui:main\n"
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`),
		"components/open-webui/open-webui.container": []byte(desiredQuadlet),
		"components/caddy/caddy.container":           []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
	})
	env.commitRepo("commit 1")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	// (a) Modify open-webui quadlet on disk out-of-band; (b) manually stop caddy.service ("inactive")
	quadletPath := env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")
	if err := os.WriteFile(quadletPath, []byte("[Container]\nImage=tampered:latest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.systemd.states["caddy/caddy.service"] = "inactive"
	env.systemd.clearCalls()

	res, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("drift heal reconcile failed: %v", err)
	}
	if !res.DriftDetected {
		t.Fatalf("expected DriftDetected = true")
	}
	gotContent, err := os.ReadFile(quadletPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotContent) != desiredQuadlet {
		t.Fatalf("expected drifted quadlet overwritten back to %q, got %q", desiredQuadlet, string(gotContent))
	}
	if env.systemd.countCalls("daemon-reload", "openwebui", "") != 1 {
		t.Fatalf("expected daemon-reload for openwebui, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected restart for open-webui.service, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("start", "caddy", "caddy.service") != 0 ||
		env.systemd.countCalls("restart", "caddy", "caddy.service") != 0 ||
		env.systemd.countCalls("daemon-reload", "caddy", "") != 0 {
		t.Fatalf("manually stopped caddy.service must not be started/restarted/reloaded, calls=%v", env.systemd.calls)
	}
	wantFailed := []apply.UnitStatus{{Scope: "caddy", Unit: "caddy.service", ActiveState: "inactive"}}
	if !reflect.DeepEqual(res.FailedUnits, wantFailed) {
		t.Fatalf("FailedUnits = %+v, want %+v", res.FailedUnits, wantFailed)
	}

	// Now verify unchanged tick with a "failed" unit (no file drift) reports FailedUnits without restarting it.
	env.systemd.states["caddy/caddy.service"] = "failed"
	env.systemd.clearCalls()

	resNoDrift, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("unchanged reconcile with failed unit returned error: %v", err)
	}
	if resNoDrift.DriftDetected {
		t.Fatalf("expected DriftDetected = false when no files/net drifted")
	}
	if env.systemd.countCalls("start", "caddy", "caddy.service") != 0 || env.systemd.countCalls("restart", "caddy", "caddy.service") != 0 {
		t.Fatalf("failed unchanged unit must not be started/restarted, calls=%v", env.systemd.calls)
	}
	wantFailed2 := []apply.UnitStatus{{Scope: "caddy", Unit: "caddy.service", ActiveState: "failed"}}
	if !reflect.DeepEqual(resNoDrift.FailedUnits, wantFailed2) {
		t.Fatalf("FailedUnits = %+v, want %+v", resNoDrift.FailedUnits, wantFailed2)
	}
}

func TestReconcileTransactionalRollbackToPriorCommit(t *testing.T) {
	env := newTestEnv(t)

	quadletV1 := "[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.brokenuser]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]
`),
		"components/open-webui/component.toml":            []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container.tmpl": []byte(quadletV1),
		"components/open-webui/files/config.yaml":         []byte("version: v1\n"),
		"secrets/open-webui.age":                          env.encryptSecret("secret-v1"),
	})
	sha1 := env.commitRepo("commit 1: healthy")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 reconcile failed: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}
	hasRule32765 := false
	hasRule0 := false
	for _, r := range env.netRunner.rules {
		if r.prio == 32765 && r.text == "from all lookup local" {
			hasRule32765 = true
		}
		if r.prio == 0 && r.text == "from all lookup local" {
			hasRule0 = true
		}
	}
	if !hasRule32765 || hasRule0 {
		t.Fatalf("expected l3mdev-before-local rule ordering (32765 present, 0 absent), got %+v", env.netRunner.rules)
	}

	// Commit 2: updates open-webui files, NM MAC/VLAN, secret v2, AND adds broken component that fails start verify
	env.systemd.overrideActiveState["brokenuser/broken.service"] = "failed"
	env.systemd.clearCalls()
	env.secRunner.calls = nil
	env.git.readAtCommitCalls = nil

	quadletV2 := "[Container]\nImage=ghcr.io/open-webui/open-webui:v2\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 31
mac = "02:51:4d:00:07:d2"
dns = ["10.31.0.1"]
tcp_ports = ["8080:8080"]

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/open-webui/open-webui.container.tmpl": []byte(quadletV2),
		"components/open-webui/files/config.yaml":         []byte("version: v2\n"),
		"secrets/open-webui.age":                          env.encryptSecret("secret-v2"),
		"components/broken/broken.container":              []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 2: broken update")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 2 reconcile to fail and roll back")
	}
	if !res2.RolledBack {
		t.Fatalf("expected RolledBack = true, got %+v", res2)
	}
	if res2.FailedStage != "apply" {
		t.Fatalf("FailedStage = %q, want %q", res2.FailedStage, "apply")
	}
	if res2.AppliedSHA != sha1 {
		t.Fatalf("Result.AppliedSHA = %q, want %q", res2.AppliedSHA, sha1)
	}

	// Verify newly added unit was stopped
	if env.systemd.countCalls("stop", "brokenuser", "broken.service") != 1 {
		t.Fatalf("expected broken.service stopped on rollback, calls=%v", env.systemd.calls)
	}

	// Verify restored Commit 1 files & removed Commit 2 files
	cfgBytes, err := os.ReadFile(env.hostPath("/var/home/openwebui/.config/quadmatic/open-webui/config.yaml"))
	if err != nil || string(cfgBytes) != "version: v1\n" {
		t.Fatalf("expected config.yaml restored to v1, got %q (err=%v)", string(cfgBytes), err)
	}
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/users/2002/broken.container")); !os.IsNotExist(err) {
		t.Fatalf("expected newly created broken.container removed on rollback, stat err=%v", err)
	}

	// Verify NM profiles restored to Commit 1
	if _, ok := env.netRunner.conns["qm-vlan31"]; ok {
		t.Fatalf("expected commit 2 qm-vlan31 deleted on rollback")
	}
	if _, ok := env.netRunner.conns["qm-vlan30"]; !ok {
		t.Fatalf("expected commit 1 qm-vlan30 restored on rollback")
	}
	if mac := env.netRunner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]; mac != "02:51:4d:00:07:d1" {
		t.Fatalf("expected qm-2001 MAC restored to 02:51:4d:00:07:d1, got %q", mac)
	}

	// Verify secret v1 was re-decrypted via gitops.ReadFileAtCommit and restored via secrets.Upsert
	if env.secRunner.store["openwebui/webui_secret"] != "secret-v1" {
		t.Fatalf("expected secret restored to secret-v1, got %q", env.secRunner.store["openwebui/webui_secret"])
	}
	foundReadAtCommit := false
	for _, c := range env.git.readAtCommitCalls {
		if c == sha1+":secrets/open-webui.age" {
			foundReadAtCommit = true
			break
		}
	}
	if !foundReadAtCommit {
		t.Fatalf("expected ReadFileAtCommit(%q, %q), got calls: %v", sha1, "secrets/open-webui.age", env.git.readAtCommitCalls)
	}

	// Verify daemon-reload ran and restored open-webui.service was restarted
	if env.systemd.countCalls("daemon-reload", "openwebui", "") < 2 {
		t.Fatalf("expected daemon-reload on openwebui during rollback, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") < 2 {
		t.Fatalf("expected open-webui.service restarted during rollback (once in forward, once in rollback), calls=%v", env.systemd.calls)
	}

	// Verify state.json kept at Commit 1 SHA
	stAfter, err := state.Load(env.stateFile)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if stAfter.AppliedSHA != sha1 {
		t.Fatalf("state.json AppliedSHA = %q, want %q", stAfter.AppliedSHA, sha1)
	}
}

func TestReconcileBootstrapRollbackWithEmptyAppliedSHA(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]
`),
		"components/open-webui/component.toml":            []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:main\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"components/open-webui/files/config.yaml":         []byte("bootstrap: true\n"),
		"secrets/open-webui.age":                          env.encryptSecret("bootstrap-secret"),
	})
	env.commitRepo("bootstrap commit")

	// Unit fails to start on clean host (AppliedSHA == "")
	env.systemd.overrideActiveState["openwebui/open-webui.service"] = "failed"

	res, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil {
		t.Fatalf("expected bootstrap reconcile to fail when unit fails to start")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack = true, got %+v", res)
	}
	if res.AppliedSHA != "" {
		t.Fatalf("expected AppliedSHA = \"\", got %q", res.AppliedSHA)
	}

	// Must never call ReadFileAtCommit with empty AppliedSHA
	if len(env.git.readAtCommitCalls) != 0 {
		t.Fatalf("bootstrap rollback must never call ReadFileAtCommit, got %v", env.git.readAtCommitCalls)
	}

	// Newly created files removed
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")); !os.IsNotExist(err) {
		t.Fatalf("expected newly created quadlet removed on bootstrap rollback")
	}
	if _, err := os.Stat(env.hostPath("/var/home/openwebui/.config/quadmatic/open-webui/config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected newly created data file removed on bootstrap rollback")
	}

	// Newly created secret removed
	if len(env.secRunner.store) != 0 {
		t.Fatalf("expected all newly created secrets removed on bootstrap rollback, got %v", env.secRunner.store)
	}

	// Newly created qm-* NM profiles removed
	if len(env.netRunner.conns) != 0 {
		t.Fatalf("expected all newly created NM profiles removed on bootstrap rollback, got %v", env.netRunner.conns)
	}

	// state.json remains empty / unset (AppliedSHA == "")
	stAfter, err := state.Load(env.stateFile)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if stAfter.AppliedSHA != "" {
		t.Fatalf("expected state.json AppliedSHA == \"\", got %q", stAfter.AppliedSHA)
	}

	// User created in Stage 5 must NEVER be deleted
	if env.users.created["openwebui"] != 2001 {
		t.Fatalf("expected created user openwebui (uid 2001) preserved, got %v", env.users.created)
	}
}

func TestReconcileLiveDHCPDNSChangeRerendersAndRestarts(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

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
`),
		"components/open-webui/open-webui.container.tmpl": []byte(`[Container]
Image=ghcr.io/open-webui/open-webui:main
Network={{ .Net.PastaArgs }}
{{- range .Net.DNS }}
DNS={{ . }}
{{- end }}
`),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
	})
	env.commitRepo("commit 1: dhcp dns")

	// Initial DHCP DNS lease
	env.netRunner.dnsByIface["qm-2001"] = "10.30.0.1\n"

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	quadletPath := env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")
	got1, err := os.ReadFile(quadletPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got1), "DNS=10.30.0.1") {
		t.Fatalf("expected initial DNS=10.30.0.1 in quadlet, got:\n%s", string(got1))
	}

	// Next tick on unchanged SHA: DHCP server returns a new DNS IP
	env.netRunner.dnsByIface["qm-2001"] = "10.30.0.53\n"
	env.systemd.clearCalls()
	env.qRunner.calls = 0

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("DNS change reconcile failed: %v", err)
	}
	if res2.DriftDetected {
		t.Fatalf("expected DriftDetected = false on clean live DHCP DNS change")
	}
	if env.qRunner.calls == 0 {
		t.Fatalf("expected quadlet --dryrun validation after DHCP DNS re-render")
	}
	got2, err := os.ReadFile(quadletPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got2), "DNS=10.30.0.53") {
		t.Fatalf("expected updated DNS=10.30.0.53 in quadlet, got:\n%s", string(got2))
	}
	if env.systemd.countCalls("daemon-reload", "openwebui", "") != 1 {
		t.Fatalf("expected daemon-reload for openwebui, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected open-webui.service restarted, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "caddy", "caddy.service") != 0 ||
		env.systemd.countCalls("start", "caddy", "caddy.service") != 0 ||
		env.systemd.countCalls("daemon-reload", "caddy", "") != 0 {
		t.Fatalf("caddy must not be restarted or reloaded on open-webui DHCP DNS change, calls=%v", env.systemd.calls)
	}
}

type fakeSystemctlRunner struct {
	calls []string
	out   []byte
	err   error
}

func (f *fakeSystemctlRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.out, f.err
}

func TestSystemctlCommandsAndValidation(t *testing.T) {
	runner := &fakeSystemctlRunner{out: []byte("ActiveState=active\nType=simple\nResult=success\n")}
	sys := apply.NewSystemctl(runner)
	ctx := context.Background()
	wantInfo := apply.UnitStatusInfo{ActiveState: "active", Type: "simple", Result: "success"}

	if err := sys.DaemonReload(ctx, "rootful"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Start(ctx, "rootful", "caddy.service"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Stop(ctx, "rootful", "caddy.service"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Restart(ctx, "rootful", "caddy.service"); err != nil {
		t.Fatal(err)
	}
	st, err := sys.UnitState(ctx, "rootful", "caddy.service")
	if err != nil || st != wantInfo {
		t.Fatalf("UnitState = (%+v, %v), want (%+v, nil)", st, err, wantInfo)
	}

	if err := sys.DaemonReload(ctx, "openwebui"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Start(ctx, "openwebui", "open-webui.service"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Stop(ctx, "openwebui", "open-webui.service"); err != nil {
		t.Fatal(err)
	}
	if err := sys.Restart(ctx, "openwebui", "open-webui.service"); err != nil {
		t.Fatal(err)
	}
	st, err = sys.UnitState(ctx, "openwebui", "open-webui.service")
	if err != nil || st != wantInfo {
		t.Fatalf("UnitState rootless = (%+v, %v), want (%+v, nil)", st, err, wantInfo)
	}

	wantCalls := []string{
		"systemctl daemon-reload",
		"systemctl start caddy.service",
		"systemctl stop caddy.service",
		"systemctl restart caddy.service",
		"systemctl show -p ActiveState -p Type -p Result caddy.service",
		"systemctl --user -M openwebui@ daemon-reload",
		"systemctl --user -M openwebui@ start open-webui.service",
		"systemctl --user -M openwebui@ stop open-webui.service",
		"systemctl --user -M openwebui@ restart open-webui.service",
		"systemctl --user -M openwebui@ show -p ActiveState -p Type -p Result open-webui.service",
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("systemctl calls =\n%v\nwant:\n%v", runner.calls, wantCalls)
	}

	// Reject unsafe scope / unit names
	if err := sys.Start(ctx, "-bad", "foo.service"); err == nil {
		t.Fatalf("expected error for leading dash scope")
	}
	if err := sys.Start(ctx, "openwebui", "-bad.service"); err == nil {
		t.Fatalf("expected error for leading dash unit")
	}
	if err := sys.DaemonReload(ctx, ""); err == nil {
		t.Fatalf("expected error for empty scope")
	}
}

type failingRestartSystemd struct {
	apply.Systemd
	failRestartKey string
	failActive     bool
}

func (f *failingRestartSystemd) Restart(ctx context.Context, scope, unit string) error {
	if f.failActive && scope+"/"+unit == f.failRestartKey {
		f.failActive = false
		return errors.New("simulated Stage 7d restart failure")
	}
	return f.Systemd.Restart(ctx, scope, unit)
}

func TestReconcileStage7dFailureTriggersRollbackAndRootfulAndPrune(t *testing.T) {
	env := newTestEnv(t)
	sysWrapper := &failingRestartSystemd{
		Systemd:        env.systemd,
		failRestartKey: "openwebui/open-webui.service",
	}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            sysWrapper,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	// Commit 1: rootless open-webui + rootful frigate
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]

[[component]]
name = "frigate"
rootful = true
reason = "USB Coral passthrough"
`),
		"components/open-webui/component.toml":            []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"components/frigate/frigate.container":            []byte("[Container]\nImage=ghcr.io/blakeblackshear/frigate:stable\n"),
		"components/frigate/files/config.yml":             []byte("mqtt: false\n"),
		"secrets/open-webui.age":                          env.encryptSecret("sec-v1"),
	})
	sha1 := env.commitRepo("commit 1: rootless + rootful")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}
	if res1.ManagedUnitsRootless != 1 || res1.ManagedUnitsRootful != 1 {
		t.Fatalf("unexpected rootless/rootful counts: %+v", res1)
	}
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/frigate.container")); err != nil {
		t.Fatalf("expected rootful frigate.container written: %v", err)
	}
	if _, err := os.Stat(env.hostPath("/etc/quadmatic/data/frigate/config.yml")); err != nil {
		t.Fatalf("expected rootful data file written: %v", err)
	}

	// Commit 2: drops frigate, updates open-webui secret, but Stage 7d Restart fails!
	sysWrapper.failActive = true
	env.systemd.clearCalls()
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]
`),
		"secrets/open-webui.age": env.encryptSecret("sec-v2"),
	})
	sha2 := env.commitRepo("commit 2: prune frigate + update secret")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 2 to fail on Stage 7d Restart")
	}
	if !res2.RolledBack || res2.FailedStage != "apply" || res2.AppliedSHA != sha1 {
		t.Fatalf("unexpected rollback result: %+v", res2)
	}
	// Frigate files and service restored, open-webui secret restored to sec-v1
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/frigate.container")); err != nil {
		t.Fatalf("expected pruned rootful frigate.container restored on rollback: %v", err)
	}
	if env.secRunner.store["openwebui/webui_secret"] != "sec-v1" {
		t.Fatalf("expected secret restored to sec-v1, got %q", env.secRunner.store["openwebui/webui_secret"])
	}
	if env.systemd.countCalls("restart", "rootful", "frigate.service") != 1 {
		t.Fatalf("expected pruned rootful frigate.service restarted on rollback, calls=%v", env.systemd.calls)
	}

	// Retry Commit 2 once Stage 7d Restart succeeds -> frigate is cleanly pruned
	sysWrapper.failActive = false
	env.systemd.clearCalls()
	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 2 retry failed: %v", err)
	}
	if res3.AppliedSHA != sha2 || res3.ManagedUnitsRootful != 0 || res3.ManagedUnitsRootless != 1 {
		t.Fatalf("unexpected retry result: %+v", res3)
	}
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/frigate.container")); !os.IsNotExist(err) {
		t.Fatalf("expected frigate.container pruned")
	}
	if env.systemd.countCalls("stop", "rootful", "frigate.service") != 1 {
		t.Fatalf("expected frigate.service stopped on prune, calls=%v", env.systemd.calls)
	}
}

type cancelOnStartSystemd struct {
	apply.Systemd
	cancelTriggerUnit string
	cancel            context.CancelFunc
	inRollback        bool
	rollbackCtxErrs   []error
}

func (c *cancelOnStartSystemd) Start(ctx context.Context, scope, unit string) error {
	if scope+"/"+unit == c.cancelTriggerUnit {
		err := c.Systemd.Start(ctx, scope, unit)
		c.cancel()
		return err
	}
	return c.Systemd.Start(ctx, scope, unit)
}

func (c *cancelOnStartSystemd) Restart(ctx context.Context, scope, unit string) error {
	if !c.inRollback && ctx.Err() != nil {
		c.inRollback = true
		return ctx.Err()
	}
	if c.inRollback && ctx.Err() != nil {
		c.rollbackCtxErrs = append(c.rollbackCtxErrs, fmt.Errorf("Restart(%s/%s): %w", scope, unit, ctx.Err()))
	}
	return c.Systemd.Restart(ctx, scope, unit)
}

func (c *cancelOnStartSystemd) UnitState(ctx context.Context, scope, unit string) (apply.UnitStatusInfo, error) {
	if !c.inRollback && ctx.Err() != nil {
		c.inRollback = true
		return apply.UnitStatusInfo{}, ctx.Err()
	}
	return c.Systemd.UnitState(ctx, scope, unit)
}

func (c *cancelOnStartSystemd) Stop(ctx context.Context, scope, unit string) error {
	if c.inRollback && ctx.Err() != nil {
		c.rollbackCtxErrs = append(c.rollbackCtxErrs, fmt.Errorf("Stop(%s/%s): %w", scope, unit, ctx.Err()))
	}
	return c.Systemd.Stop(ctx, scope, unit)
}

func (c *cancelOnStartSystemd) DaemonReload(ctx context.Context, scope string) error {
	if c.inRollback && ctx.Err() != nil {
		c.rollbackCtxErrs = append(c.rollbackCtxErrs, fmt.Errorf("DaemonReload(%s): %w", scope, ctx.Err()))
	}
	return c.Systemd.DaemonReload(ctx, scope)
}

type ctxCheckGitClient struct {
	*spyGitClient
	checkActive     *bool
	rollbackCtxErrs *[]error
}

func (g *ctxCheckGitClient) ReadFileAtCommit(ctx context.Context, sha, relPath string) ([]byte, error) {
	if *g.checkActive && ctx.Err() != nil {
		*g.rollbackCtxErrs = append(*g.rollbackCtxErrs, fmt.Errorf("ReadFileAtCommit(%s:%s): %w", sha, relPath, ctx.Err()))
	}
	return g.spyGitClient.ReadFileAtCommit(ctx, sha, relPath)
}

type ctxCheckNetmgr struct {
	apply.NetmgrReconciler
	checkActive     *bool
	rollbackCtxErrs *[]error
}

func (n *ctxCheckNetmgr) Restore(ctx context.Context, snap *netmgr.Snapshot, created []state.ManagedNetworkRecord) error {
	if *n.checkActive && ctx.Err() != nil {
		*n.rollbackCtxErrs = append(*n.rollbackCtxErrs, fmt.Errorf("Netmgr.Restore: %w", ctx.Err()))
	}
	return n.NetmgrReconciler.Restore(ctx, snap, created)
}

type ctxCheckSecrets struct {
	apply.SecretsManager
	checkActive     *bool
	rollbackCtxErrs *[]error
}

func (s *ctxCheckSecrets) Upsert(ctx context.Context, scope, name string, plaintext []byte) error {
	if *s.checkActive && ctx.Err() != nil {
		*s.rollbackCtxErrs = append(*s.rollbackCtxErrs, fmt.Errorf("Secrets.Upsert(%s/%s): %w", scope, name, ctx.Err()))
	}
	return s.SecretsManager.Upsert(ctx, scope, name, plaintext)
}

func TestReconcileRollbackSurvivesCanceledContext(t *testing.T) {
	env := newTestEnv(t)

	// Commit 1: healthy open-webui with secret v1 + NM profile
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.brokenuser]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]
`),
		"components/open-webui/component.toml":            []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"secrets/open-webui.age":                          env.encryptSecret("secret-v1"),
	})
	sha1 := env.commitRepo("commit 1: baseline")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Commit 2: update secret v2, NM vlan, and add broken component whose Start cancels ctx.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sysWrapper := &cancelOnStartSystemd{
		Systemd:           env.systemd,
		cancelTriggerUnit: "brokenuser/broken.service",
		cancel:            cancel,
	}
	gitWrapper := &ctxCheckGitClient{
		spyGitClient:    env.git,
		checkActive:     &sysWrapper.inRollback,
		rollbackCtxErrs: &sysWrapper.rollbackCtxErrs,
	}
	netWrapper := &ctxCheckNetmgr{
		NetmgrReconciler: env.netmgr,
		checkActive:      &sysWrapper.inRollback,
		rollbackCtxErrs:  &sysWrapper.rollbackCtxErrs,
	}
	secWrapper := &ctxCheckSecrets{
		SecretsManager:  env.secretsMgr,
		checkActive:     &sysWrapper.inRollback,
		rollbackCtxErrs: &sysWrapper.rollbackCtxErrs,
	}

	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                gitWrapper,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            secWrapper,
		Netmgr:             netWrapper,
		Systemd:            sysWrapper,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
		RollbackTimeout:    5 * time.Second,
	})

	env.systemd.clearCalls()
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 31
mac = "02:51:4d:00:07:d2"
dns = ["10.31.0.1"]

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v2\nNetwork={{ .Net.PastaArgs }}\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"secrets/open-webui.age":                          env.encryptSecret("secret-v2"),
		"components/broken/broken.container":              []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 2: canceled mid-Stage 7")

	res, err := env.engine.Reconcile(ctx, env.reconcileOpts(50*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 2 to fail when ctx canceled mid-Stage 7")
	}
	if !res.RolledBack {
		t.Fatalf("expected RolledBack = true, got %+v", res)
	}
	if res.FailedStage != "apply" {
		t.Fatalf("FailedStage = %q, want %q (rollback must not fail with context.Canceled)", res.FailedStage, "apply")
	}
	if res.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res.AppliedSHA, sha1)
	}
	if len(sysWrapper.rollbackCtxErrs) > 0 {
		t.Fatalf("rollback calls observed canceled context: %v", sysWrapper.rollbackCtxErrs)
	}

	// Verify full restoration despite canceled caller ctx
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/users/2002/broken.container")); !os.IsNotExist(err) {
		t.Fatalf("expected broken.container deleted on rollback")
	}
	qBytes, err := os.ReadFile(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container"))
	if err != nil || !strings.Contains(string(qBytes), "open-webui:v1") {
		t.Fatalf("expected open-webui.container restored to v1, got %q (err=%v)", string(qBytes), err)
	}
	if env.secRunner.store["openwebui/webui_secret"] != "secret-v1" {
		t.Fatalf("expected secret restored to secret-v1, got %q", env.secRunner.store["openwebui/webui_secret"])
	}
	if _, ok := env.netRunner.conns["qm-vlan30"]; !ok {
		t.Fatalf("expected qm-vlan30 restored on rollback")
	}
	if _, ok := env.netRunner.conns["qm-vlan31"]; ok {
		t.Fatalf("expected qm-vlan31 deleted on rollback")
	}
	stAfter, err := state.Load(env.stateFile)
	if err != nil || stAfter.AppliedSHA != sha1 {
		t.Fatalf("expected state.json kept at %q, got %q (err=%v)", sha1, stAfter.AppliedSHA, err)
	}
}

type failingSecretsManager struct {
	apply.SecretsManager
	failUpsert bool
}

func (f *failingSecretsManager) Upsert(ctx context.Context, scope, name string, plaintext []byte) error {
	if f.failUpsert {
		return errors.New("simulated Stage 7c secret upsert error")
	}
	return f.SecretsManager.Upsert(ctx, scope, name, plaintext)
}

type failingStartSystemd struct {
	apply.Systemd
	failStartKey string
}

func (f *failingStartSystemd) Start(ctx context.Context, scope, unit string) error {
	if scope+"/"+unit == f.failStartKey {
		return errors.New("simulated Stage 7d start failure")
	}
	return f.Systemd.Start(ctx, scope, unit)
}

func TestReconcileStage7cSecretFailureDoesNotRestartUntouchedOrManuallyStoppedUnits(t *testing.T) {
	env := newTestEnv(t)
	secMgr := &failingSecretsManager{SecretsManager: env.secretsMgr}
	sysWrapper := &failingStartSystemd{Systemd: env.systemd}

	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            secMgr,
		Netmgr:             env.netmgr,
		Systemd:            sysWrapper,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	// Commit 1: open-webui (active) + caddy (will be manually stopped before Commit 2)
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.caddy]\nuid = 2002\n\n[users.brokenuser]\nuid = 2003\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`),
		"components/open-webui/component.toml":       []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"components/caddy/caddy.container":           []byte("[Container]\nImage=docker.io/library/caddy:v1\n"),
		"secrets/open-webui.age":                     env.encryptSecret("secret-v1"),
	})
	sha1 := env.commitRepo("commit 1: open-webui and caddy")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Manually stop caddy before Commit 2
	env.systemd.states["caddy/caddy.service"] = "inactive"
	env.systemd.clearCalls()
	secMgr.failUpsert = true

	// Commit 2: updates both quadlets (Stage 7b) + rotates open-webui secret (fails in Stage 7c before DaemonReload)
	env.writeRepoFiles(map[string][]byte{
		"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v2\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"components/caddy/caddy.container":           []byte("[Container]\nImage=docker.io/library/caddy:v2\n"),
		"secrets/open-webui.age":                     env.encryptSecret("secret-v2"),
	})
	env.commitRepo("commit 2: stage 7c failure")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 2 to fail in Stage 7c")
	}
	if !res2.RolledBack || res2.FailedStage != "secrets" || res2.AppliedSHA != sha1 {
		t.Fatalf("unexpected Stage 7c rollback result: %+v", res2)
	}

	// Both quadlets rolled back cleanly
	owBytes, err := os.ReadFile(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container"))
	if err != nil || !strings.Contains(string(owBytes), "open-webui:v1") {
		t.Fatalf("expected open-webui.container rolled back to v1, got %q (err=%v)", string(owBytes), err)
	}
	caddyBytes, err := os.ReadFile(env.hostPath("/etc/containers/systemd/users/2002/caddy.container"))
	if err != nil || !strings.Contains(string(caddyBytes), "caddy:v1") {
		t.Fatalf("expected caddy.container rolled back to v1, got %q (err=%v)", string(caddyBytes), err)
	}

	// Crucially: zero DaemonReload, Start, Restart, or Stop calls during pre-reload Stage 7c rollback!
	for _, call := range env.systemd.calls {
		if call.op != "unit-state" {
			t.Fatalf("expected zero mutating systemd calls on Stage 7c rollback, got calls=%v", env.systemd.calls)
		}
	}

	// Part 2: When Stage 7d DOES run DaemonReload and then fails on Start("brokenuser/broken.service")
	// BEFORE restarting caddy.service, manually stopped caddy.service must STILL NOT be restarted on rollback,
	// whereas previously-active open-webui.service IS restarted.
	secMgr.failUpsert = false
	sysWrapper.failStartKey = "brokenuser/broken.service"
	env.systemd.clearCalls()

	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/broken/broken.container": []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 3: stage 7d start failure after reload")

	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 3 to fail on Start")
	}
	if !res3.RolledBack || res3.FailedStage != "apply" || res3.AppliedSHA != sha1 {
		t.Fatalf("unexpected Stage 7d rollback result: %+v", res3)
	}
	if env.systemd.countCalls("restart", "caddy", "caddy.service") != 0 {
		t.Fatalf("manually stopped caddy.service must not be restarted on rollback, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("previously active open-webui.service expected restarted once on rollback, calls=%v", env.systemd.calls)
	}
	if env.secRunner.store["openwebui/webui_secret"] != "secret-v1" {
		t.Fatalf("expected secret restored to secret-v1, got %q", env.secRunner.store["openwebui/webui_secret"])
	}
}

func TestReconcileDryRunPlanSummaryIncludesWriteHealPruneSecretsAndUnits(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.caddy]\nuid = 2002\n\n[users.legacy]\nuid = 2003\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "legacy"
user = "legacy"
`),
		"components/open-webui/component.toml":       []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"components/open-webui/files/app.conf":       []byte("v1\n"),
		"components/legacy/component.toml":           []byte("[secrets]\nlegacy_sec = \"secrets/legacy.age\"\n"),
		"components/legacy/legacy.container":         []byte("[Container]\nImage=alpine:3.20\nSecret=legacy_sec,type=env,target=LEGACY\n"),
		"components/legacy/files/old.conf":           []byte("old\n"),
		"secrets/open-webui.age":                     env.encryptSecret("ow-v1"),
		"secrets/legacy.age":                         env.encryptSecret("leg-v1"),
	})
	env.commitRepo("commit 1")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Tamper with open-webui/files/app.conf on disk so it is marked healed in dry-run.
	if err := os.WriteFile(env.hostPath("/var/home/openwebui/.config/quadmatic/open-webui/app.conf"), []byte("tampered\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Commit 2: updates open-webui secret, drops legacy (prune files, secret, stop unit), adds caddy (write file, upsert secret, start unit).
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[[component]]
name = "caddy"
user = "caddy"
`),
		"components/caddy/component.toml":  []byte("[secrets]\ncaddy_sec = \"secrets/caddy.age\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:2\nSecret=caddy_sec,type=env,target=CADDY_SEC\n"),
		"secrets/open-webui.age":           env.encryptSecret("ow-v2"),
		"secrets/caddy.age":                env.encryptSecret("cad-v1"),
	})
	env.commitRepo("commit 2")

	opts := env.reconcileOpts(100 * time.Millisecond)
	opts.DryRun = true
	res, err := env.engine.Reconcile(context.Background(), opts)
	if err != nil {
		t.Fatalf("dry-run reconcile failed: %v", err)
	}

	wants := []string{
		"write /etc/containers/systemd/users/2002/caddy.container",
		"write /var/home/openwebui/.config/quadmatic/open-webui/app.conf (healed)",
		"prune /etc/containers/systemd/users/2003/legacy.container",
		"prune /var/home/legacy/.config/quadmatic/legacy/old.conf",
		"upsert caddy/caddy_sec",
		"upsert openwebui/webui_secret",
		"prune legacy/legacy_sec",
		"start caddy/caddy.service",
		"restart openwebui/open-webui.service",
		"stop legacy/legacy.service",
	}
	for _, want := range wants {
		if !strings.Contains(res.PlanSummary, want) {
			t.Fatalf("PlanSummary missing %q:\n%s", want, res.PlanSummary)
		}
	}
}

func TestReconcileStoppedNetworkUnitDoesNotFailOrDrift(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
dns = ["10.30.0.1"]
`),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\n"),
	})
	sha1 := env.commitRepo("commit 1: network unit")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}

	// Manually stop the unit on the host.
	env.systemd.states["openwebui/open-webui.service"] = "inactive"
	env.systemd.clearCalls()
	env.netRunner.clearCalls()

	// Next tick while unit remains stopped reports zero drift, performs zero mutations, and reports FailedUnits.
	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("reconcile on manually stopped network unit failed: %v", err)
	}
	if res2.DriftDetected || res2.RolledBack || res2.AppliedSHA != sha1 {
		t.Fatalf("expected no drift or rollback on stopped unit, got %+v", res2)
	}
	wantFailed := []apply.UnitStatus{{Scope: "openwebui", Unit: "open-webui.service", ActiveState: "inactive"}}
	if !reflect.DeepEqual(res2.FailedUnits, wantFailed) {
		t.Fatalf("FailedUnits = %+v, want %+v", res2.FailedUnits, wantFailed)
	}
	for _, call := range env.systemd.calls {
		if call.op != "unit-state" {
			t.Fatalf("expected zero mutating systemd calls on steady stopped unit, got %v", env.systemd.calls)
		}
	}
	for _, call := range env.netRunner.calls {
		if strings.HasPrefix(call, "nmcli connection add") ||
			strings.HasPrefix(call, "nmcli connection modify") ||
			strings.HasPrefix(call, "nmcli connection up") ||
			strings.HasPrefix(call, "nmcli connection delete") ||
			strings.HasPrefix(call, "ip rule add") ||
			strings.HasPrefix(call, "ip rule del") {
			t.Fatalf("expected zero mutating net calls on steady stopped unit, got %v", env.netRunner.calls)
		}
	}
}

func TestReconcileNetworkConfigChangeWithoutTemplateChangeRestartsUnitAndRollsBack(t *testing.T) {
	env := newTestEnv(t)

	// Container template uses {{ .Net.PastaArgs }} + static DNS, so rendered text is identical
	// regardless of vlan, mac, or macvlan_mode changes.
	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n\n[users.brokenuser]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d1"
macvlan_mode = "private"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]
`),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\nDNS={{ index .Net.DNS 0 }}\n"),
		"components/open-webui/open-webui.volume":         []byte("[Volume]\n"),
	})
	env.commitRepo("commit 1: baseline network")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	quadletPath := env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")
	renderedBefore, err := os.ReadFile(quadletPath)
	if err != nil {
		t.Fatal(err)
	}

	// Commit 2: change MAC only -> rendered .container is identical, yet rootless workload unit MUST restart.
	env.systemd.clearCalls()
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 30
mac = "02:51:4d:00:07:d2"
macvlan_mode = "private"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]
`),
	})
	sha2 := env.commitRepo("commit 2: change MAC only")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 2 failed: %v", err)
	}
	if res2.AppliedSHA != sha2 {
		t.Fatalf("AppliedSHA = %q, want %q", res2.AppliedSHA, sha2)
	}
	renderedAfter, err := os.ReadFile(quadletPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(renderedAfter) != string(renderedBefore) {
		t.Fatalf("expected identical rendered .container text:\nbefore:\n%s\nafter:\n%s", renderedBefore, renderedAfter)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected open-webui.service restarted on MAC change, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui-volume.service") != 0 {
		t.Fatalf("helper volume unit must not be restarted, calls=%v", env.systemd.calls)
	}

	// Commit 3: change vlan and macvlan_mode -> rendered .container still identical, yet unit MUST restart.
	env.systemd.clearCalls()
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 31
mac = "02:51:4d:00:07:d2"
macvlan_mode = "bridge"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]
`),
	})
	sha3 := env.commitRepo("commit 3: change vlan and macvlan_mode")

	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 3 failed: %v", err)
	}
	if res3.AppliedSHA != sha3 {
		t.Fatalf("AppliedSHA = %q, want %q", res3.AppliedSHA, sha3)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected open-webui.service restarted on vlan+macvlan_mode change, calls=%v", env.systemd.calls)
	}

	// Commit 4: change MAC again + add broken unit that fails Start BEFORE open-webui.service is restarted.
	// Rollback restores qm-2001 MAC AND must restart open-webui.service even without DaemonReload.
	env.systemd.clearCalls()
	sysWrapper := &failingStartSystemd{Systemd: env.systemd, failStartKey: "brokenuser/broken.service"}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            sysWrapper,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"

[component.network]
vlan = 31
mac = "02:51:4d:00:07:d3"
macvlan_mode = "bridge"
dns = ["10.30.0.1"]
tcp_ports = ["8080:8080"]

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/broken/broken.container": []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 4: mac change + failing new unit")

	res4, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil || !res4.RolledBack || res4.AppliedSHA != sha3 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha3, res4, err)
	}
	if gotMAC := env.netRunner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]; gotMAC != "02:51:4d:00:07:d2" {
		t.Fatalf("expected qm-2001 MAC rolled back to 02:51:4d:00:07:d2, got %q", gotMAC)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 1 {
		t.Fatalf("expected rollback to restart open-webui.service after restoring qm-2001, calls=%v", env.systemd.calls)
	}
}

func TestReconcileFlockWaitsAndRespectsCancellation(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml":                       []byte("[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml":           []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:v1\n"),
	})
	sha1 := env.commitRepo("commit 1")

	lockPath := env.stateFile + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("acquire test flock: %v", err)
	}

	type outcome struct {
		res *apply.Result
		err error
	}
	doneCh := make(chan outcome, 1)
	go func() {
		r, e := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
		doneCh <- outcome{res: r, err: e}
	}()

	select {
	case out := <-doneCh:
		t.Fatalf("Reconcile finished prematurely while flock was held: %+v, err=%v", out.res, out.err)
	case <-time.After(75 * time.Millisecond):
	}

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("unlock test flock: %v", err)
	}
	_ = lockFile.Close()

	select {
	case out := <-doneCh:
		if out.err != nil {
			t.Fatalf("Reconcile after flock release failed: %v", out.err)
		}
		if out.res.AppliedSHA != sha1 {
			t.Fatalf("AppliedSHA = %q, want %q", out.res.AppliedSHA, sha1)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for Reconcile after flock release")
	}

	// Now hold flock again and cancel ctx while Reconcile is blocked.
	lockFile2, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile2.Close()
	if err := syscall.Flock(int(lockFile2.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("acquire second test flock: %v", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile2.Fd()), syscall.LOCK_UN)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancelDone := make(chan outcome, 1)
	go func() {
		r, e := env.engine.Reconcile(ctx, env.reconcileOpts(100*time.Millisecond))
		cancelDone <- outcome{res: r, err: e}
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case out := <-cancelDone:
		if !errors.Is(out.err, context.Canceled) {
			t.Fatalf("expected context.Canceled when canceled while waiting on flock, got %v", out.err)
		}
		if out.res == nil || out.res.FailedStage != "fetch" {
			t.Fatalf("expected FailedStage = \"fetch\", got %+v", out.res)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for canceled Reconcile on held flock")
	}
}

type scriptExitRunner struct {
	calls         []string
	unloadedUnits map[string]bool
	unitStates    map[string]string
	failStartKey  string
}

func (r *scriptExitRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, "systemctl "+strings.Join(args, " "))
	scope := "rootful"
	rest := args
	if len(args) >= 3 && args[0] == "--user" && args[1] == "-M" {
		scope = strings.TrimSuffix(args[2], "@")
		rest = args[3:]
	}
	if len(rest) == 0 {
		return nil, errors.New("empty systemctl args")
	}
	switch rest[0] {
	case "daemon-reload":
		return nil, nil
	case "start":
		unit := rest[1]
		if scope+"/"+unit == r.failStartKey {
			return []byte("start failed"), errors.New("start failed")
		}
		r.unitStates[scope+"/"+unit] = "active"
		return nil, nil
	case "stop":
		unit := rest[1]
		key := scope + "/" + unit
		if r.unloadedUnits[key] {
			err := exec.Command("sh", "-c", "exit 5").Run()
			return []byte("Unit " + unit + " not loaded."), err
		}
		r.unitStates[key] = "inactive"
		return nil, nil
	case "restart":
		unit := rest[1]
		r.unitStates[scope+"/"+unit] = "active"
		return nil, nil
	case "show":
		unit := rest[len(rest)-1]
		st := r.unitStates[scope+"/"+unit]
		if st == "" {
			st = "inactive"
		}
		if slices.Contains(rest, "--value") {
			return []byte(st + "\n"), nil
		}
		return []byte(fmt.Sprintf("ActiveState=%s\nType=simple\nResult=success\n", st)), nil
	default:
		return nil, fmt.Errorf("unexpected systemctl args: %v", args)
	}
}

func TestSystemctlStopToleratesExitCode5AndRejectsExitCode1(t *testing.T) {
	exitRunner := func(code int) apply.CmdRunner {
		return &fakeExitRunner{code: code}
	}

	sys5 := apply.NewSystemctl(exitRunner(5))
	if err := sys5.Stop(context.Background(), "openwebui", "open-webui.service"); err != nil {
		t.Fatalf("Systemctl.Stop with exit code 5 returned error: %v", err)
	}

	sys1 := apply.NewSystemctl(exitRunner(1))
	if err := sys1.Stop(context.Background(), "openwebui", "open-webui.service"); err == nil {
		t.Fatalf("Systemctl.Stop with exit code 1 unexpectedly returned nil")
	}
}

type fakeExitRunner struct {
	code int
}

func (f *fakeExitRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", f.code)).Run()
	return []byte("simulated systemctl exit"), err
}

func TestReconcilePruneAndRollbackWithExitCode5Stop(t *testing.T) {
	env := newTestEnv(t)
	sysRunner := &scriptExitRunner{
		unloadedUnits: make(map[string]bool),
		unitStates:    make(map[string]string),
	}
	sys := apply.NewSystemctl(sysRunner)
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            sys,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	env.writeRepoFiles(map[string][]byte{
		"users.toml":                         []byte("[users.caddy]\nuid = 2002\n\n[users.legacy]\nuid = 2003\n\n[users.brokenuser]\nuid = 2004\n"),
		"hosts/services-02.toml":             []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n\n[[component]]\nname = \"legacy\"\nuser = \"legacy\"\n"),
		"components/caddy/caddy.container":   []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
		"components/legacy/legacy.container": []byte("[Container]\nImage=alpine:3.20\n"),
	})
	sha1 := env.commitRepo("commit 1: caddy + legacy")
	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Mark legacy.service as unloaded so `systemctl stop` exits 5 when pruning it.
	sysRunner.unloadedUnits["legacy/legacy.service"] = true
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
	})
	sha2 := env.commitRepo("commit 2: prune unloaded legacy")
	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 2 pruning unloaded unit failed: %v", err)
	}
	if res2.AppliedSHA != sha2 {
		t.Fatalf("AppliedSHA = %q, want %q", res2.AppliedSHA, sha2)
	}

	// Commit 3: add broken unit that fails Start and returns exit 5 on rollback Stop.
	sysRunner.failStartKey = "brokenuser/broken.service"
	sysRunner.unloadedUnits["brokenuser/broken.service"] = true
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml":             []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n\n[[component]]\nname = \"broken\"\nuser = \"brokenuser\"\n"),
		"components/broken/broken.container": []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 3: add failing unloaded unit")

	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected commit 3 to fail and roll back")
	}
	if !res3.RolledBack || res3.FailedStage != "apply" || res3.AppliedSHA != sha2 {
		t.Fatalf("expected clean rollback with FailedStage=\"apply\" and AppliedSHA=%q, got %+v (err=%v)", sha2, res3, err)
	}
	if res3.AppliedSHA == sha1 {
		t.Fatalf("unexpected rollback to sha1")
	}
}

func TestSystemctlUnitStateAndVerifyOneshotAndSimpleFailure(t *testing.T) {
	runner := &fakeSystemctlRunner{
		out: []byte("ActiveState=inactive\nType=oneshot\nResult=success\n"),
	}
	sys := apply.NewSystemctl(runner)
	info, err := sys.UnitState(context.Background(), "openwebui", "db-migrate.service")
	if err != nil {
		t.Fatalf("UnitState failed: %v", err)
	}
	wantInfo := apply.UnitStatusInfo{ActiveState: "inactive", Type: "oneshot", Result: "success"}
	if info != wantInfo {
		t.Fatalf("UnitState = %+v, want %+v", info, wantInfo)
	}
	wantCall := "systemctl --user -M openwebui@ show -p ActiveState -p Type -p Result db-migrate.service"
	if !slices.Contains(runner.calls, wantCall) {
		t.Fatalf("expected call %q, got %v", wantCall, runner.calls)
	}

	// 1. Type=oneshot + inactive + Result=success passes verifyUnitActive immediately.
	env := newTestEnv(t)
	env.writeRepoFiles(map[string][]byte{
		"users.toml":                       []byte("[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml":           []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
	})
	sha1 := env.commitRepo("oneshot commit")

	env.systemd.overrideUnitState["caddy/caddy.service"] = apply.UnitStatusInfo{
		ActiveState: "inactive",
		Type:        "oneshot",
		Result:      "success",
	}
	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(2*time.Second))
	if err != nil {
		t.Fatalf("oneshot clean exit failed verifyUnitActive: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}
	if env.systemd.countCalls("unit-state", "caddy", "caddy.service") != 1 {
		t.Fatalf("expected immediate single UnitState check for clean oneshot, got %d", env.systemd.countCalls("unit-state", "caddy", "caddy.service"))
	}

	// 2. Type=simple + inactive + Result=exit-code fails verifyUnitActive immediately (without waiting for 5s timeout).
	env2 := newTestEnv(t)
	env2.writeRepoFiles(map[string][]byte{
		"users.toml":                       []byte("[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml":           []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:2\n"),
	})
	env2.commitRepo("simple exit-code commit")

	env2.systemd.overrideUnitState["caddy/caddy.service"] = apply.UnitStatusInfo{
		ActiveState: "inactive",
		Type:        "simple",
		Result:      "exit-code",
	}
	start := time.Now()
	res2, err := env2.engine.Reconcile(context.Background(), env2.reconcileOpts(5*time.Second))
	elapsed := time.Since(start)
	if err == nil || !res2.RolledBack || res2.FailedStage != "apply" {
		t.Fatalf("expected immediate rollback for Type=simple inactive Result=exit-code, got res=%+v err=%v", res2, err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("verifyUnitActive waited too long (%v) instead of failing immediately on exit-code", elapsed)
	}
	if env2.systemd.countCalls("unit-state", "caddy", "caddy.service") != 1 {
		t.Fatalf("expected single UnitState poll before immediate failure, got %d", env2.systemd.countCalls("unit-state", "caddy", "caddy.service"))
	}
}

func TestReconcileAdoptedUserCustomGIDWritesDataFilesWithPrimaryGID(t *testing.T) {
	runCase := func(t *testing.T, postStage5Only bool) {
		t.Helper()
		env := newTestEnv(t)
		env.engine = apply.NewEngine(apply.EngineDeps{
			Config:  env.cfg,
			Git:     env.git,
			Users:   env.users,
			Quadlet: env.quadlet,
			Secrets: env.secretsMgr,
			Netmgr:  env.netmgr,
			Systemd: env.systemd,
			RootDir: env.rootDir,
			Chown: func(p string, uid, gid int) error {
				env.chownCalls = append(env.chownCalls, fmt.Sprintf("%s:%d:%d", p, uid, gid))
				return nil
			},
			UserGIDLookup: func(username string) (int, bool, error) {
				if username != "openwebui" {
					return 0, false, nil
				}
				if postStage5Only && env.users.applyCalls == 0 {
					return 0, false, nil
				}
				return 3000, true, nil
			},
			DHCPTimeout:        100 * time.Millisecond,
			VerifyPollInterval: 5 * time.Millisecond,
		})

		env.writeRepoFiles(map[string][]byte{
			"users.toml":             []byte("[users.openwebui]\nuid = 2001\n"),
			"hosts/services-02.toml": []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"open-webui\"\nuser = \"openwebui\"\n"),
			"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\n"),
			"components/open-webui/files/config.yaml":    []byte("theme: dark\n"),
		})
		env.commitRepo("adopted user custom gid")

		if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
			t.Fatalf("Reconcile failed: %v", err)
		}

		wantChownSuffix := "config.yaml:2001:3000"
		foundDataChown := false
		for _, c := range env.chownCalls {
			if strings.Contains(c, ":2001:3000") {
				foundDataChown = true
			}
			if strings.Contains(c, "config.yaml") && !strings.Contains(c, wantChownSuffix) {
				t.Fatalf("unexpected chown call for config.yaml: %q (want suffix %q)", c, wantChownSuffix)
			}
		}
		if !foundDataChown {
			t.Fatalf("expected chown call with 2001:3000, got %v", env.chownCalls)
		}

		st, err := state.Load(env.stateFile)
		if err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		rec, ok := st.Files["/var/home/openwebui/.config/quadmatic/open-webui/config.yaml"]
		if !ok {
			t.Fatalf("expected config.yaml recorded in state.Files, got %+v", st.Files)
		}
		if rec.OwnerUID != 2001 || rec.OwnerGID != 3000 {
			t.Fatalf("state FileRecord ownership = %d:%d, want 2001:3000", rec.OwnerUID, rec.OwnerGID)
		}
	}

	t.Run("resolved_at_stage3", func(t *testing.T) {
		runCase(t, false)
	})
	t.Run("resolved_after_stage5_rerender", func(t *testing.T) {
		runCase(t, true)
	})
}

func TestReconcileRollbackStopsPreviouslyInactiveRestartedUnit(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.a]\nuid = 2001\n\n[users.b]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "a-app"
user = "a"

[[component]]
name = "b-app"
user = "b"
`),
		"components/a-app/a-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
		"components/a-app/files/cfg.ini":   []byte("v=1\n"),
		"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
	})
	sha1 := env.commitRepo("commit 1")

	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Manually stop a-app.service before Commit 2.
	env.systemd.states["a/a-app.service"] = "inactive"
	env.systemd.clearCalls()

	// Commit 2: updates a-app's data file (putting a-app in unitsToRestart) and updates b-app
	// which fails verifyUnitActive after a-app has already been restarted.
	env.systemd.overrideActiveState["b/b-app.service"] = "failed"
	env.writeRepoFiles(map[string][]byte{
		"components/a-app/files/cfg.ini":   []byte("v=2\n"),
		"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.21\n"),
	})
	env.commitRepo("commit 2: data file restart + b-app failure")

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !res2.RolledBack || res2.FailedStage != "apply" || res2.AppliedSHA != sha1 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, res2, err)
	}

	// a-app.service was restarted once in forward Stage 7d, stopped once on rollback, and NEVER restarted in rollback.
	if got := env.systemd.countCalls("restart", "a", "a-app.service"); got != 1 {
		t.Fatalf("a-app.service restart count = %d, want 1 (forward only); calls=%v", got, env.systemd.calls)
	}
	if got := env.systemd.countCalls("stop", "a", "a-app.service"); got != 1 {
		t.Fatalf("a-app.service stop count = %d, want 1 (rollback stop); calls=%v", got, env.systemd.calls)
	}
	if env.systemd.states["a/a-app.service"] != "inactive" {
		t.Fatalf("expected a-app.service restored to inactive, got %q", env.systemd.states["a/a-app.service"])
	}
	cfgBytes, err := os.ReadFile(env.hostPath("/var/home/a/.config/quadmatic/a-app/cfg.ini"))
	if err != nil || string(cfgBytes) != "v=1\n" {
		t.Fatalf("expected cfg.ini rolled back to v=1, got %q (err=%v)", string(cfgBytes), err)
	}
}

type failingSnapshotNetmgr struct {
	apply.NetmgrReconciler
	failSnapshot bool
}

func (f *failingSnapshotNetmgr) Snapshot(ctx context.Context, host *manifest.ResolvedHost, owned []state.ManagedNetworkRecord) (*netmgr.Snapshot, error) {
	if f.failSnapshot {
		return nil, errors.New("simulated Stage 6 net snapshot error")
	}
	return f.NetmgrReconciler.Snapshot(ctx, host, owned)
}

type failPostRollbackQuerySystemd struct {
	apply.Systemd
	stopBrokenSeen   bool
	failNonCtxKey    string
	waitForCtxCancel bool
}

func (f *failPostRollbackQuerySystemd) Stop(ctx context.Context, scope, unit string) error {
	if scope+"/"+unit == "brokenuser/broken.service" {
		f.stopBrokenSeen = true
	}
	return f.Systemd.Stop(ctx, scope, unit)
}

func (f *failPostRollbackQuerySystemd) UnitState(ctx context.Context, scope, unit string) (apply.UnitStatusInfo, error) {
	if f.stopBrokenSeen {
		if f.waitForCtxCancel {
			<-ctx.Done()
			return apply.UnitStatusInfo{}, ctx.Err()
		}
		if f.failNonCtxKey != "" && scope+"/"+unit == f.failNonCtxKey {
			return apply.UnitStatusInfo{}, errors.New("simulated post-rollback query failure")
		}
	}
	return f.Systemd.UnitState(ctx, scope, unit)
}

func TestReconcilePopulatesFailedUnitsOnStage5Stage6AndRollback(t *testing.T) {
	env := newTestEnv(t)
	netWrapper := &failingSnapshotNetmgr{NetmgrReconciler: env.netmgr}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             netWrapper,
		Systemd:            env.systemd,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.healthy]\nuid = 2001\n\n[users.unhealthy]\nuid = 2002\n\n[users.brokenuser]\nuid = 2003\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "healthy"
user = "healthy"

[[component]]
name = "unhealthy"
user = "unhealthy"
`),
		"components/healthy/healthy.container":     []byte("[Container]\nImage=alpine:3.20\n"),
		"components/unhealthy/unhealthy.container": []byte("[Container]\nImage=alpine:3.20\n"),
	})
	sha1 := env.commitRepo("commit 1: healthy + unhealthy")
	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Mark unhealthy.service as failed out-of-band before Commit 2.
	env.systemd.states["unhealthy/unhealthy.service"] = "failed"
	wantFailed := []apply.UnitStatus{{Scope: "unhealthy", Unit: "unhealthy.service", ActiveState: "failed"}}

	// Commit 2: update healthy so Stage 5/6 runs.
	env.writeRepoFiles(map[string][]byte{
		"components/healthy/healthy.container": []byte("[Container]\nImage=alpine:3.21\n"),
	})
	env.commitRepo("commit 2: update healthy")

	// 1. Stage 5 (users) failure preserves AppliedSHA and FailedUnits.
	env.users.failApply = errors.New("simulated useradd error")
	res5, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected Stage 5 error")
	}
	if res5.FailedStage != "users" || res5.AppliedSHA != sha1 || !reflect.DeepEqual(res5.FailedUnits, wantFailed) {
		t.Fatalf("Stage 5 failure result = %+v, want FailedStage=users AppliedSHA=%q FailedUnits=%+v", res5, sha1, wantFailed)
	}
	env.users.failApply = nil

	// 2. Stage 6 (net Snapshot) failure preserves AppliedSHA and FailedUnits.
	netWrapper.failSnapshot = true
	res6, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatalf("expected Stage 6 net snapshot error")
	}
	if res6.FailedStage != "net" || res6.AppliedSHA != sha1 || !reflect.DeepEqual(res6.FailedUnits, wantFailed) {
		t.Fatalf("Stage 6 failure result = %+v, want FailedStage=net AppliedSHA=%q FailedUnits=%+v", res6, sha1, wantFailed)
	}
	netWrapper.failSnapshot = false

	// 3. Stage 7 rollback re-queries prevState.GeneratedUnits and populates res.FailedUnits.
	env.systemd.overrideActiveState["brokenuser/broken.service"] = "failed"
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "healthy"
user = "healthy"

[[component]]
name = "unhealthy"
user = "unhealthy"

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/broken/broken.container": []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 3: add broken unit")

	res7, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !res7.RolledBack || res7.AppliedSHA != sha1 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, res7, err)
	}
	if !reflect.DeepEqual(res7.FailedUnits, wantFailed) {
		t.Fatalf("post-rollback FailedUnits = %+v, want %+v", res7.FailedUnits, wantFailed)
	}

	// 4. Non-context per-unit error in queryPrevStateFailedUnits continues past the error and reports both unknown and failed units.
	partialFailSys := &failPostRollbackQuerySystemd{
		Systemd:       env.systemd,
		failNonCtxKey: "healthy/healthy.service",
	}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            partialFailSys,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})
	resPartial, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !resPartial.RolledBack || resPartial.AppliedSHA != sha1 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, resPartial, err)
	}
	wantPartialFailed := []apply.UnitStatus{
		{Scope: "healthy", Unit: "healthy.service", ActiveState: "unknown"},
		{Scope: "unhealthy", Unit: "unhealthy.service", ActiveState: "failed"},
	}
	if !reflect.DeepEqual(resPartial.FailedUnits, wantPartialFailed) {
		t.Fatalf("post-rollback partial error FailedUnits = %+v, want %+v", resPartial.FailedUnits, wantPartialFailed)
	}

	// 5. Fallback to stage4FailedUnits when post-rollback UnitState query hits context deadline/cancel.
	fallbackSys := &failPostRollbackQuerySystemd{
		Systemd:          env.systemd,
		waitForCtxCancel: true,
	}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            fallbackSys,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		RollbackTimeout:    30 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})
	resFallback, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !resFallback.RolledBack || resFallback.AppliedSHA != sha1 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, resFallback, err)
	}
	if !reflect.DeepEqual(resFallback.FailedUnits, wantFailed) {
		t.Fatalf("post-rollback fallback FailedUnits = %+v, want %+v", resFallback.FailedUnits, wantFailed)
	}
}

type reprovisionUsersReconciler struct {
	*fakeUsersReconciler
	missingLinger map[string]bool
}

func (u *reprovisionUsersReconciler) Plan(ctx context.Context, reg *users.Registry, activeUsers []string, prev []string) (*users.Plan, error) {
	plan, err := u.fakeUsersReconciler.Plan(ctx, reg, activeUsers, prev)
	if err != nil {
		return nil, err
	}
	for _, user := range activeUsers {
		if u.missingLinger[user] {
			spec := reg.Users[user]
			plan.Actions = append(plan.Actions, users.Action{
				Kind: users.EnableLinger,
				User: user,
				UID:  spec.UID,
			})
		}
	}
	return plan, nil
}

func (u *reprovisionUsersReconciler) Apply(ctx context.Context, reg *users.Registry, activeUsers []string, prev []string) (*users.Plan, error) {
	plan, err := u.fakeUsersReconciler.Apply(ctx, reg, activeUsers, prev)
	if err != nil {
		return plan, err
	}
	for _, user := range activeUsers {
		delete(u.missingLinger, user)
	}
	return plan, nil
}

type reprovisionGuardSystemd struct {
	apply.Systemd
	users             *fakeUsersReconciler
	errBeforeCreation string
	transientErrScope string
	cancelOnQueryKey  string
	cancelFunc        context.CancelFunc
}

func (s *reprovisionGuardSystemd) UnitState(ctx context.Context, scope, unit string) (apply.UnitStatusInfo, error) {
	if s.cancelOnQueryKey != "" && scope+"/"+unit == s.cancelOnQueryKey {
		s.cancelFunc()
		return apply.UnitStatusInfo{}, ctx.Err()
	}
	if s.errBeforeCreation != "" && scope == s.errBeforeCreation && s.users.created[scope] == 0 {
		return apply.UnitStatusInfo{}, fmt.Errorf("user %q does not exist yet on host", scope)
	}
	if s.transientErrScope != "" && scope == s.transientErrScope {
		return apply.UnitStatusInfo{}, fmt.Errorf("dbus connection failed for %s", scope)
	}
	return s.Systemd.UnitState(ctx, scope, unit)
}

func TestReconcileReprovisioningWithPreservedVarRecreatesUserAndUnits(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml":             []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"open-webui\"\nuser = \"openwebui\"\n"),
		"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\n"),
		"components/open-webui/files/config.yaml":    []byte("theme: dark\n"),
	})
	sha1 := env.commitRepo("commit 1: baseline")

	// Initial apply populates state.json in /var/lib/quadmatic.
	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Simulate OS reprovisioning with preserved /var (state.json intact), wiped /etc/passwd,
	// wiped /var/lib/systemd/linger, and wiped /etc/containers/systemd/users/2001/open-webui.container.
	if err := os.Remove(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")); err != nil {
		t.Fatalf("remove quadlet on reprovisioned root: %v", err)
	}
	delete(env.users.created, "openwebui")
	delete(env.systemd.states, "openwebui/open-webui.service")

	usersRec := &reprovisionUsersReconciler{
		fakeUsersReconciler: env.users,
		missingLinger:       map[string]bool{"openwebui": true},
	}
	guardSys := &reprovisionGuardSystemd{
		Systemd:           env.systemd,
		users:             env.users,
		errBeforeCreation: "openwebui",
	}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              usersRec,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            guardSys,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})
	env.systemd.clearCalls()

	res, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("reprovision Reconcile failed: %v", err)
	}
	if res.AppliedSHA != sha1 || !res.DriftDetected {
		t.Fatalf("unexpected reprovision result: %+v", res)
	}
	if env.users.created["openwebui"] != 2001 {
		t.Fatalf("expected openwebui user recreated with uid 2001, got %+v", env.users.created)
	}
	if _, err := os.Stat(env.hostPath("/etc/containers/systemd/users/2001/open-webui.container")); err != nil {
		t.Fatalf("expected open-webui.container rewritten after reprovision: %v", err)
	}
	if env.systemd.countCalls("daemon-reload", "openwebui", "") != 1 {
		t.Fatalf("expected daemon-reload for recreated openwebui user, calls=%v", env.systemd.calls)
	}
	if env.systemd.countCalls("restart", "openwebui", "open-webui.service")+env.systemd.countCalls("start", "openwebui", "open-webui.service") == 0 {
		t.Fatalf("expected open-webui.service started/restarted after reprovision, calls=%v", env.systemd.calls)
	}
	if len(res.FailedUnits) != 0 {
		t.Fatalf("expected zero FailedUnits after reprovision recovery, got %+v", res.FailedUnits)
	}

	// Non-context per-unit query error (e.g., user deleted out-of-band / transient D-Bus failure)
	// must record ActiveState="unknown" instead of failing Stage 4, while context cancellation
	// must fail with FailedStage="validate".
	guardSys.errBeforeCreation = ""
	guardSys.transientErrScope = "openwebui"
	dryOpts := env.reconcileOpts(100 * time.Millisecond)
	dryOpts.DryRun = true
	resTransient, err := env.engine.Reconcile(context.Background(), dryOpts)
	if err != nil {
		t.Fatalf("expected non-context per-unit query error not to wedge Stage 4, got: %v", err)
	}
	wantUnknown := []apply.UnitStatus{{Scope: "openwebui", Unit: "open-webui.service", ActiveState: "unknown"}}
	if !reflect.DeepEqual(resTransient.FailedUnits, wantUnknown) {
		t.Fatalf("FailedUnits = %+v, want %+v", resTransient.FailedUnits, wantUnknown)
	}

	guardSys.transientErrScope = ""
	ctxCancel, cancel := context.WithCancel(context.Background())
	guardSys.cancelOnQueryKey = "openwebui/open-webui.service"
	guardSys.cancelFunc = cancel
	resCtx, err := env.engine.Reconcile(ctxCancel, env.reconcileOpts(100*time.Millisecond))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Stage 4 query, got %v", err)
	}
	if resCtx == nil || resCtx.FailedStage != "validate" {
		t.Fatalf("expected FailedStage = \"validate\" on pre-apply Stage 4 context error, got %+v", resCtx)
	}
}

func TestReconcileHealthyOneshotNotReportedAsFailed(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.db]\nuid = 2001\n\n[users.brokenuser]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "db-migrate"
user = "db"
`),
		"components/db-migrate/db-migrate.container": []byte("[Container]\nImage=alpine:3.20\n"),
	})
	sha1 := env.commitRepo("commit 1: healthy oneshot")

	env.systemd.overrideUnitState["db/db-migrate.service"] = apply.UnitStatusInfo{
		ActiveState: "inactive",
		Type:        "oneshot",
		Result:      "success",
	}

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 || len(res1.FailedUnits) != 0 {
		t.Fatalf("unexpected commit 1 result: %+v", res1)
	}

	// Subsequent steady tick must NOT report healthy oneshot in FailedUnits.
	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("subsequent tick failed: %v", err)
	}
	if len(res2.FailedUnits) != 0 {
		t.Fatalf("expected healthy oneshot excluded from Result.FailedUnits on subsequent tick, got %+v", res2.FailedUnits)
	}

	// Failed apply triggering rollback must also NOT report healthy oneshot in post-rollback FailedUnits.
	env.systemd.overrideActiveState["brokenuser/broken.service"] = "failed"
	env.writeRepoFiles(map[string][]byte{
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "db-migrate"
user = "db"

[[component]]
name = "broken"
user = "brokenuser"
`),
		"components/broken/broken.container": []byte("[Container]\nImage=example.invalid/broken:latest\n"),
	})
	env.commitRepo("commit 2: add failing unit")

	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !res3.RolledBack {
		t.Fatalf("expected commit 2 rollback, got res=%+v err=%v", res3, err)
	}
	if len(res3.FailedUnits) != 0 {
		t.Fatalf("expected healthy oneshot excluded from post-rollback Result.FailedUnits, got %+v", res3.FailedUnits)
	}
}

type dryRunSpyGitClient struct {
	*gitops.Client
	fetchAndVerifyCalls       int
	fetchAndVerifyDryRunCalls int
	cleanupCalls              int
}

func (g *dryRunSpyGitClient) FetchAndVerify(ctx context.Context, appliedSHA string, allowNonFF bool) (string, error) {
	g.fetchAndVerifyCalls++
	return g.Client.FetchAndVerify(ctx, appliedSHA, allowNonFF)
}

func (g *dryRunSpyGitClient) FetchAndVerifyDryRun(ctx context.Context, appliedSHA string, allowNonFF bool) (string, func(), error) {
	g.fetchAndVerifyDryRunCalls++
	sha, cleanup, err := g.Client.FetchAndVerifyDryRun(ctx, appliedSHA, allowNonFF)
	if cleanup == nil {
		return sha, nil, err
	}
	return sha, func() {
		g.cleanupCalls++
		cleanup()
	}, err
}

func TestReconcileRemoteDryRunUsesEphemeralGitFetch(t *testing.T) {
	base := t.TempDir()
	rootDir := filepath.Join(base, "rootfs")
	remoteBare := filepath.Join(base, "remote.git")
	workDir := filepath.Join(base, "work")
	mirrorDir := filepath.Join(base, "mirror.git")
	stateFile := filepath.Join(base, "state", "state.json")

	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	signingKey := filepath.Join(base, "signing_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", signingKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, string(out))
	}
	pubBytes, err := os.ReadFile(signingKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	allowedSigners := filepath.Join(base, "allowed-signers")
	if err := os.WriteFile(allowedSigners, []byte("ci@example.lan "+strings.TrimSpace(string(pubBytes))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deployKey := filepath.Join(base, "deploy_key")
	knownHosts := filepath.Join(base, "known_hosts")
	_ = os.WriteFile(deployKey, []byte("dummy\n"), 0o600)
	_ = os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600)

	if out, err := exec.Command("git", "init", "--bare", "-b", "main", remoteBare).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, string(out))
	}
	initGitRepo(t, workDir)
	runGitCmd(t, workDir, "config", "gpg.format", "ssh")
	runGitCmd(t, workDir, "remote", "add", "origin", remoteBare)

	writeWork := func(rel, content string) {
		p := filepath.Join(workDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commitSignedAndPush := func(msg string) string {
		runGitCmd(t, workDir, "add", "-A")
		runGitCmd(t, workDir, "-c", "user.signingkey="+signingKey, "commit", "-S", "-m", msg)
		runGitCmd(t, workDir, "push", "origin", "HEAD:refs/heads/main")
		return strings.TrimSpace(runGitCmd(t, workDir, "rev-parse", "HEAD"))
	}

	writeWork("users.toml", "[users.caddy]\nuid = 2002\n")
	writeWork("hosts/services-02.toml", "hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n")
	writeWork("components/caddy/caddy.container", "[Container]\nImage=docker.io/library/caddy:v1\n")
	sha1 := commitSignedAndPush("commit 1")

	cfg := &config.HostConfig{
		Hostname:       "services-02",
		RepoURL:        remoteBare,
		Branch:         "main",
		SSHKey:         deployKey,
		SSHKnownHosts:  knownHosts,
		AllowedSigners: allowedSigners,
		TrunkInterface: "enp3s0",
		StateFile:      stateFile,
		RepoDir:        mirrorDir,
	}

	spyGit := &dryRunSpyGitClient{Client: gitops.NewClient(cfg)}
	engine := apply.NewEngine(apply.EngineDeps{
		Config:             cfg,
		Git:                spyGit,
		Users:              newFakeUsersReconciler(),
		Quadlet:            quadlet.NewValidator("/fake/quadlet", &fakeQuadletRunner{}),
		Secrets:            secrets.NewManager(newFakeSecretRunner()),
		Netmgr:             netmgr.NewReconciler("enp3s0", newFakeNetRunner(), newZeroSysctl()),
		Systemd:            newFakeSystemd(),
		RootDir:            rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	// Apply commit 1 normally.
	res1, err := engine.Reconcile(context.Background(), apply.ReconcileOptions{StartVerifyTimeout: 100 * time.Millisecond})
	if err != nil || res1.AppliedSHA != sha1 {
		t.Fatalf("commit 1 Reconcile = (%+v, %v), want sha=%s", res1, err, sha1)
	}
	refsBefore := strings.TrimSpace(runGitCmd(t, mirrorDir, "show-ref"))

	// Push commit 2 and run remote --dry-run (LocalRepoPath == "", DryRun == true).
	writeWork("components/caddy/caddy.container", "[Container]\nImage=docker.io/library/caddy:v2\n")
	sha2 := commitSignedAndPush("commit 2")

	spyGit.fetchAndVerifyCalls = 0
	spyGit.fetchAndVerifyDryRunCalls = 0
	spyGit.cleanupCalls = 0

	resDry, err := engine.Reconcile(context.Background(), apply.ReconcileOptions{
		DryRun:             true,
		StartVerifyTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("remote DryRun Reconcile failed: %v", err)
	}
	if spyGit.fetchAndVerifyCalls != 0 {
		t.Fatalf("remote DryRun must NEVER call FetchAndVerify, got %d calls", spyGit.fetchAndVerifyCalls)
	}
	if spyGit.fetchAndVerifyDryRunCalls != 1 {
		t.Fatalf("expected 1 FetchAndVerifyDryRun call, got %d", spyGit.fetchAndVerifyDryRunCalls)
	}
	if spyGit.cleanupCalls != 1 {
		t.Fatalf("expected FetchAndVerifyDryRun cleanup called once, got %d", spyGit.cleanupCalls)
	}
	if !strings.Contains(resDry.PlanSummary, sha2) {
		t.Fatalf("expected PlanSummary to reference fetched SHA %s, got:\n%s", sha2, resDry.PlanSummary)
	}
	refsAfter := strings.TrimSpace(runGitCmd(t, mirrorDir, "show-ref"))
	if refsAfter != refsBefore {
		t.Fatalf("remote DryRun mutated cfg.RepoDir refs!\nbefore:\n%s\nafter:\n%s", refsBefore, refsAfter)
	}
}

func TestReconcileLockTimeoutReturnsClearError(t *testing.T) {
	env := newTestEnv(t)
	env.writeRepoFiles(map[string][]byte{
		"users.toml":                       []byte("[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml":           []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:v1\n"),
	})
	env.commitRepo("commit 1")

	lockPath := env.stateFile + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("acquire test flock: %v", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	engine := apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            env.systemd,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		LockTimeout:        60 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	res, err := engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err == nil {
		t.Fatal("expected lock timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded error, got: %v", err)
	}
	if !strings.Contains(err.Error(), lockPath) {
		t.Fatalf("expected lock timeout error to name lock path %q, got: %v", lockPath, err)
	}
	if res == nil || res.FailedStage != "fetch" {
		t.Fatalf("expected FailedStage = \"fetch\", got %+v", res)
	}
}

type oneShotTransientUnitStateSystemd struct {
	apply.Systemd
	targetKey string
	failOnce  bool
}

func (s *oneShotTransientUnitStateSystemd) UnitState(ctx context.Context, scope, unit string) (apply.UnitStatusInfo, error) {
	if s.failOnce && scope+"/"+unit == s.targetKey {
		s.failOnce = false
		return apply.UnitStatusInfo{}, errors.New("dbus connection timed out")
	}
	return s.Systemd.UnitState(ctx, scope, unit)
}

func TestReconcileStage4TransientErrorDoesNotStopRunningUnitOnRollback(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.a]\nuid = 2001\n\n[users.b]\nuid = 2002\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "a-app"
user = "a"

[[component]]
name = "b-app"
user = "b"
`),
		"components/a-app/a-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
		"components/a-app/files/cfg.ini":   []byte("v=1\n"),
		"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
	})
	sha1 := env.commitRepo("commit 1: a + b running")
	if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}

	// Commit 2: updates a-app's data file (restarted in Stage 7d) and updates b-app.
	env.writeRepoFiles(map[string][]byte{
		"components/a-app/files/cfg.ini":   []byte("v=2\n"),
		"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.21\n"),
	})
	env.commitRepo("commit 2: restart a-app + fail b-app")

	transientSys := &oneShotTransientUnitStateSystemd{
		Systemd:   env.systemd,
		targetKey: "a/a-app.service",
		failOnce:  true,
	}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            transientSys,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	// Dry-run records ActiveState="unknown" for transient Stage 4 error.
	dryOpts := env.reconcileOpts(100 * time.Millisecond)
	dryOpts.DryRun = true
	resDry, err := env.engine.Reconcile(context.Background(), dryOpts)
	if err != nil {
		t.Fatalf("dry-run with transient D-Bus error failed: %v", err)
	}
	wantUnknown := []apply.UnitStatus{{Scope: "a", Unit: "a-app.service", ActiveState: "unknown"}}
	if !reflect.DeepEqual(resDry.FailedUnits, wantUnknown) {
		t.Fatalf("dry-run FailedUnits = %+v, want %+v", resDry.FailedUnits, wantUnknown)
	}

	// Non-dry-run with transient Stage 4 D-Bus error on running a-app.service and b-app failing Stage 7d
	// verifyUnitActive -> rollback MUST restart a-app.service, NOT stop it.
	env.systemd.overrideActiveState["b/b-app.service"] = "failed"
	env.systemd.clearCalls()
	transientSys.failOnce = true
	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
	if err == nil || !res2.RolledBack || res2.FailedStage != "apply" || res2.AppliedSHA != sha1 {
		t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, res2, err)
	}
	if got := env.systemd.countCalls("stop", "a", "a-app.service"); got != 0 {
		t.Fatalf("running unit with transient Stage 4 query error must NOT be stopped on rollback, stop count=%d calls=%v", got, env.systemd.calls)
	}
	if got := env.systemd.countCalls("restart", "a", "a-app.service"); got != 2 {
		t.Fatalf("running unit with transient Stage 4 query error must be restarted (forward + rollback), restart count=%d calls=%v", got, env.systemd.calls)
	}
	if env.systemd.states["a/a-app.service"] != "active" {
		t.Fatalf("expected a-app.service active after rollback, got %q", env.systemd.states["a/a-app.service"])
	}
}

func TestReconcileCreateUserReportsFailedUnitsAndEnableLingerStillQueriesSystemd(t *testing.T) {
	t.Run("CreateUser pending units appear in FailedUnits on dry-run and Stage 5 failure", func(t *testing.T) {
		env := newTestEnv(t)

		env.writeRepoFiles(map[string][]byte{
			"users.toml":             []byte("[users.openwebui]\nuid = 2001\n"),
			"hosts/services-02.toml": []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"open-webui\"\nuser = \"openwebui\"\n"),
			"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\n"),
		})
		sha1 := env.commitRepo("commit 1")
		if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
			t.Fatalf("commit 1 failed: %v", err)
		}

		// Simulate user wiped from host while state.json still tracks openwebui/open-webui.service.
		delete(env.users.created, "openwebui")
		delete(env.systemd.states, "openwebui/open-webui.service")

		guardSys := &reprovisionGuardSystemd{
			Systemd:           env.systemd,
			users:             env.users,
			errBeforeCreation: "openwebui",
		}
		env.engine = apply.NewEngine(apply.EngineDeps{
			Config:             env.cfg,
			Git:                env.git,
			Users:              env.users,
			Quadlet:            env.quadlet,
			Secrets:            env.secretsMgr,
			Netmgr:             env.netmgr,
			Systemd:            guardSys,
			RootDir:            env.rootDir,
			Chown:              func(string, int, int) error { return nil },
			DHCPTimeout:        100 * time.Millisecond,
			VerifyPollInterval: 5 * time.Millisecond,
		})
		env.systemd.clearCalls()

		wantDown := []apply.UnitStatus{{Scope: "openwebui", Unit: "open-webui.service", ActiveState: "inactive"}}

		dryOpts := env.reconcileOpts(100 * time.Millisecond)
		dryOpts.DryRun = true
		resDry, err := env.engine.Reconcile(context.Background(), dryOpts)
		if err != nil {
			t.Fatalf("dry-run failed: %v", err)
		}
		if !reflect.DeepEqual(resDry.FailedUnits, wantDown) {
			t.Fatalf("dry-run FailedUnits = %+v, want %+v", resDry.FailedUnits, wantDown)
		}
		if env.systemd.countCalls("unit-state", "openwebui", "open-webui.service") != 0 {
			t.Fatalf("expected UnitState skipped for CreateUser scope, calls=%v", env.systemd.calls)
		}

		env.users.failApply = errors.New("simulated Stage 5 useradd error")
		res5, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
		if err == nil || res5.FailedStage != "users" || res5.AppliedSHA != sha1 {
			t.Fatalf("expected Stage 5 failure preserving sha1=%q, got res=%+v err=%v", sha1, res5, err)
		}
		if !reflect.DeepEqual(res5.FailedUnits, wantDown) {
			t.Fatalf("Stage 5 failure FailedUnits = %+v, want %+v", res5.FailedUnits, wantDown)
		}
	})

	t.Run("EnableLinger-only user still gets queried and active unit is not marked priorNonActive", func(t *testing.T) {
		env := newTestEnv(t)

		env.writeRepoFiles(map[string][]byte{
			"users.toml": []byte("[users.a]\nuid = 2001\n\n[users.b]\nuid = 2002\n"),
			"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "a-app"
user = "a"

[[component]]
name = "b-app"
user = "b"
`),
			"components/a-app/a-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
			"components/a-app/files/cfg.ini":   []byte("v=1\n"),
			"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.20\n"),
		})
		sha1 := env.commitRepo("commit 1")
		if _, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond)); err != nil {
			t.Fatalf("commit 1 failed: %v", err)
		}

		// User 'a' exists (AdoptUser) and only needs EnableLinger; its unit a/a-app.service is active.
		usersRec := &reprovisionUsersReconciler{
			fakeUsersReconciler: env.users,
			missingLinger:       map[string]bool{"a": true},
		}
		env.engine = apply.NewEngine(apply.EngineDeps{
			Config:             env.cfg,
			Git:                env.git,
			Users:              usersRec,
			Quadlet:            env.quadlet,
			Secrets:            env.secretsMgr,
			Netmgr:             env.netmgr,
			Systemd:            env.systemd,
			RootDir:            env.rootDir,
			Chown:              func(string, int, int) error { return nil },
			DHCPTimeout:        100 * time.Millisecond,
			VerifyPollInterval: 5 * time.Millisecond,
		})

		env.writeRepoFiles(map[string][]byte{
			"components/a-app/files/cfg.ini":   []byte("v=2\n"),
			"components/b-app/b-app.container": []byte("[Container]\nImage=alpine:3.21\n"),
		})
		env.commitRepo("commit 2: restart a-app + fail b-app")

		// Dry-run must query UnitState for EnableLinger-only user 'a' and report zero failed units.
		env.systemd.clearCalls()
		dryOpts := env.reconcileOpts(100 * time.Millisecond)
		dryOpts.DryRun = true
		resDry, err := env.engine.Reconcile(context.Background(), dryOpts)
		if err != nil {
			t.Fatalf("dry-run failed: %v", err)
		}
		if env.systemd.countCalls("unit-state", "a", "a-app.service") != 1 {
			t.Fatalf("expected UnitState queried for EnableLinger-only user 'a', calls=%v", env.systemd.calls)
		}
		if len(resDry.FailedUnits) != 0 {
			t.Fatalf("expected zero FailedUnits for active EnableLinger-only unit, got %+v", resDry.FailedUnits)
		}

		// Failed apply triggering rollback must restart (NOT stop) a/a-app.service.
		env.systemd.overrideActiveState["b/b-app.service"] = "failed"
		env.systemd.clearCalls()
		res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(50*time.Millisecond))
		if err == nil || !res2.RolledBack || res2.AppliedSHA != sha1 {
			t.Fatalf("expected rollback to %q, got res=%+v err=%v", sha1, res2, err)
		}
		if got := env.systemd.countCalls("stop", "a", "a-app.service"); got != 0 {
			t.Fatalf("active EnableLinger-only unit must NOT be stopped on rollback, stop=%d calls=%v", got, env.systemd.calls)
		}
		if got := env.systemd.countCalls("restart", "a", "a-app.service"); got != 2 {
			t.Fatalf("active EnableLinger-only unit must be restarted (forward + rollback), restart=%d calls=%v", got, env.systemd.calls)
		}
	})
}

func TestReconcileRecreatedUserReupsertsSecretsDespiteMatchingDigest(t *testing.T) {
	env := newTestEnv(t)

	env.writeRepoFiles(map[string][]byte{
		"users.toml": []byte("[users.openwebui]\nuid = 2001\n"),
		"hosts/services-02.toml": []byte(`hostname = "services-02"

[[component]]
name = "open-webui"
user = "openwebui"
`),
		"components/open-webui/component.toml":       []byte("[secrets]\nwebui_secret = \"secrets/open-webui.age\"\n"),
		"components/open-webui/open-webui.container": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nSecret=webui_secret,type=env,target=WEBUI_SECRET_KEY\n"),
		"secrets/open-webui.age":                     env.encryptSecret("persisted-secret-v1"),
	})
	sha1 := env.commitRepo("commit 1: secret baseline")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 || env.secRunner.store["openwebui/webui_secret"] != "persisted-secret-v1" {
		t.Fatalf("unexpected commit 1 state: res=%+v store=%+v", res1, env.secRunner.store)
	}

	// Simulate `userdel -r openwebui` / fresh-home reprovisioning: user and rootless podman secret
	// store are gone, while state.json still holds matching secret digest.
	delete(env.users.created, "openwebui")
	delete(env.secRunner.store, "openwebui/webui_secret")
	env.secRunner.calls = nil
	env.systemd.clearCalls()

	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("recreated user Reconcile failed: %v", err)
	}
	if res2.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res2.AppliedSHA, sha1)
	}
	if !slices.Contains(env.secRunner.calls, "upsert:openwebui/webui_secret") {
		t.Fatalf("expected secrets.Upsert called for recreated user openwebui despite matching digest, calls=%v", env.secRunner.calls)
	}
	if got := env.secRunner.store["openwebui/webui_secret"]; got != "persisted-secret-v1" {
		t.Fatalf("re-upserted secret value = %q, want %q", got, "persisted-secret-v1")
	}
}

type lockGateGitClient struct {
	*spyGitClient
	repoPath     string
	dryRunCalled chan struct{}
}

func (g *lockGateGitClient) FetchAndVerifyDryRun(ctx context.Context, appliedSHA string, allowNonFF bool) (string, func(), error) {
	select {
	case g.dryRunCalled <- struct{}{}:
	default:
	}
	sha, err := g.VerifyLocalRepo(ctx, g.repoPath, appliedSHA, allowNonFF, true)
	return sha, func() {}, err
}

func TestReconcileRemoteDryRunSharedLock(t *testing.T) {
	env := newTestEnv(t)
	env.writeRepoFiles(map[string][]byte{
		"users.toml":                       []byte("[users.caddy]\nuid = 2002\n"),
		"hosts/services-02.toml":           []byte("hostname = \"services-02\"\n\n[[component]]\nname = \"caddy\"\nuser = \"caddy\"\n"),
		"components/caddy/caddy.container": []byte("[Container]\nImage=docker.io/library/caddy:v1\n"),
	})
	sha1 := env.commitRepo("commit 1")

	lockPath := env.stateFile + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		t.Fatal(err)
	}

	// 1. Remote dry-run blocks while LOCK_EX is held, and proceeds once released.
	exFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer exFile.Close()
	if err := syscall.Flock(int(exFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("acquire LOCK_EX: %v", err)
	}

	dryCalled := make(chan struct{}, 2)
	gateGit := &lockGateGitClient{
		spyGitClient: env.git,
		repoPath:     env.repoDir,
		dryRunCalled: dryCalled,
	}
	engine := apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                gateGit,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             env.netmgr,
		Systemd:            env.systemd,
		RootDir:            env.rootDir,
		Chown:              func(string, int, int) error { return nil },
		DHCPTimeout:        100 * time.Millisecond,
		LockTimeout:        2 * time.Second,
		VerifyPollInterval: 5 * time.Millisecond,
	})

	type recOut struct {
		res *apply.Result
		err error
	}
	done := make(chan recOut, 1)
	go func() {
		r, e := engine.Reconcile(context.Background(), apply.ReconcileOptions{
			DryRun:             true,
			StartVerifyTimeout: 100 * time.Millisecond,
		})
		done <- recOut{res: r, err: e}
	}()

	select {
	case <-dryCalled:
		_ = syscall.Flock(int(exFile.Fd()), syscall.LOCK_UN)
		t.Fatal("remote dry-run proceeded to FetchAndVerifyDryRun while LOCK_EX was held")
	case <-time.After(60 * time.Millisecond):
	}

	if err := syscall.Flock(int(exFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("release LOCK_EX: %v", err)
	}

	var out recOut
	select {
	case out = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("remote dry-run did not complete after LOCK_EX was released")
	}
	if out.err != nil || !strings.Contains(out.res.PlanSummary, sha1) {
		t.Fatalf("remote dry-run after LOCK_EX release = (%+v, %v), want sha=%s", out.res, out.err, sha1)
	}

	// 2. Remote dry-run does NOT block another LOCK_SH holder.
	shFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer shFile.Close()
	if err := syscall.Flock(int(shFile.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		t.Fatalf("acquire LOCK_SH: %v", err)
	}
	defer func() {
		_ = syscall.Flock(int(shFile.Fd()), syscall.LOCK_UN)
	}()

	resShared, err := engine.Reconcile(context.Background(), apply.ReconcileOptions{
		DryRun:             true,
		StartVerifyTimeout: 100 * time.Millisecond,
	})
	if err != nil || !strings.Contains(resShared.PlanSummary, sha1) {
		t.Fatalf("remote dry-run while LOCK_SH held = (%+v, %v), want success with sha=%s", resShared, err, sha1)
	}
}
