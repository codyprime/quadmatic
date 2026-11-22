package apply_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
	states              map[string]string // "<scope>/<unit>" -> state
	overrideActiveState map[string]string // overrides ActiveState return without clearing
}

func newFakeSystemd() *fakeSystemd {
	return &fakeSystemd{
		states:              make(map[string]string),
		overrideActiveState: make(map[string]string),
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

func (f *fakeSystemd) ActiveState(_ context.Context, scope, unit string) (string, error) {
	f.calls = append(f.calls, systemdCall{op: "active-state", scope: scope, unit: unit})
	key := scope + "/" + unit
	if st, ok := f.overrideActiveState[key]; ok {
		return st, nil
	}
	if st, ok := f.states[key]; ok {
		return st, nil
	}
	return "inactive", nil
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

type fakeNetRunner struct {
	calls      []string
	conns      map[string]*fakeNMConn
	active     map[string]bool
	dnsByIface map[string]string
	routes     map[int][]string
	routes6    map[int][]string
	nftTable   string
}

func newFakeNetRunner() *fakeNetRunner {
	return &fakeNetRunner{
		conns:      make(map[string]*fakeNMConn),
		active:     make(map[string]bool),
		dnsByIface: make(map[string]string),
		routes:     make(map[int][]string),
		routes6:    make(map[int][]string),
	}
}

func (f *fakeNetRunner) clearCalls() {
	f.calls = nil
}

func (f *fakeNetRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "nmcli":
		return f.handleNMCLI(args)
	case "ip":
		return f.handleIP(args)
	case "nft":
		return f.handleNFT(string(stdin), args)
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
				if k == "ethernet.cloned-mac-address" {
					k = "802-3-ethernet.cloned-mac-address"
				}
				c.props[k] = v
			}
			return nil, nil
		case "up":
			conName := rest[2]
			if _, ok := f.conns[conName]; !ok {
				return []byte("Error: no such connection profile"), errors.New("exit status 10")
			}
			f.active[conName] = true
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

func (f *fakeNetRunner) handleNFT(stdin string, args []string) ([]byte, error) {
	if len(args) >= 4 && args[0] == "list" {
		if f.nftTable == "" {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		}
		return []byte(f.nftTable), nil
	}
	if len(args) >= 4 && args[0] == "delete" {
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
	}
	return nil, fmt.Errorf("unsupported nft: %v", args)
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
	netRec.CgroupExists = func(cgPath string) bool {
		unit := path.Base(cgPath)
		uid := extractCgroupUID(cgPath)
		if uid <= 0 {
			return false
		}
		scope := usersRec.scopeForUID(uid)
		if scope == "" {
			return false
		}
		key := scope + "/" + unit
		if st, ok := sysd.overrideActiveState[key]; ok {
			return st == "active"
		}
		return sysd.states[key] == "active"
	}

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

func extractCgroupUID(cgPath string) int {
	for _, seg := range strings.Split(cgPath, "/") {
		if after, ok := strings.CutPrefix(seg, "user-"); ok {
			if uidStr, ok := strings.CutSuffix(after, ".slice"); ok {
				if uid, err := strconv.Atoi(uidStr); err == nil {
					return uid
				}
			}
		}
	}
	return 0
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
	if len(env.netRunner.conns) != 0 || env.netRunner.nftTable != "" {
		t.Fatalf("DryRun unexpectedly mutated network/nftables: conns=%v nft=%q", env.netRunner.conns, env.netRunner.nftTable)
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
	snapNFT := env.netRunner.nftTable
	if snapNFT == "" {
		t.Fatalf("expected commit 1 to create inet quadmatic nftables ruleset")
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

	// Verify NM profiles + nftables restored to Commit 1
	if _, ok := env.netRunner.conns["qm-vlan31"]; ok {
		t.Fatalf("expected commit 2 qm-vlan31 deleted on rollback")
	}
	if _, ok := env.netRunner.conns["qm-vlan30"]; !ok {
		t.Fatalf("expected commit 1 qm-vlan30 restored on rollback")
	}
	if mac := env.netRunner.conns["qm-2001"].props["802-3-ethernet.cloned-mac-address"]; mac != "02:51:4d:00:07:d1" {
		t.Fatalf("expected qm-2001 MAC restored to 02:51:4d:00:07:d1, got %q", mac)
	}
	if env.netRunner.nftTable != snapNFT {
		t.Fatalf("expected nftables ruleset restored to Commit 1 snapshot:\ngot:\n%s\nwant:\n%s", env.netRunner.nftTable, snapNFT)
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
	runner := &fakeSystemctlRunner{out: []byte("active\n")}
	sys := apply.NewSystemctl(runner)
	ctx := context.Background()

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
	st, err := sys.ActiveState(ctx, "rootful", "caddy.service")
	if err != nil || st != "active" {
		t.Fatalf("ActiveState = (%q, %v), want (\"active\", nil)", st, err)
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
	st, err = sys.ActiveState(ctx, "openwebui", "open-webui.service")
	if err != nil || st != "active" {
		t.Fatalf("ActiveState rootless = (%q, %v), want (\"active\", nil)", st, err)
	}

	wantCalls := []string{
		"systemctl daemon-reload",
		"systemctl start caddy.service",
		"systemctl stop caddy.service",
		"systemctl restart caddy.service",
		"systemctl show -p ActiveState --value caddy.service",
		"systemctl --user -M openwebui@ daemon-reload",
		"systemctl --user -M openwebui@ start open-webui.service",
		"systemctl --user -M openwebui@ stop open-webui.service",
		"systemctl --user -M openwebui@ restart open-webui.service",
		"systemctl --user -M openwebui@ show -p ActiveState --value open-webui.service",
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

type failNFTNetmgr struct {
	apply.NetmgrReconciler
	failNFT bool
}

func (f *failNFTNetmgr) ApplyNFTables(ctx context.Context, host *manifest.ResolvedHost) (string, error) {
	if f.failNFT {
		return "", errors.New("nft -f -: cgroupv2 path missing")
	}
	return f.NetmgrReconciler.ApplyNFTables(ctx, host)
}

func TestReconcileNFTablesFailureTriggersRollbackAndRootfulAndPrune(t *testing.T) {
	env := newTestEnv(t)
	nftWrapper := &failNFTNetmgr{NetmgrReconciler: env.netmgr}
	env.engine = apply.NewEngine(apply.EngineDeps{
		Config:             env.cfg,
		Git:                env.git,
		Users:              env.users,
		Quadlet:            env.quadlet,
		Secrets:            env.secretsMgr,
		Netmgr:             nftWrapper,
		Systemd:            env.systemd,
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

	// Commit 2: drops frigate, updates open-webui secret, but ApplyNFTables fails!
	nftWrapper.failNFT = true
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
		t.Fatalf("expected commit 2 to fail on ApplyNFTables")
	}
	if !res2.RolledBack || res2.FailedStage != "net" || res2.AppliedSHA != sha1 {
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

	// Retry Commit 2 once ApplyNFTables succeeds -> frigate is cleanly pruned
	nftWrapper.failNFT = false
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

func (c *cancelOnStartSystemd) ActiveState(ctx context.Context, scope, unit string) (string, error) {
	if !c.inRollback && ctx.Err() != nil {
		c.inRollback = true
		return "", ctx.Err()
	}
	return c.Systemd.ActiveState(ctx, scope, unit)
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
		if call.op != "active-state" {
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

func TestReconcileStoppedOutboundGuardUnitDoesNotFailOrDrift(t *testing.T) {
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
outbound_guard = true
`),
		"components/open-webui/open-webui.container.tmpl": []byte("[Container]\nImage=ghcr.io/open-webui/open-webui:v1\nNetwork={{ .Net.PastaArgs }}\n"),
	})
	sha1 := env.commitRepo("commit 1: guarded unit")

	res1, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("commit 1 failed: %v", err)
	}
	if res1.AppliedSHA != sha1 {
		t.Fatalf("AppliedSHA = %q, want %q", res1.AppliedSHA, sha1)
	}
	if env.netRunner.nftTable == "" {
		t.Fatalf("expected table inet quadmatic created after commit 1")
	}

	// Manually stop the unit on the host -> cgroupv2 directory disappears, leaving numeric inode in nft list output.
	env.systemd.states["openwebui/open-webui.service"] = "inactive"
	env.netRunner.nftTable = strings.ReplaceAll(
		env.netRunner.nftTable,
		`"user.slice/user-2001.slice/user@2001.service/app.slice/open-webui.service"`,
		`987654321`,
	)
	env.systemd.clearCalls()
	env.netRunner.clearCalls()

	// Next tick cleans stale table inet quadmatic cleanly without failing ApplyNFTables, rolling back, or restarting stopped unit.
	res2, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("reconcile on manually stopped outbound_guard unit failed: %v", err)
	}
	if res2.RolledBack || res2.AppliedSHA != sha1 {
		t.Fatalf("unexpected rollback/SHA on stopped unit: %+v", res2)
	}
	if env.netRunner.nftTable != "" {
		t.Fatalf("expected stale table inet quadmatic deleted, got:\n%s", env.netRunner.nftTable)
	}
	if env.systemd.countCalls("start", "openwebui", "open-webui.service") != 0 ||
		env.systemd.countCalls("restart", "openwebui", "open-webui.service") != 0 {
		t.Fatalf("manually stopped unit must not be started/restarted, calls=%v", env.systemd.calls)
	}
	wantFailed := []apply.UnitStatus{{Scope: "openwebui", Unit: "open-webui.service", ActiveState: "inactive"}}
	if !reflect.DeepEqual(res2.FailedUnits, wantFailed) {
		t.Fatalf("FailedUnits = %+v, want %+v", res2.FailedUnits, wantFailed)
	}

	// Following tick while unit remains stopped reports zero drift and performs zero mutations.
	env.systemd.clearCalls()
	env.netRunner.clearCalls()
	res3, err := env.engine.Reconcile(context.Background(), env.reconcileOpts(100*time.Millisecond))
	if err != nil {
		t.Fatalf("subsequent reconcile on stopped unit failed: %v", err)
	}
	if res3.DriftDetected || res3.RolledBack {
		t.Fatalf("expected no perpetual drift or rollback, got %+v", res3)
	}
	if !reflect.DeepEqual(res3.FailedUnits, wantFailed) {
		t.Fatalf("FailedUnits = %+v, want %+v", res3.FailedUnits, wantFailed)
	}
	for _, call := range env.systemd.calls {
		if call.op != "active-state" {
			t.Fatalf("expected zero mutating systemd calls on steady stopped unit, got %v", env.systemd.calls)
		}
	}
	for _, call := range env.netRunner.calls {
		if strings.HasPrefix(call, "nft -f") || strings.HasPrefix(call, "nft delete") {
			t.Fatalf("expected zero mutating nft calls on steady stopped unit, got %v", env.netRunner.calls)
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
