package manifest

import (
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type portBinding struct {
	component string
	portName  string
	addr      netip.Addr
	port      int
	protocol  string
}

// Validate enforces all static manifest constraints (users, rootful reason, default-VRF
// port collisions, MAC/VLAN/DNS network rules, quadlet/data filename collisions, and
// strict repository/component containment for secrets and file overrides) before any host mutation.
func Validate(host *ResolvedHost, repoDir string) error {
	if host == nil {
		return fmt.Errorf("resolved host is nil")
	}
	if err := validateSimpleName("hostname", host.Hostname); err != nil {
		return err
	}
	if strings.TrimSpace(repoDir) == "" {
		return fmt.Errorf("repo directory is required")
	}
	realRepoDir, err := resolveBaseDir(repoDir)
	if err != nil {
		return fmt.Errorf("resolve repo directory %q: %w", repoDir, err)
	}

	seenComponents := make(map[string]bool, len(host.Components))
	seenMACs := make(map[string]string)
	networkUsers := make(map[string]string)
	scopeQuadlets := make(map[string]map[string]string)
	var defaultVRFPorts []portBinding

	for _, comp := range host.Components {
		if err := validateSimpleName("component name", comp.Name); err != nil {
			return err
		}
		if seenComponents[comp.Name] {
			return fmt.Errorf("duplicate component %q on host %q", comp.Name, host.Hostname)
		}
		seenComponents[comp.Name] = true

		if err := validateComponentIdentity(host, comp); err != nil {
			return err
		}

		bindings, err := validateComponentPorts(comp)
		if err != nil {
			return err
		}
		if comp.Network == nil {
			for _, b := range bindings {
				for _, prev := range defaultVRFPorts {
					if portsCollide(prev, b) {
						return fmt.Errorf(
							"default-VRF port collision on %d/%s between %s.%s (%s) and %s.%s (%s)",
							b.port, b.protocol,
							prev.component, prev.portName, prev.addr,
							b.component, b.portName, b.addr,
						)
					}
				}
				defaultVRFPorts = append(defaultVRFPorts, b)
			}
		} else {
			if err := validateComponentNetwork(comp, seenMACs, networkUsers); err != nil {
				return err
			}
		}

		if err := validateComponentSecrets(realRepoDir, comp); err != nil {
			return err
		}
		if err := validateComponentFiles(realRepoDir, comp, scopeQuadlets); err != nil {
			return err
		}
	}

	return nil
}

func validateComponentIdentity(host *ResolvedHost, comp ResolvedComponent) error {
	if comp.Rootful {
		if strings.TrimSpace(comp.Reason) == "" {
			return fmt.Errorf("rootful component %q requires a non-empty reason", comp.Name)
		}
		if comp.User != "" {
			return fmt.Errorf("rootful component %q must not set user %q", comp.Name, comp.User)
		}
		if comp.UID != 0 {
			return fmt.Errorf("rootful component %q must have UID 0, got %d", comp.Name, comp.UID)
		}
		return nil
	}

	if comp.User == "" {
		return fmt.Errorf("rootless component %q must specify user", comp.Name)
	}
	if comp.User == "rootful" {
		return fmt.Errorf("component %q user %q is reserved", comp.Name, comp.User)
	}
	if err := validateSimpleName("user", comp.User); err != nil {
		return fmt.Errorf("component %q: %w", comp.Name, err)
	}
	if host.Registry != nil {
		spec, ok := host.Registry.Users[comp.User]
		if !ok {
			return fmt.Errorf("component %q user %q not found in users registry", comp.Name, comp.User)
		}
		if spec.UID != comp.UID {
			return fmt.Errorf("component %q user %q UID %d does not match registry UID %d", comp.Name, comp.User, comp.UID, spec.UID)
		}
	}
	if comp.UID < 1000 {
		return fmt.Errorf("rootless component %q user %q UID %d must be >= 1000", comp.Name, comp.User, comp.UID)
	}
	return nil
}

func validateComponentPorts(comp ResolvedComponent) ([]portBinding, error) {
	bindings := make([]portBinding, 0, len(comp.Ports))
	for _, portName := range sortedMapKeys(comp.Ports) {
		ps := comp.Ports[portName]
		if ps.Port < 1 || ps.Port > 65535 {
			return nil, fmt.Errorf("component %q port %q value %d must be between 1 and 65535", comp.Name, portName, ps.Port)
		}
		proto := strings.ToLower(ps.Protocol)
		if proto == "" {
			proto = defaultProtocol
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("component %q port %q has unsupported protocol %q (must be tcp or udp)", comp.Name, portName, ps.Protocol)
		}
		hostIP := ps.HostIP
		if hostIP == "" {
			hostIP = defaultHostIP
		}
		addr, err := netip.ParseAddr(hostIP)
		if err != nil {
			return nil, fmt.Errorf("component %q port %q invalid host_ip %q: %w", comp.Name, portName, hostIP, err)
		}
		bindings = append(bindings, portBinding{
			component: comp.Name,
			portName:  portName,
			addr:      addr.Unmap(),
			port:      ps.Port,
			protocol:  proto,
		})
	}
	return bindings, nil
}

func portsCollide(a, b portBinding) bool {
	if a.port != b.port || a.protocol != b.protocol {
		return false
	}
	if a.addr == b.addr {
		return true
	}
	// IPv6 wildcard :: typically accepts both IPv6 and IPv4 on Linux dual-stack sockets;
	// IPv4 0.0.0.0 collides with any IPv4 address.
	if a.addr.Is6() && a.addr.IsUnspecified() || b.addr.Is6() && b.addr.IsUnspecified() {
		return true
	}
	if a.addr.Is4() && b.addr.Is4() && (a.addr.IsUnspecified() || b.addr.IsUnspecified()) {
		return true
	}
	return false
}

func validateComponentNetwork(comp ResolvedComponent, seenMACs, networkUsers map[string]string) error {
	netSpec := comp.Network
	if netSpec.VLAN < 0 || netSpec.VLAN > 4094 {
		return fmt.Errorf("component %q invalid VLAN %d (must be 0..4094)", comp.Name, netSpec.VLAN)
	}
	if netSpec.MacvlanMode != "" && netSpec.MacvlanMode != "private" && netSpec.MacvlanMode != "bridge" {
		return fmt.Errorf("component %q invalid macvlan_mode %q (must be private or bridge)", comp.Name, netSpec.MacvlanMode)
	}
	if strings.TrimSpace(netSpec.MAC) == "" {
		return fmt.Errorf("component %q network requires a MAC address", comp.Name)
	}
	hw, err := net.ParseMAC(netSpec.MAC)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("component %q invalid Ethernet MAC %q", comp.Name, netSpec.MAC)
	}
	if isAllZeroMAC(hw) {
		return fmt.Errorf("component %q invalid all-zero MAC %q", comp.Name, netSpec.MAC)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("component %q MAC %q must be unicast (multicast bit is set)", comp.Name, netSpec.MAC)
	}
	normMAC := strings.ToLower(hw.String())
	if prevComp, dup := seenMACs[normMAC]; dup {
		return fmt.Errorf("duplicate MAC %q shared by components %q and %q", normMAC, prevComp, comp.Name)
	}
	seenMACs[normMAC] = comp.Name

	for _, dns := range netSpec.DNS {
		if _, err := netip.ParseAddr(dns); err != nil {
			return fmt.Errorf("component %q invalid DNS IP %q: %w", comp.Name, dns, err)
		}
	}
	if err := validatePastaPortList(comp.Name, "tcp_ports", netSpec.TCPPorts); err != nil {
		return err
	}
	if err := validatePastaPortList(comp.Name, "udp_ports", netSpec.UDPPorts); err != nil {
		return err
	}

	if !comp.Rootful {
		if prevComp, dup := networkUsers[comp.User]; dup {
			return fmt.Errorf("rootless user %q may have at most one [component.network] (used by %q and %q)", comp.User, prevComp, comp.Name)
		}
		networkUsers[comp.User] = comp.Name

		if len(fmt.Sprintf("qmv-%d", comp.UID)) > 15 {
			return fmt.Errorf("component %q VRF interface name qmv-%d exceeds 15 characters", comp.Name, comp.UID)
		}
		if len(netSpec.DNS) == 0 && !netSpec.DNSFromDHCP {
			return fmt.Errorf("rootless network component %q must specify dns or dns_from_dhcp = true", comp.Name)
		}
	}
	return nil
}

func validatePastaPortList(compName, field string, specs []string) error {
	for _, spec := range specs {
		if spec == "" || strings.ContainsAny(spec, ",/ \t\r\n") {
			return fmt.Errorf("component %q %s entry %q contains invalid characters", compName, field, spec)
		}
		parts := strings.Split(spec, ":")
		if len(parts) > 2 {
			return fmt.Errorf("component %q %s entry %q must be <port> or <host>:<container>", compName, field, spec)
		}
		for _, part := range parts {
			if err := validatePortOrRange(part); err != nil {
				return fmt.Errorf("component %q %s entry %q: %w", compName, field, spec, err)
			}
		}
	}
	return nil
}

func validatePortOrRange(s string) error {
	bounds := strings.Split(s, "-")
	if len(bounds) > 2 {
		return fmt.Errorf("invalid port range %q", s)
	}
	var prev int
	for i, b := range bounds {
		p, err := strconv.Atoi(b)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port number %q", b)
		}
		if i == 1 && p < prev {
			return fmt.Errorf("descending port range %q", s)
		}
		prev = p
	}
	return nil
}

func validateComponentSecrets(realRepoDir string, comp ResolvedComponent) error {
	for _, secretName := range sortedMapKeys(comp.Secrets) {
		if err := validateSecretName(secretName); err != nil {
			return fmt.Errorf("component %q %w", comp.Name, err)
		}
		relPath := comp.Secrets[secretName]
		if err := validateSafeRelPath(relPath); err != nil {
			return fmt.Errorf("component %q secret %q path %q rejected: %w", comp.Name, secretName, relPath, err)
		}
		joined := filepath.Join(realRepoDir, filepath.FromSlash(relPath))
		if err := ensureSubPath(realRepoDir, joined); err != nil {
			return fmt.Errorf("component %q secret %q escapes repo root: %w", comp.Name, secretName, err)
		}
		if _, lerr := os.Lstat(joined); lerr == nil {
			if err := ensureRealContainment(realRepoDir, joined); err != nil {
				return fmt.Errorf("component %q secret %q escapes repo root via symlink: %w", comp.Name, secretName, err)
			}
		} else if os.IsNotExist(lerr) {
			if err := ensureExistingParentContained(realRepoDir, filepath.Dir(joined)); err != nil {
				return fmt.Errorf("component %q secret %q escapes repo root via symlink: %w", comp.Name, secretName, err)
			}
			return fmt.Errorf("component %q secret %q file %q: %w", comp.Name, secretName, relPath, lerr)
		} else {
			return fmt.Errorf("component %q secret %q file %q: %w", comp.Name, secretName, relPath, lerr)
		}
		info, err := os.Stat(joined)
		if err != nil {
			return fmt.Errorf("component %q secret %q file %q: %w", comp.Name, secretName, relPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("component %q secret %q file %q is not a regular file", comp.Name, secretName, relPath)
		}
	}
	return nil
}

func validateComponentFiles(realRepoDir string, comp ResolvedComponent, scopeQuadlets map[string]map[string]string) error {
	realComponentsDir := filepath.Join(realRepoDir, "components")
	if _, err := os.Lstat(realComponentsDir); err == nil {
		if err := ensureRealContainment(realRepoDir, realComponentsDir); err != nil {
			return fmt.Errorf("components directory escapes repo root: %w", err)
		}
	}
	realCompDir := filepath.Join(realComponentsDir, comp.Name)
	if _, err := os.Lstat(realCompDir); err == nil {
		if err := ensureRepoAndParentContainment(realRepoDir, realComponentsDir, realCompDir, fmt.Sprintf("component %q directory", comp.Name)); err != nil {
			return err
		}
	}
	compTOMLPath := filepath.Join(realCompDir, "component.toml")
	if _, err := os.Lstat(compTOMLPath); err == nil {
		if err := ensureRepoAndParentContainment(realRepoDir, realCompDir, compTOMLPath, fmt.Sprintf("component %q manifest", comp.Name)); err != nil {
			return err
		}
	}
	realFilesDir := filepath.Join(realCompDir, "files")
	if _, err := os.Lstat(realFilesDir); err == nil {
		if err := ensureRepoAndParentContainment(realRepoDir, realCompDir, realFilesDir, fmt.Sprintf("component %q files directory", comp.Name)); err != nil {
			return err
		}
	}

	scope := comp.Scope()
	if scopeQuadlets[scope] == nil {
		scopeQuadlets[scope] = make(map[string]string)
	}
	compQuadlets := make(map[string]bool, len(comp.QuadletFiles))
	for _, qf := range comp.QuadletFiles {
		if err := validateSimpleName("quadlet filename", qf.RelPath); err != nil {
			return fmt.Errorf("component %q: %w", comp.Name, err)
		}
		if err := validateSimpleName("quadlet source filename", qf.SourceRelPath); err != nil {
			return fmt.Errorf("component %q: %w", comp.Name, err)
		}
		if qf.SourceAbsPath != "" {
			if err := ensureRepoAndParentContainment(realRepoDir, realCompDir, qf.SourceAbsPath, fmt.Sprintf("component %q quadlet %q", comp.Name, qf.SourceRelPath)); err != nil {
				return err
			}
		}
		if compQuadlets[qf.RelPath] {
			return fmt.Errorf("component %q has duplicate rendered quadlet %q", comp.Name, qf.RelPath)
		}
		compQuadlets[qf.RelPath] = true

		if prevComp, dup := scopeQuadlets[scope][qf.RelPath]; dup {
			return fmt.Errorf("quadlet filename collision for %q in scope %q between components %q and %q", qf.RelPath, scope, prevComp, comp.Name)
		}
		scopeQuadlets[scope][qf.RelPath] = comp.Name
	}

	compDataByRel := make(map[string]bool, len(comp.DataFiles))
	compDataBySrc := make(map[string]bool, len(comp.DataFiles))
	for _, df := range comp.DataFiles {
		if err := validateSafeRelPath(df.RelPath); err != nil {
			return fmt.Errorf("component %q data file %q: %w", comp.Name, df.RelPath, err)
		}
		if err := validateSafeRelPath(df.SourceRelPath); err != nil {
			return fmt.Errorf("component %q data source file %q: %w", comp.Name, df.SourceRelPath, err)
		}
		if df.SourceAbsPath != "" {
			if err := ensureRepoAndParentContainment(realRepoDir, realFilesDir, df.SourceAbsPath, fmt.Sprintf("component %q data file %q", comp.Name, df.SourceRelPath)); err != nil {
				return err
			}
		}
		if compDataByRel[df.RelPath] {
			return fmt.Errorf("component %q has duplicate rendered data file %q", comp.Name, df.RelPath)
		}
		compDataByRel[df.RelPath] = true
		compDataBySrc[df.SourceRelPath] = true
	}

	matchedRendered := make(map[string]string)
	for _, rel := range sortedMapKeys(comp.FileOverrides) {
		if err := validateSafeRelPath(rel); err != nil {
			return fmt.Errorf("component %q file override %q rejected: %w", comp.Name, rel, err)
		}
		if comp.DataDir != "" {
			if err := ensureSubPath(comp.DataDir, filepath.Join(comp.DataDir, filepath.FromSlash(rel))); err != nil {
				return fmt.Errorf("component %q file override %q escapes data dir: %w", comp.Name, rel, err)
			}
		}
		ov := comp.FileOverrides[rel]
		if ov.Mode != "" {
			if _, err := parseOctalMode(ov.Mode); err != nil {
				return fmt.Errorf("component %q file override %q invalid mode %q: %w", comp.Name, rel, ov.Mode, err)
			}
		}
		if !compDataByRel[rel] && !compDataBySrc[rel] {
			return fmt.Errorf("component %q file override %q does not match any file under components/%s/files", comp.Name, rel, comp.Name)
		}
		targetRel := strings.TrimSuffix(rel, ".tmpl")
		if compDataByRel[rel] {
			targetRel = rel
		}
		if prevKey, dup := matchedRendered[targetRel]; dup {
			return fmt.Errorf("component %q has conflicting file overrides %q and %q for %q", comp.Name, prevKey, rel, targetRel)
		}
		matchedRendered[targetRel] = rel
	}

	return nil
}

func validateSimpleName(kind, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("invalid %s %q", kind, name)
	}
	return nil
}

func validateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name must not be empty")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum && c != '_' {
				return fmt.Errorf("invalid secret name %q: must start with an alphanumeric character or underscore", name)
			}
			continue
		}
		if !isAlphaNum && c != '_' && c != '.' && c != '-' {
			return fmt.Errorf("invalid secret name %q: contains disallowed character %q", name, c)
		}
	}
	return nil
}

func validateSafeRelPath(rel string) error {
	if rel == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.ContainsRune(rel, '\x00') || strings.ContainsRune(rel, '\\') {
		return fmt.Errorf("path %q contains forbidden characters", rel)
	}
	if strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) {
		return fmt.Errorf("path %q must be relative", rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("path %q contains invalid segment %q", rel, seg)
		}
	}
	return nil
}

func resolveBaseDir(dir string) (string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if realDir, err := filepath.EvalSymlinks(absDir); err == nil {
		return realDir, nil
	}
	return absDir, nil
}

func ensureSubPath(baseDir, targetPath string) error {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%q is outside %q", targetPath, baseDir)
	}
	return nil
}

func ensureRealContainment(baseDir, targetPath string) error {
	realBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return err
	}
	realTarget, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return err
	}
	return ensureSubPath(realBase, realTarget)
}

func ensureRepoAndParentContainment(repoDir, parentDir, targetPath, label string) error {
	if err := ensureRealContainment(repoDir, targetPath); err != nil {
		return fmt.Errorf("%s escapes repo root: %w", label, err)
	}
	if err := ensureRealContainment(parentDir, targetPath); err != nil {
		return fmt.Errorf("%s escapes parent directory: %w", label, err)
	}
	return nil
}

func ensureExistingParentContained(realRepoDir, dir string) error {
	cur := filepath.Clean(dir)
	for {
		if cur == realRepoDir {
			return nil
		}
		if _, err := os.Lstat(cur); err == nil {
			return ensureRealContainment(realRepoDir, cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

func parseOctalMode(raw string) (fs.FileMode, error) {
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil || v > 0o777 {
		return 0, fmt.Errorf("mode must be an octal permission in 0000..0777")
	}
	return fs.FileMode(v), nil
}

func isAllZeroMAC(hw net.HardwareAddr) bool {
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}
