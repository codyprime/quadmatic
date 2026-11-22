package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"quadmatic/pkg/users"
)

var quadletExtensions = []string{
	".container",
	".pod",
	".volume",
	".network",
	".kube",
	".image",
}

type rawVars map[string]any

func (r *rawVars) UnmarshalTOML(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("vars must be a table, got %T", v)
	}
	*r = cloneAnyMap(m)
	return nil
}

type rawPortValue struct {
	shorthand bool
	port      *int
	protocol  *string
	hostIP    *string
}

func (p *rawPortValue) UnmarshalTOML(v any) error {
	switch val := v.(type) {
	case int64:
		n := int(val)
		p.shorthand = true
		p.port = &n
		return nil
	case map[string]any:
		for _, k := range sortedMapKeys(val) {
			fieldVal := val[k]
			switch k {
			case "port":
				n, ok := fieldVal.(int64)
				if !ok {
					return fmt.Errorf("field %q must be an integer", k)
				}
				port := int(n)
				p.port = &port
			case "protocol":
				s, ok := fieldVal.(string)
				if !ok {
					return fmt.Errorf("field %q must be a string", k)
				}
				proto := strings.ToLower(s)
				p.protocol = &proto
			case "host_ip":
				s, ok := fieldVal.(string)
				if !ok {
					return fmt.Errorf("field %q must be a string", k)
				}
				ip := s
				p.hostIP = &ip
			default:
				return fmt.Errorf("unknown field %q", k)
			}
		}
		return nil
	default:
		return fmt.Errorf("must be an integer or table, got %T", v)
	}
}

type rawHostManifest struct {
	Hostname   string             `toml:"hostname"`
	Vars       rawVars            `toml:"vars"`
	Components []rawHostComponent `toml:"component"`
}

type rawHostComponent struct {
	Name    string                  `toml:"name"`
	User    string                  `toml:"user"`
	Rootful bool                    `toml:"rootful"`
	Reason  string                  `toml:"reason"`
	Vars    rawVars                 `toml:"vars"`
	Ports   map[string]rawPortValue `toml:"ports"`
	Network *rawNetworkSpec         `toml:"network"`
}

type rawComponentManifest struct {
	Vars    rawVars                    `toml:"vars"`
	Ports   map[string]rawPortValue    `toml:"ports"`
	Network *rawNetworkSpec            `toml:"network"`
	Secrets map[string]string          `toml:"secrets"`
	Files   map[string]rawFileOverride `toml:"files"`
}

type rawNetworkSpec struct {
	VLAN          *int      `toml:"vlan"`
	MAC           *string   `toml:"mac"`
	MacvlanMode   *string   `toml:"macvlan_mode"`
	DNS           *[]string `toml:"dns"`
	DNSFromDHCP   *bool     `toml:"dns_from_dhcp"`
	TCPPorts      *[]string `toml:"tcp_ports"`
	UDPPorts      *[]string `toml:"udp_ports"`
	IPv6          *bool     `toml:"ipv6"`
	OutboundGuard *bool     `toml:"outbound_guard"`
}

type rawFileOverride struct {
	Mode *string `toml:"mode"`
}

// LoadHost reads hosts/<hostname>.toml and each referenced component's manifest and files,
// merging host-level overrides and resolving user UIDs from reg.
func LoadHost(repoDir, hostname string, reg *users.Registry) (*ResolvedHost, error) {
	if reg == nil {
		return nil, fmt.Errorf("users registry is nil")
	}
	if strings.TrimSpace(repoDir) == "" {
		return nil, fmt.Errorf("repo directory is required")
	}
	if err := validateSimpleName("hostname", hostname); err != nil {
		return nil, err
	}

	hostsDir := filepath.Join(repoDir, "hosts")
	if _, err := os.Lstat(hostsDir); err == nil {
		if err := ensureRealContainment(repoDir, hostsDir); err != nil {
			return nil, fmt.Errorf("hosts directory escapes repo root: %w", err)
		}
	}
	hostPath := filepath.Join(hostsDir, hostname+".toml")
	if err := ensureSubPath(hostsDir, hostPath); err != nil {
		return nil, fmt.Errorf("invalid host path %q: %w", hostname, err)
	}
	if _, err := os.Lstat(hostPath); err == nil {
		if err := ensureRepoAndParentContainment(repoDir, hostsDir, hostPath, fmt.Sprintf("host manifest %q", hostPath)); err != nil {
			return nil, err
		}
	}

	hostBytes, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, fmt.Errorf("read host manifest %q: %w", hostPath, err)
	}

	var rawHost rawHostManifest
	if err := decodeStrictTOML(hostBytes, &rawHost, fmt.Sprintf("host manifest %q", hostname)); err != nil {
		return nil, err
	}
	if rawHost.Hostname != "" && rawHost.Hostname != hostname {
		return nil, fmt.Errorf("host manifest %q declares mismatched hostname %q", hostPath, rawHost.Hostname)
	}

	resolved := &ResolvedHost{
		Hostname:   hostname,
		Vars:       cloneAnyMap(rawHost.Vars),
		Components: make([]ResolvedComponent, 0, len(rawHost.Components)),
		Registry:   reg,
	}

	componentsDir := filepath.Join(repoDir, "components")
	if len(rawHost.Components) > 0 {
		if _, err := os.Lstat(componentsDir); err == nil {
			if err := ensureRealContainment(repoDir, componentsDir); err != nil {
				return nil, fmt.Errorf("components directory escapes repo root: %w", err)
			}
		}
	}
	for _, hc := range rawHost.Components {
		comp, err := loadComponent(repoDir, componentsDir, hc, reg)
		if err != nil {
			return nil, err
		}
		resolved.Components = append(resolved.Components, comp)
	}

	return resolved, nil
}

func loadComponent(repoDir, componentsDir string, hc rawHostComponent, reg *users.Registry) (ResolvedComponent, error) {
	if err := validateSimpleName("component name", hc.Name); err != nil {
		return ResolvedComponent{}, err
	}

	compDir := filepath.Join(componentsDir, hc.Name)
	if err := ensureSubPath(componentsDir, compDir); err != nil {
		return ResolvedComponent{}, fmt.Errorf("invalid component directory %q: %w", hc.Name, err)
	}
	if _, err := os.Lstat(compDir); err == nil {
		if err := ensureRepoAndParentContainment(repoDir, componentsDir, compDir, fmt.Sprintf("component directory %q", hc.Name)); err != nil {
			return ResolvedComponent{}, err
		}
	}
	info, err := os.Stat(compDir)
	if err != nil {
		return ResolvedComponent{}, fmt.Errorf("stat component directory %q: %w", compDir, err)
	}
	if !info.IsDir() {
		return ResolvedComponent{}, fmt.Errorf("component path %q is not a directory", compDir)
	}

	var rawComp rawComponentManifest
	compTOMLPath := filepath.Join(compDir, "component.toml")
	if _, lerr := os.Lstat(compTOMLPath); lerr == nil {
		if err := ensureRepoAndParentContainment(repoDir, compDir, compTOMLPath, fmt.Sprintf("component %q manifest", hc.Name)); err != nil {
			return ResolvedComponent{}, err
		}
		tinfo, err := os.Stat(compTOMLPath)
		if err != nil {
			return ResolvedComponent{}, fmt.Errorf("stat component manifest %q: %w", compTOMLPath, err)
		}
		if !tinfo.Mode().IsRegular() {
			return ResolvedComponent{}, fmt.Errorf("component manifest %q is not a regular file", compTOMLPath)
		}
		compBytes, err := os.ReadFile(compTOMLPath)
		if err != nil {
			return ResolvedComponent{}, fmt.Errorf("read component manifest %q: %w", compTOMLPath, err)
		}
		if err := decodeStrictTOML(compBytes, &rawComp, fmt.Sprintf("component %q manifest", hc.Name)); err != nil {
			return ResolvedComponent{}, err
		}
	} else if !os.IsNotExist(lerr) {
		return ResolvedComponent{}, fmt.Errorf("lstat component manifest %q: %w", compTOMLPath, lerr)
	}

	vars := mergeAnyMaps(rawComp.Vars, hc.Vars)

	ports := parsePortsMap(rawComp.Ports)
	ports = mergePortsMap(ports, hc.Ports)

	network := mergeNetwork(rawComp.Network, hc.Network)

	secrets := make(map[string]string, len(rawComp.Secrets))
	for k, v := range rawComp.Secrets {
		secrets[k] = v
	}

	overrides := make(map[string]FileOverride, len(rawComp.Files))
	for k, v := range rawComp.Files {
		var mode string
		if v.Mode != nil {
			mode = *v.Mode
		}
		overrides[k] = FileOverride{Mode: mode}
	}

	quadlets, err := collectQuadletFiles(repoDir, compDir)
	if err != nil {
		return ResolvedComponent{}, fmt.Errorf("collect quadlets for component %q: %w", hc.Name, err)
	}
	dataFiles, err := collectDataFiles(repoDir, compDir)
	if err != nil {
		return ResolvedComponent{}, fmt.Errorf("collect data files for component %q: %w", hc.Name, err)
	}

	var uid int
	var dataDir string
	if hc.Rootful {
		dataDir = path.Join(rootfulDataDirBase, hc.Name)
	} else if hc.User != "" {
		if spec, ok := reg.Users[hc.User]; ok {
			uid = spec.UID
			dataDir = path.Join(rootlessHomeBase, hc.User, ".config", "quadmatic", hc.Name)
		}
	}

	return ResolvedComponent{
		Name:          hc.Name,
		User:          hc.User,
		UID:           uid,
		Rootful:       hc.Rootful,
		Reason:        hc.Reason,
		DataDir:       dataDir,
		Vars:          vars,
		Ports:         ports,
		Network:       network,
		Secrets:       secrets,
		FileOverrides: overrides,
		QuadletFiles:  quadlets,
		DataFiles:     dataFiles,
	}, nil
}

func decodeStrictTOML(data []byte, dst any, label string) error {
	md, err := toml.Decode(string(data), dst)
	if err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return fmt.Errorf("unknown key(s) in %s: %s", label, strings.Join(keys, ", "))
	}
	return nil
}

func parsePortsMap(raw map[string]rawPortValue) map[string]PortSpec {
	out := make(map[string]PortSpec, len(raw))
	for _, name := range sortedMapKeys(raw) {
		out[name] = resolvePortValue(raw[name], nil)
	}
	return out
}

func mergePortsMap(base map[string]PortSpec, overrides map[string]rawPortValue) map[string]PortSpec {
	out := make(map[string]PortSpec, len(base)+len(overrides))
	for k, v := range base {
		out[k] = v
	}
	for _, name := range sortedMapKeys(overrides) {
		var prev *PortSpec
		if existing, ok := out[name]; ok {
			copySpec := existing
			prev = &copySpec
		}
		out[name] = resolvePortValue(overrides[name], prev)
	}
	return out
}

func resolvePortValue(v rawPortValue, base *PortSpec) PortSpec {
	if v.shorthand {
		var port int
		if v.port != nil {
			port = *v.port
		}
		return PortSpec{
			Port:     port,
			Protocol: defaultProtocol,
			HostIP:   defaultHostIP,
		}
	}
	spec := PortSpec{
		Protocol: defaultProtocol,
		HostIP:   defaultHostIP,
	}
	if base != nil {
		spec = *base
	}
	if v.port != nil {
		spec.Port = *v.port
	}
	if v.protocol != nil {
		if *v.protocol == "" {
			spec.Protocol = defaultProtocol
		} else {
			spec.Protocol = *v.protocol
		}
	}
	if v.hostIP != nil {
		if *v.hostIP == "" {
			spec.HostIP = defaultHostIP
		} else {
			spec.HostIP = *v.hostIP
		}
	}
	return spec
}

func mergeNetwork(base, override *rawNetworkSpec) *NetworkSpec {
	if base == nil && override == nil {
		return nil
	}
	merged := &NetworkSpec{}
	applyRawNetwork(merged, base)
	applyRawNetwork(merged, override)
	if override != nil {
		if override.DNS != nil && len(*override.DNS) > 0 && override.DNSFromDHCP == nil {
			merged.DNSFromDHCP = false
		}
		if override.DNSFromDHCP != nil && *override.DNSFromDHCP && override.DNS == nil {
			merged.DNS = nil
		}
	}
	if merged.MacvlanMode == "" {
		merged.MacvlanMode = defaultMacvlanMode
	}
	if merged.OutboundGuard == nil {
		guard := true
		merged.OutboundGuard = &guard
	}
	return merged
}

func applyRawNetwork(dst *NetworkSpec, src *rawNetworkSpec) {
	if src == nil {
		return
	}
	if src.VLAN != nil {
		dst.VLAN = *src.VLAN
	}
	if src.MAC != nil {
		dst.MAC = *src.MAC
	}
	if src.MacvlanMode != nil {
		dst.MacvlanMode = *src.MacvlanMode
	}
	if src.DNS != nil {
		dst.DNS = append([]string(nil), (*src.DNS)...)
	}
	if src.DNSFromDHCP != nil {
		dst.DNSFromDHCP = *src.DNSFromDHCP
	}
	if src.TCPPorts != nil {
		dst.TCPPorts = append([]string(nil), (*src.TCPPorts)...)
	}
	if src.UDPPorts != nil {
		dst.UDPPorts = append([]string(nil), (*src.UDPPorts)...)
	}
	if src.IPv6 != nil {
		dst.IPv6 = *src.IPv6
	}
	if src.OutboundGuard != nil {
		v := *src.OutboundGuard
		dst.OutboundGuard = &v
	}
}

func collectQuadletFiles(repoDir, compDir string) ([]SourceFile, error) {
	entries, err := os.ReadDir(compDir)
	if err != nil {
		return nil, err
	}
	var out []SourceFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		rel, isTmpl, ok := parseQuadletFilename(name)
		if !ok {
			continue
		}
		absPath := filepath.Join(compDir, name)
		content, err := readContainedFile(repoDir, compDir, absPath, entry.Type()&os.ModeSymlink != 0)
		if err != nil {
			return nil, fmt.Errorf("read quadlet %q: %w", name, err)
		}
		out = append(out, SourceFile{
			RelPath:       rel,
			SourceRelPath: name,
			SourceAbsPath: absPath,
			Content:       content,
			IsTemplate:    isTmpl,
		})
	}
	sortSourceFiles(out)
	return out, nil
}

func collectDataFiles(repoDir, compDir string) ([]SourceFile, error) {
	filesDir := filepath.Join(compDir, "files")
	info, err := os.Lstat(filesDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("files path %q must be a real directory", filesDir)
	}
	if err := ensureRealContainment(repoDir, filesDir); err != nil {
		return nil, fmt.Errorf("files directory %q escapes repo root: %w", filesDir, err)
	}

	var out []SourceFile
	err = filepath.WalkDir(filesDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		relFromFiles, err := filepath.Rel(filesDir, p)
		if err != nil {
			return err
		}
		slashRel := filepath.ToSlash(relFromFiles)
		isTmpl := strings.HasSuffix(slashRel, ".tmpl")
		renderedRel := slashRel
		if isTmpl {
			renderedRel = strings.TrimSuffix(slashRel, ".tmpl")
		}
		content, err := readContainedFile(repoDir, filesDir, p, d.Type()&os.ModeSymlink != 0)
		if err != nil {
			return fmt.Errorf("read data file %q: %w", slashRel, err)
		}
		out = append(out, SourceFile{
			RelPath:       renderedRel,
			SourceRelPath: slashRel,
			SourceAbsPath: p,
			Content:       content,
			IsTemplate:    isTmpl,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortSourceFiles(out)
	return out, nil
}

// readContainedFile avoids reading outside repoDir/baseDir if a symlink escapes; escaping
// symlinks return nil content here so Validate can reject them with a path-traversal error.
func readContainedFile(repoDir, baseDir, filePath string, isSymlink bool) ([]byte, error) {
	if isSymlink {
		if err := ensureRealContainment(repoDir, filePath); err != nil {
			return nil, nil
		}
		if err := ensureRealContainment(baseDir, filePath); err != nil {
			return nil, nil
		}
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file %q is not a regular file", filePath)
	}
	return os.ReadFile(filePath)
}

func parseQuadletFilename(name string) (rendered string, isTemplate bool, ok bool) {
	base := name
	if strings.HasSuffix(name, ".tmpl") {
		isTemplate = true
		base = strings.TrimSuffix(name, ".tmpl")
	}
	for _, ext := range quadletExtensions {
		if strings.HasSuffix(base, ext) && len(base) > len(ext) {
			return base, isTemplate, true
		}
	}
	return "", false, false
}

func sortSourceFiles(files []SourceFile) {
	sort.Slice(files, func(i, j int) bool {
		if files[i].RelPath != files[j].RelPath {
			return files[i].RelPath < files[j].RelPath
		}
		return files[i].SourceRelPath < files[j].SourceRelPath
	})
}

func cloneAnyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func mergeAnyMaps(base, override map[string]any) map[string]any {
	out := cloneAnyMap(base)
	for k, v := range override {
		out[k] = v
	}
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
