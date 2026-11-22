package manifest

import (
	"io/fs"

	"quadmatic/pkg/users"
)

const (
	// FileKindQuadlet identifies a rendered systemd quadlet unit file.
	FileKindQuadlet = "quadlet"
	// FileKindData identifies a rendered component data/configuration file.
	FileKindData = "data"

	// PlaceholderDNS is the RFC 5737 TEST-NET-1 DNS placeholder used during dry-run
	// when a component enables dns_from_dhcp before a live lease exists.
	PlaceholderDNS = "192.0.2.53"

	defaultHostIP      = "0.0.0.0"
	defaultProtocol    = "tcp"
	defaultMacvlanMode = "private"

	quadletFileMode fs.FileMode = 0o644
	defaultDataMode fs.FileMode = 0o640

	rootlessQuadletDir = "/etc/containers/systemd/users"
	rootfulQuadletDir  = "/etc/containers/systemd"
	rootfulDataDirBase = "/etc/quadmatic/data"
	rootlessHomeBase   = "/var/home"
)

// PortSpec describes a default-VRF host-published port declared by a component.
type PortSpec struct {
	Port     int
	Protocol string
	HostIP   string
}

// NetworkSpec configures an optional dedicated virtual network (VLAN + VRF + macvlan)
// for a component.
type NetworkSpec struct {
	VLAN          int      `toml:"vlan"`
	MAC           string   `toml:"mac"`
	MacvlanMode   string   `toml:"macvlan_mode"`
	DNS           []string `toml:"dns"`
	DNSFromDHCP   bool     `toml:"dns_from_dhcp"`
	TCPPorts      []string `toml:"tcp_ports"`
	UDPPorts      []string `toml:"udp_ports"`
	IPv6          bool     `toml:"ipv6"`
	OutboundGuard *bool    `toml:"outbound_guard"`
}

// FileOverride specifies metadata overrides for a file under components/<name>/files/.
type FileOverride struct {
	Mode string `toml:"mode"`
}

// SourceFile represents a collected quadlet or data file prior to template rendering.
type SourceFile struct {
	RelPath       string
	SourceRelPath string
	SourceAbsPath string
	Content       []byte
	IsTemplate    bool
}

// ResolvedComponent holds the merged host + component configuration for a single component.
type ResolvedComponent struct {
	Name          string
	User          string
	UID           int
	Rootful       bool
	Reason        string
	DataDir       string
	Vars          map[string]any
	Ports         map[string]PortSpec
	Network       *NetworkSpec
	Secrets       map[string]string
	FileOverrides map[string]FileOverride
	QuadletFiles  []SourceFile
	DataFiles     []SourceFile
}

// Scope returns "rootful" for rootful components or the Linux username for rootless ones.
func (c ResolvedComponent) Scope() string {
	if c.Rootful {
		return "rootful"
	}
	return c.User
}

// ResolvedHost holds the parsed host manifest, merged components, and user registry.
type ResolvedHost struct {
	Hostname   string
	Vars       map[string]any
	Components []ResolvedComponent
	Registry   *users.Registry
}

// RenderEnv supplies runtime/environment inputs needed when rendering templates.
type RenderEnv struct {
	LiveDNS      map[string][]string
	ParentIfaces map[int]string
	DryRun       bool
}

// RenderedFile represents a single rendered quadlet or data file ready for installation.
type RenderedFile struct {
	RelPath  string
	DestPath string
	Kind     string
	Content  []byte
	Mode     fs.FileMode
	OwnerUID int
	OwnerGID int
	SHA256   string
}

// RenderedComponent holds all rendered files and resolved metadata for one component.
type RenderedComponent struct {
	Name               string
	User               string
	UID                int
	Rootful            bool
	DataDir            string
	Vars               map[string]any
	Ports              map[string]PortSpec
	Network            *NetworkSpec
	Net                *NetContext
	Secrets            map[string]string
	Files              []RenderedFile
	UsedPlaceholderDNS bool
}

// Scope returns "rootful" for rootful components or the Linux username for rootless ones.
func (c RenderedComponent) Scope() string {
	if c.Rootful {
		return "rootful"
	}
	return c.User
}

// RenderedHost holds all rendered components for a host.
type RenderedHost struct {
	Hostname           string
	Vars               map[string]any
	Components         []RenderedComponent
	UsedPlaceholderDNS bool
}

// NetContext exposes resolved virtual-network variables to templates under .Net.
type NetContext struct {
	Interface       string
	VRF             string
	ParentInterface string
	VLAN            int
	MAC             string
	DNS             []string
	PastaArgs       string
}

// ComponentContext exposes resolved component metadata to templates under .Component
// and .Host.Components[<name>].
type ComponentContext struct {
	Name    string
	User    string
	UID     int
	Rootful bool
	Vars    map[string]any
	Ports   map[string]PortSpec
	DataDir string
	Network *NetworkSpec
	Net     *NetContext
}

// HostContext exposes host-level variables and resolved components under .Host.
type HostContext struct {
	Hostname   string
	Vars       map[string]any
	Components map[string]ComponentContext
}

// TemplateContext is the root data object passed to Go text/template execution.
type TemplateContext struct {
	Host      HostContext
	Component ComponentContext
	Net       *NetContext
}
