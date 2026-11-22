package manifest

import (
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"
	"text/template"

	"quadmatic/internal/hashutil"
)

// RenderHost renders all component quadlet and data templates using Go text/template
// with Option("missingkey=error"), resolves .Net metadata and .Net.PastaArgs, and
// builds destination paths, file modes, ownership, and SHA-256 digests.
func RenderHost(host *ResolvedHost, env RenderEnv) (*RenderedHost, error) {
	if host == nil {
		return nil, fmt.Errorf("resolved host is nil")
	}

	hostCtx := HostContext{
		Hostname:   host.Hostname,
		Vars:       cloneAnyMap(host.Vars),
		Components: make(map[string]ComponentContext, len(host.Components)),
	}

	compContexts := make([]ComponentContext, len(host.Components))
	compPlaceholder := make([]bool, len(host.Components))
	anyPlaceholder := false

	// Build complete .Host.Components metadata before executing templates so cross-component
	// references (e.g., Caddy upstream templates) see every component regardless of manifest order.
	for i, comp := range host.Components {
		netCtx, usedPlaceholder, err := buildNetContext(comp, env)
		if err != nil {
			return nil, err
		}
		if usedPlaceholder {
			anyPlaceholder = true
			compPlaceholder[i] = true
		}

		cc := ComponentContext{
			Name:    comp.Name,
			User:    comp.User,
			UID:     comp.UID,
			Rootful: comp.Rootful,
			Vars:    cloneAnyMap(comp.Vars),
			Ports:   clonePortsMap(comp.Ports),
			DataDir: comp.DataDir,
			Network: cloneNetworkSpec(comp.Network),
			Net:     netCtx,
		}
		compContexts[i] = cc
		hostCtx.Components[comp.Name] = cc
	}

	rendered := &RenderedHost{
		Hostname:           host.Hostname,
		Vars:               cloneAnyMap(host.Vars),
		Components:         make([]RenderedComponent, 0, len(host.Components)),
		UsedPlaceholderDNS: anyPlaceholder,
	}

	for i, comp := range host.Components {
		cc := compContexts[i]
		tmplCtx := TemplateContext{
			Host:      hostCtx,
			Component: cc,
			Net:       cc.Net,
		}

		files := make([]RenderedFile, 0, len(comp.QuadletFiles)+len(comp.DataFiles))
		quadletDestDir := rootfulQuadletDir
		if !comp.Rootful {
			quadletDestDir = path.Join(rootlessQuadletDir, strconv.Itoa(comp.UID))
		}

		for _, qf := range comp.QuadletFiles {
			content, err := renderSourceFile(comp.Name, qf, tmplCtx)
			if err != nil {
				return nil, err
			}
			files = append(files, RenderedFile{
				RelPath:  qf.RelPath,
				DestPath: path.Join(quadletDestDir, qf.RelPath),
				Kind:     FileKindQuadlet,
				Content:  content,
				Mode:     quadletFileMode,
				OwnerUID: 0,
				OwnerGID: 0,
				SHA256:   hashutil.SHA256Hex(content),
			})
		}

		ownerUID, ownerGID := 0, 0
		if !comp.Rootful {
			ownerUID, ownerGID = comp.UID, comp.UID
			if gid, ok := env.UserGIDs[comp.User]; ok {
				ownerGID = gid
			}
		}
		for _, df := range comp.DataFiles {
			content, err := renderSourceFile(comp.Name, df, tmplCtx)
			if err != nil {
				return nil, err
			}
			mode := defaultDataMode
			if ov, ok := lookupFileOverride(comp.FileOverrides, df); ok && ov.Mode != "" {
				parsed, err := parseOctalMode(ov.Mode)
				if err != nil {
					return nil, fmt.Errorf("component %q file %q invalid mode %q: %w", comp.Name, df.RelPath, ov.Mode, err)
				}
				mode = parsed
			}
			files = append(files, RenderedFile{
				RelPath:  df.RelPath,
				DestPath: path.Join(comp.DataDir, df.RelPath),
				Kind:     FileKindData,
				Content:  content,
				Mode:     mode,
				OwnerUID: ownerUID,
				OwnerGID: ownerGID,
				SHA256:   hashutil.SHA256Hex(content),
			})
		}

		rendered.Components = append(rendered.Components, RenderedComponent{
			Name:               comp.Name,
			User:               comp.User,
			UID:                comp.UID,
			Rootful:            comp.Rootful,
			DataDir:            comp.DataDir,
			Vars:               cc.Vars,
			Ports:              cc.Ports,
			Network:            cc.Network,
			Net:                cc.Net,
			Secrets:            cloneStringMap(comp.Secrets),
			Files:              files,
			UsedPlaceholderDNS: compPlaceholder[i],
		})
	}

	return rendered, nil
}

// BuildPastaArgs constructs the hardened Network=pasta:... value for a rootless
// virtual-network component attached to iface.
func BuildPastaArgs(iface string, net *NetworkSpec) string {
	if net == nil {
		return ""
	}
	args := []string{
		"--no-map-gw",
		"--map-host-loopback",
		"none",
	}
	if !net.IPv6 {
		args = append(args, "--ipv4-only")
	}
	args = append(args, "-i", iface, "--outbound-if4", iface)
	if net.IPv6 {
		args = append(args, "--outbound-if6", iface)
	}
	for _, p := range net.TCPPorts {
		args = append(args, "-t", fmt.Sprintf("%%%s/%s", iface, p))
	}
	for _, p := range net.UDPPorts {
		args = append(args, "-u", fmt.Sprintf("%%%s/%s", iface, p))
	}
	return "pasta:" + strings.Join(args, ",")
}

func buildNetContext(comp ResolvedComponent, env RenderEnv) (*NetContext, bool, error) {
	if comp.Network == nil {
		return nil, false, nil
	}
	netSpec := comp.Network
	parentIface := resolveParentIface(netSpec.VLAN, env.ParentIfaces)

	if comp.Rootful {
		return &NetContext{
			ParentInterface: parentIface,
			VLAN:            netSpec.VLAN,
			MAC:             netSpec.MAC,
			DNS:             append([]string(nil), netSpec.DNS...),
		}, false, nil
	}

	iface := fmt.Sprintf("qm-%d", comp.UID)
	vrf := fmt.Sprintf("qmv-%d", comp.UID)

	var dns []string
	usedPlaceholder := false
	if netSpec.DNSFromDHCP {
		if live := env.LiveDNS[comp.Name]; len(live) > 0 {
			dns = append([]string(nil), live...)
		} else if env.DryRun {
			dns = []string{PlaceholderDNS}
			usedPlaceholder = true
		} else {
			return nil, false, fmt.Errorf("component %q has dns_from_dhcp=true but no live DNS is available", comp.Name)
		}
	} else {
		dns = append([]string(nil), netSpec.DNS...)
	}

	return &NetContext{
		Interface:       iface,
		VRF:             vrf,
		ParentInterface: parentIface,
		VLAN:            netSpec.VLAN,
		MAC:             netSpec.MAC,
		DNS:             dns,
		PastaArgs:       BuildPastaArgs(iface, netSpec),
	}, usedPlaceholder, nil
}

func resolveParentIface(vlan int, parentIfaces map[int]string) string {
	if parentIfaces != nil {
		if iface := parentIfaces[vlan]; iface != "" {
			return iface
		}
	}
	if vlan == 0 {
		return "trunk_interface"
	}
	return fmt.Sprintf("qm-vlan%d", vlan)
}

func renderSourceFile(compName string, sf SourceFile, ctx TemplateContext) ([]byte, error) {
	if !sf.IsTemplate {
		return append([]byte(nil), sf.Content...), nil
	}
	tmpl, err := template.New(sf.SourceRelPath).Option("missingkey=error").Parse(string(sf.Content))
	if err != nil {
		return nil, fmt.Errorf("parse template %s/%s: %w", compName, sf.SourceRelPath, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("execute template %s/%s: %w", compName, sf.SourceRelPath, err)
	}
	return buf.Bytes(), nil
}

func lookupFileOverride(overrides map[string]FileOverride, df SourceFile) (FileOverride, bool) {
	if ov, ok := overrides[df.RelPath]; ok {
		return ov, true
	}
	ov, ok := overrides[df.SourceRelPath]
	return ov, ok
}

func clonePortsMap(src map[string]PortSpec) map[string]PortSpec {
	out := make(map[string]PortSpec, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneNetworkSpec(src *NetworkSpec) *NetworkSpec {
	if src == nil {
		return nil
	}
	cp := *src
	if src.DNS != nil {
		cp.DNS = append([]string(nil), src.DNS...)
	}
	if src.TCPPorts != nil {
		cp.TCPPorts = append([]string(nil), src.TCPPorts...)
	}
	if src.UDPPorts != nil {
		cp.UDPPorts = append([]string(nil), src.UDPPorts...)
	}
	return &cp
}
