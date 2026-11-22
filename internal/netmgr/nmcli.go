package netmgr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"quadmatic/internal/manifest"
	"quadmatic/internal/state"
)

const (
	kindVLAN    = "vlan"
	kindVRF     = "vrf"
	kindMacvlan = "macvlan"
)

var ipLinkVLANIDRe = regexp.MustCompile(`\bid\s+(\d+)\b`)

func isManagedConnectionName(name string) bool {
	return strings.HasPrefix(name, ManagedPrefix) || strings.HasPrefix(name, ManagedVRFPrefix)
}

type unmanagedVLAN struct {
	Device     string
	Connection string
	Parent     string
	VLANID     int
}

type desiredVLAN struct {
	VLAN       int
	ConnName   string
	DeviceName string
	Owned      bool
	Component  string
	Scope      string
}

type desiredRootlessNet struct {
	CompName      string
	Scope         string
	UID           int
	ParentIface   string
	VRFName       string
	TableID       int
	MacvlanName   string
	Mode          string
	MAC           string
	IPv6          bool
	DNSFromDHCP   bool
	OutboundGuard bool
	Units         []string
}

type desiredPlan struct {
	vlans       []desiredVLAN
	rootless    []desiredRootlessNet
	nftTargets  []nftGuardTarget
	parentMap   map[int]string
	hasNetworks bool
}

// ResolveVLANParents maps each requested VLAN ID in host to either an existing unmanaged
// VLAN device on trunk_interface (e.g., "enp3s0.3") or the managed name "qm-vlan<V>".
// When VLAN 0 is requested (attach directly to trunk_interface), it maps 0 -> trunk_interface.
func (r *Reconciler) ResolveVLANParents(ctx context.Context, host *manifest.ResolvedHost) (map[int]string, error) {
	parents, _, err := r.resolveVLANParentsWithInfo(ctx, host)
	return parents, err
}

func (r *Reconciler) resolveVLANParentsWithInfo(ctx context.Context, host *manifest.ResolvedHost) (map[int]string, map[int]unmanagedVLAN, error) {
	if r == nil {
		return nil, nil, errors.New("netmgr reconciler is nil")
	}
	if host == nil {
		return nil, nil, errors.New("resolved host is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	requested, hasNetworks, err := collectRequestedVLANs(host)
	if err != nil {
		return nil, nil, err
	}
	parents := make(map[int]string, len(requested))
	if !hasNetworks {
		return parents, nil, nil
	}
	if err := validateIfName("trunk_interface", r.trunkInterface); err != nil {
		return nil, nil, err
	}

	needLookup := false
	for _, vlan := range requested {
		if vlan == 0 {
			parents[0] = r.trunkInterface
			continue
		}
		needLookup = true
	}
	if !needLookup {
		return parents, nil, nil
	}

	unmanaged, err := r.discoverUnmanagedVLANs(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, vlan := range requested {
		if vlan == 0 {
			continue
		}
		if existing, ok := unmanaged[vlan]; ok {
			parents[vlan] = existing.Device
			continue
		}
		qmName := fmt.Sprintf("qm-vlan%d", vlan)
		if err := validateIfName("vlan interface", qmName); err != nil {
			return nil, nil, err
		}
		parents[vlan] = qmName
	}
	return parents, unmanaged, nil
}

// ReadLiveDNS queries NetworkManager for active IPv4 DNS servers on ifname.
func (r *Reconciler) ReadLiveDNS(ctx context.Context, ifname string) ([]string, error) {
	if r == nil {
		return nil, errors.New("netmgr reconciler is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateIfName("interface", ifname); err != nil {
		return nil, err
	}
	out, err := r.runner.Run(ctx, nil, "nmcli", "-g", "IP4.DNS", "device", "show", ifname)
	if err != nil {
		return nil, formatCmdErr(fmt.Sprintf("nmcli -g IP4.DNS device show %s", ifname), out, err)
	}
	return parseDNSList(string(out)), nil
}

// Snapshot captures all currently owned `qm-*` NetworkManager profiles and the live
// `table inet quadmatic` nftables ruleset prior to mutation.
func (r *Reconciler) Snapshot(ctx context.Context, owned []state.ManagedNetworkRecord) (*Snapshot, error) {
	if r == nil {
		return nil, errors.New("netmgr reconciler is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	snap := &Snapshot{
		Profiles:     make(map[string]string),
		OwnedRecords: slices.Clone(owned),
	}

	seen := make(map[string]bool)
	for _, rec := range owned {
		if !rec.Owned || !isManagedConnectionName(rec.ConnectionName) {
			continue
		}
		if seen[rec.ConnectionName] {
			continue
		}
		seen[rec.ConnectionName] = true
		if err := validateConnName(rec.ConnectionName); err != nil {
			return nil, err
		}

		out, err := r.runner.Run(ctx, nil, "nmcli", "-t", "connection", "show", rec.ConnectionName)
		if err != nil {
			if isNMNotFoundErr(out, err) {
				continue
			}
			return nil, formatCmdErr(fmt.Sprintf("nmcli -t connection show %s", rec.ConnectionName), out, err)
		}
		snap.Profiles[rec.ConnectionName] = string(out)
	}

	ruleset, exists, err := r.readNFTables(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		snap.NFTablesRuleset = ruleset
	}
	return snap, nil
}

// DetectDrift reports whether live NetworkManager profiles, VRF unreachable routes,
// `owned` records, or `table inet quadmatic` diverge from the desired state in host.
func (r *Reconciler) DetectDrift(ctx context.Context, host *manifest.ResolvedHost, owned []state.ManagedNetworkRecord) (bool, error) {
	if r == nil {
		return false, errors.New("netmgr reconciler is nil")
	}
	if host == nil {
		return false, errors.New("resolved host is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	plan, err := r.buildDesiredPlan(ctx, host)
	if err != nil {
		return false, err
	}

	desiredOwnedSet := make(map[string]bool)
	for _, v := range plan.vlans {
		if v.Owned {
			desiredOwnedSet[v.ConnName] = true
		}
	}
	for _, rl := range plan.rootless {
		desiredOwnedSet[rl.VRFName] = true
		desiredOwnedSet[rl.MacvlanName] = true
	}

	liveNames, err := r.listConnectionNames(ctx)
	if err != nil {
		return false, err
	}
	liveSet := make(map[string]bool, len(liveNames))
	for _, name := range liveNames {
		liveSet[name] = true
	}

	recordedOwnedSet := make(map[string]bool)
	for _, rec := range owned {
		if !rec.Owned {
			continue
		}
		if isManagedConnectionName(rec.ConnectionName) && !desiredOwnedSet[rec.ConnectionName] && liveSet[rec.ConnectionName] {
			return true, nil
		}
		recordedOwnedSet[rec.ConnectionName] = true
	}
	for name := range desiredOwnedSet {
		if !recordedOwnedSet[name] {
			return true, nil
		}
	}

	activeConns, err := r.listActiveConnectionNames(ctx)
	if err != nil {
		return false, err
	}

	for _, v := range plan.vlans {
		if !v.Owned {
			continue
		}
		if !activeConns[v.ConnName] {
			return true, nil
		}
		props, exists, err := r.readProfileProps(ctx, v.ConnName)
		if err != nil {
			return false, err
		}
		if !exists || !propsMatch(props, r.desiredVLANProps(v)) {
			return true, nil
		}
	}

	for _, rl := range plan.rootless {
		if !activeConns[rl.VRFName] || !activeConns[rl.MacvlanName] {
			return true, nil
		}
		vrfProps, exists, err := r.readProfileProps(ctx, rl.VRFName)
		if err != nil {
			return false, err
		}
		if !exists || !propsMatch(vrfProps, desiredVRFProps(rl)) {
			return true, nil
		}
		hasRoute, err := r.hasVRFUnreachableRoute(ctx, rl.TableID)
		if err != nil {
			return false, err
		}
		if !hasRoute {
			return true, nil
		}

		mvProps, exists, err := r.readProfileProps(ctx, rl.MacvlanName)
		if err != nil {
			return false, err
		}
		if !exists || !propsMatch(mvProps, desiredMacvlanProps(rl)) {
			return true, nil
		}
	}

	nftDrifted, err := r.hasNFTablesDrift(ctx, plan.nftTargets)
	if err != nil {
		return false, err
	}
	return nftDrifted, nil
}

// ApplyProfiles reconciles VLAN parents, per-component VRFs and macvlans, live DHCP DNS
// polling, and pruning of unreferenced owned profiles without modifying nftables. Even when
// err != nil, newOwned contains all `qm-*`/`qmv-*` profiles created or reconciled up to the
// point of failure so callers can pass them straight to Restore.
func (r *Reconciler) ApplyProfiles(
	ctx context.Context,
	host *manifest.ResolvedHost,
	prevOwned []state.ManagedNetworkRecord,
	dhcpTimeout time.Duration,
) (newOwned []state.ManagedNetworkRecord, liveDNS map[string][]string, err error) {
	if r == nil {
		return nil, nil, errors.New("netmgr reconciler is nil")
	}
	if host == nil {
		return nil, nil, errors.New("resolved host is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	plan, err := r.buildDesiredPlan(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(plan.rootless) > 0 {
		if err := r.CheckKernelInvariants(); err != nil {
			return nil, nil, err
		}
	}

	var activeConns map[string]bool
	if plan.hasNetworks {
		activeConns, err = r.listActiveConnectionNames(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	// Track desired records incrementally so partial failures still return every qm-*/qmv-*
	// profile created or updated up to the failure point.
	newOwned = make([]state.ManagedNetworkRecord, 0, len(plan.vlans)+2*len(plan.rootless))

	for _, v := range plan.vlans {
		if !v.Owned {
			newOwned = append(newOwned, state.ManagedNetworkRecord{
				ConnectionName: v.ConnName,
				Kind:           kindVLAN,
				Owned:          false,
				Component:      v.Component,
				Scope:          v.Scope,
			})
			continue
		}

		desired := r.desiredVLANProps(v)
		mutated, createdNow, err := r.ensureProfile(ctx, v.ConnName, kindVLAN, desired, func() ([]string, error) {
			return vlanAddArgs(v.ConnName, desired), nil
		})
		if createdNow {
			newOwned = append(newOwned, state.ManagedNetworkRecord{
				ConnectionName: v.ConnName,
				Kind:           kindVLAN,
				Owned:          true,
				Component:      v.Component,
				Scope:          v.Scope,
			})
		}
		if err != nil {
			return newOwned, nil, err
		}
		if mutated || !activeConns[v.ConnName] {
			if err := r.upConnection(ctx, v.ConnName); err != nil {
				return newOwned, nil, err
			}
		}
	}

	liveDNS = make(map[string][]string)
	for _, rl := range plan.rootless {
		vrfDesired := desiredVRFProps(rl)
		vrfMutated, vrfPresent, err := r.ensureProfile(ctx, rl.VRFName, kindVRF, vrfDesired, func() ([]string, error) {
			return vrfAddArgs(rl.VRFName, vrfDesired), nil
		})
		if vrfPresent {
			newOwned = append(newOwned, state.ManagedNetworkRecord{
				ConnectionName: rl.VRFName,
				Kind:           kindVRF,
				Owned:          true,
				Component:      rl.CompName,
				Scope:          rl.Scope,
			})
		}
		if err != nil {
			return newOwned, nil, err
		}
		if vrfMutated || !activeConns[rl.VRFName] {
			if err := r.upConnection(ctx, rl.VRFName); err != nil {
				return newOwned, nil, err
			}
		}
		if err := r.ensureVRFUnreachableRoute(ctx, rl.TableID); err != nil {
			return newOwned, nil, err
		}

		mvDesired := desiredMacvlanProps(rl)
		mvMutated, mvPresent, err := r.ensureProfile(ctx, rl.MacvlanName, kindMacvlan, mvDesired, func() ([]string, error) {
			return macvlanAddArgs(rl.MacvlanName, mvDesired), nil
		})
		if mvPresent {
			newOwned = append(newOwned, state.ManagedNetworkRecord{
				ConnectionName: rl.MacvlanName,
				Kind:           kindMacvlan,
				Owned:          true,
				Component:      rl.CompName,
				Scope:          rl.Scope,
			})
		}
		if err != nil {
			return newOwned, nil, err
		}
		if mvMutated || !activeConns[rl.MacvlanName] {
			if err := r.upConnection(ctx, rl.MacvlanName); err != nil {
				return newOwned, nil, err
			}
		}

		if rl.DNSFromDHCP {
			dns, err := r.pollLiveDNS(ctx, rl.MacvlanName, dhcpTimeout)
			if err != nil {
				return newOwned, nil, fmt.Errorf("component %q (%s): %w", rl.CompName, rl.MacvlanName, err)
			}
			liveDNS[rl.CompName] = dns
		}
	}

	if err := r.pruneUnreferenced(ctx, prevOwned, newOwned); err != nil {
		return newOwned, nil, err
	}

	return newOwned, liveDNS, nil
}

// Apply reconciles NetworkManager profiles (ApplyProfiles) followed by the cgroupv2-scoped
// `inet quadmatic` nftables outbound guard (ApplyNFTables). Even when err != nil, newOwned
// contains all `qm-*`/`qmv-*` profiles created or reconciled up to the point of failure.
func (r *Reconciler) Apply(
	ctx context.Context,
	host *manifest.ResolvedHost,
	prevOwned []state.ManagedNetworkRecord,
	dhcpTimeout time.Duration,
) (newOwned []state.ManagedNetworkRecord, liveDNS map[string][]string, nftHash string, err error) {
	newOwned, liveDNS, err = r.ApplyProfiles(ctx, host, prevOwned, dhcpTimeout)
	if err != nil {
		return newOwned, nil, "", err
	}
	nftHash, err = r.ApplyNFTables(ctx, host)
	if err != nil {
		return newOwned, nil, "", err
	}
	return newOwned, liveDNS, nftHash, nil
}

// Restore deletes newly created `qm-*` profiles from createdDuringAttempt that were not
// present in snap, restores snapshotted `qm-*` profiles (in vlan -> vrf -> macvlan order),
// and restores or removes `table inet quadmatic`. Unmanaged (`Owned == false` or non-`qm-`)
// profiles are never modified or deleted.
func (r *Reconciler) Restore(ctx context.Context, snap *Snapshot, createdDuringAttempt []state.ManagedNetworkRecord) error {
	if r == nil {
		return errors.New("netmgr reconciler is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	snapProfiles := make(map[string]string)
	if snap != nil {
		for k, v := range snap.Profiles {
			snapProfiles[k] = v
		}
	}

	toDelete := make(map[string]state.ManagedNetworkRecord)
	for _, rec := range createdDuringAttempt {
		if !rec.Owned || !isManagedConnectionName(rec.ConnectionName) {
			continue
		}
		if _, inSnap := snapProfiles[rec.ConnectionName]; inSnap {
			continue
		}
		toDelete[rec.ConnectionName] = rec
	}
	deleteList := make([]state.ManagedNetworkRecord, 0, len(toDelete))
	for _, rec := range toDelete {
		deleteList = append(deleteList, rec)
	}
	sortDeleteRecords(deleteList)
	for _, rec := range deleteList {
		if err := r.deleteOwnedRecord(ctx, rec); err != nil {
			return err
		}
	}

	type snapItem struct {
		name  string
		kind  string
		props map[string]string
	}
	var restoreItems []snapItem
	for name, raw := range snapProfiles {
		if !isManagedConnectionName(name) {
			continue
		}
		props := parseSnapshotProfile(name, raw)
		kind := inferProfileKind(name, props)
		restoreItems = append(restoreItems, snapItem{
			name:  name,
			kind:  kind,
			props: props,
		})
	}
	slices.SortFunc(restoreItems, func(a, b snapItem) int {
		if ra, rb := createRank(a.kind), createRank(b.kind); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.name, b.name)
	})

	var activeConns map[string]bool
	if len(restoreItems) > 0 {
		var err error
		activeConns, err = r.listActiveConnectionNames(ctx)
		if err != nil {
			return err
		}
	}
	for _, item := range restoreItems {
		if err := r.restoreProfile(ctx, item.name, item.kind, item.props, activeConns); err != nil {
			return err
		}
	}

	var ruleset string
	if snap != nil {
		ruleset = snap.NFTablesRuleset
	}
	return r.restoreNFTables(ctx, ruleset)
}

func (r *Reconciler) buildDesiredPlan(ctx context.Context, host *manifest.ResolvedHost) (*desiredPlan, error) {
	parents, unmanaged, err := r.resolveVLANParentsWithInfo(ctx, host)
	if err != nil {
		return nil, err
	}

	plan := &desiredPlan{
		parentMap: parents,
	}

	vlanSeen := make(map[int]bool)
	seenUsers := make(map[int]string)
	seenMACs := make(map[string]string)

	for _, comp := range host.Components {
		if comp.Network == nil {
			continue
		}
		plan.hasNetworks = true
		ns := comp.Network

		if ns.VLAN < 0 || ns.VLAN > 4094 {
			return nil, fmt.Errorf("component %q invalid VLAN %d", comp.Name, ns.VLAN)
		}
		if ns.VLAN > 0 && !vlanSeen[ns.VLAN] {
			vlanSeen[ns.VLAN] = true
			parentIface := parents[ns.VLAN]
			owned := isManagedConnectionName(parentIface)
			connName := parentIface
			if !owned {
				if info, ok := unmanaged[ns.VLAN]; ok && info.Connection != "" && info.Connection != "--" {
					connName = info.Connection
				}
			}
			plan.vlans = append(plan.vlans, desiredVLAN{
				VLAN:       ns.VLAN,
				ConnName:   connName,
				DeviceName: parentIface,
				Owned:      owned,
				Component:  comp.Name,
				Scope:      comp.Scope(),
			})
		}

		if comp.Rootful {
			continue
		}

		if comp.UID <= 0 {
			return nil, fmt.Errorf("rootless component %q must have positive UID, got %d", comp.Name, comp.UID)
		}
		if prevComp, dup := seenUsers[comp.UID]; dup {
			return nil, fmt.Errorf("UID %d shared by multiple [component.network] components (%q and %q)", comp.UID, prevComp, comp.Name)
		}
		seenUsers[comp.UID] = comp.Name

		mac, err := normalizeAndValidateMAC(comp.Name, ns.MAC)
		if err != nil {
			return nil, err
		}
		if prevComp, dup := seenMACs[mac]; dup {
			return nil, fmt.Errorf("duplicate MAC %q shared by components %q and %q", mac, prevComp, comp.Name)
		}
		seenMACs[mac] = comp.Name

		mode := ns.MacvlanMode
		if mode == "" {
			mode = "private"
		}
		if mode != "private" && mode != "bridge" {
			return nil, fmt.Errorf("component %q unsupported macvlan_mode %q", comp.Name, mode)
		}
		if len(ns.DNS) == 0 && !ns.DNSFromDHCP {
			return nil, fmt.Errorf("rootless network component %q must specify dns or dns_from_dhcp = true", comp.Name)
		}

		vrfName := fmt.Sprintf("qmv-%d", comp.UID)
		mvName := fmt.Sprintf("qm-%d", comp.UID)
		if err := validateIfName("vrf", vrfName); err != nil {
			return nil, err
		}
		if err := validateIfName("macvlan", mvName); err != nil {
			return nil, err
		}

		parentIface := parents[ns.VLAN]
		if parentIface == "" {
			parentIface = r.trunkInterface
		}

		plan.rootless = append(plan.rootless, desiredRootlessNet{
			CompName:      comp.Name,
			Scope:         comp.Scope(),
			UID:           comp.UID,
			ParentIface:   parentIface,
			VRFName:       vrfName,
			TableID:       vrfTableOffset + comp.UID,
			MacvlanName:   mvName,
			Mode:          mode,
			MAC:           mac,
			IPv6:          ns.IPv6,
			DNSFromDHCP:   ns.DNSFromDHCP,
			OutboundGuard: outboundGuardEnabled(ns),
			Units:         resolveComponentWorkloadUnits(comp),
		})
	}

	slices.SortFunc(plan.vlans, func(a, b desiredVLAN) int {
		return a.VLAN - b.VLAN
	})
	slices.SortFunc(plan.rootless, func(a, b desiredRootlessNet) int {
		if a.UID != b.UID {
			return a.UID - b.UID
		}
		return strings.Compare(a.CompName, b.CompName)
	})

	targets, err := collectNFTGuardTargets(r.cgroupPattern, host)
	if err != nil {
		return nil, err
	}
	plan.nftTargets = targets

	return plan, nil
}

func (r *Reconciler) discoverUnmanagedVLANs(ctx context.Context) (map[int]unmanagedVLAN, error) {
	out, err := r.runner.Run(ctx, nil, "nmcli", "-t", "-f", "DEVICE,TYPE,CONNECTION", "device")
	if err != nil {
		return nil, formatCmdErr("nmcli -t -f DEVICE,TYPE,CONNECTION device", out, err)
	}

	found := make(map[int]unmanagedVLAN)
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := splitNMCLITerseFields(line, 3)
		if len(fields) < 3 {
			continue
		}
		device, devType, conn := fields[0], fields[1], fields[2]
		if devType != "vlan" {
			continue
		}
		// Never treat quadmatic-owned qm-*/qmv-* devices or profiles as unmanaged parents.
		if isManagedConnectionName(device) || isManagedConnectionName(conn) {
			continue
		}

		var parent string
		var vlanID int
		var inspectErr error
		if conn != "" && conn != "--" {
			parent, vlanID, inspectErr = r.inspectVLANConnection(ctx, conn)
		} else {
			parent, vlanID, inspectErr = r.inspectKernelVLANLink(ctx, device)
		}
		if inspectErr != nil {
			continue
		}
		if parent == r.trunkInterface && vlanID > 0 {
			if _, exists := found[vlanID]; !exists {
				found[vlanID] = unmanagedVLAN{
					Device:     device,
					Connection: conn,
					Parent:     parent,
					VLANID:     vlanID,
				}
			}
		}
	}
	return found, nil
}

func (r *Reconciler) inspectVLANConnection(ctx context.Context, conn string) (string, int, error) {
	out, err := r.runner.Run(ctx, nil, "nmcli", "-g", "vlan.parent,vlan.id", "connection", "show", conn)
	if err != nil {
		return "", 0, err
	}
	var vals []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "vlan.parent:") {
			vals = append(vals, unescapeNMCLI(strings.TrimPrefix(line, "vlan.parent:")))
			continue
		}
		if strings.HasPrefix(line, "vlan.id:") {
			vals = append(vals, unescapeNMCLI(strings.TrimPrefix(line, "vlan.id:")))
			continue
		}
		vals = append(vals, unescapeNMCLI(line))
	}
	if len(vals) < 2 {
		return "", 0, fmt.Errorf("unexpected nmcli vlan.parent,vlan.id output for %q", conn)
	}
	id, err := strconv.Atoi(strings.TrimSpace(vals[1]))
	if err != nil || id <= 0 {
		return "", 0, fmt.Errorf("invalid vlan.id %q for %q", vals[1], conn)
	}
	return strings.TrimSpace(vals[0]), id, nil
}

func (r *Reconciler) inspectKernelVLANLink(ctx context.Context, device string) (string, int, error) {
	out, err := r.runner.Run(ctx, nil, "ip", "-d", "-o", "link", "show", "dev", device)
	if err != nil {
		return "", 0, err
	}
	text := string(out)
	var parent string
	if idx := strings.Index(text, device+"@"); idx >= 0 {
		rest := text[idx+len(device)+1:]
		if end := strings.IndexAny(rest, ": "); end > 0 {
			parent = rest[:end]
		}
	}
	m := ipLinkVLANIDRe.FindStringSubmatch(text)
	if parent == "" || len(m) < 2 {
		return "", 0, fmt.Errorf("could not parse kernel vlan link %q", device)
	}
	id, err := strconv.Atoi(m[1])
	if err != nil || id <= 0 {
		return "", 0, err
	}
	return parent, id, nil
}

func (r *Reconciler) ensureProfile(
	ctx context.Context,
	connName string,
	expectedType string,
	desired map[string]string,
	addArgsFn func() ([]string, error),
) (mutated bool, presentInNM bool, err error) {
	if !isManagedConnectionName(connName) {
		return false, false, fmt.Errorf("refusing to manage non-qm connection %q", connName)
	}

	existing, exists, err := r.readProfileProps(ctx, connName)
	if err != nil {
		return false, false, err
	}
	if !exists {
		addArgs, err := addArgsFn()
		if err != nil {
			return false, false, err
		}
		out, err := r.runner.Run(ctx, nil, "nmcli", addArgs...)
		if err != nil {
			return false, false, formatCmdErr(fmt.Sprintf("nmcli %s", strings.Join(addArgs, " ")), out, err)
		}
		return true, true, nil
	}

	if existingType := existing["connection.type"]; existingType != "" && existingType != expectedType {
		if err := r.deleteConnectionIfExists(ctx, connName); err != nil {
			return false, true, err
		}
		addArgs, err := addArgsFn()
		if err != nil {
			return false, false, err
		}
		out, err := r.runner.Run(ctx, nil, "nmcli", addArgs...)
		if err != nil {
			return false, false, formatCmdErr(fmt.Sprintf("nmcli %s", strings.Join(addArgs, " ")), out, err)
		}
		return true, true, nil
	}

	if propsMatch(existing, desired) {
		return false, true, nil
	}

	modArgs := []string{"connection", "modify", connName}
	keys := make([]string, 0, len(desired))
	for k := range desired {
		if k == "connection.id" || k == "connection.type" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		modArgs = append(modArgs, modifyPropName(k), desired[k])
	}
	out, err := r.runner.Run(ctx, nil, "nmcli", modArgs...)
	if err != nil {
		return false, true, formatCmdErr(fmt.Sprintf("nmcli connection modify %s", connName), out, err)
	}
	return true, true, nil
}

func vlanAddArgs(connName string, desired map[string]string) []string {
	return []string{
		"connection", "add",
		"type", "vlan",
		"con-name", connName,
		"ifname", desired["connection.interface-name"],
		"dev", desired["vlan.parent"],
		"id", desired["vlan.id"],
		"ipv4.method", desired["ipv4.method"],
		"ipv6.method", desired["ipv6.method"],
		"autoconnect", desired["connection.autoconnect"],
	}
}

func vrfAddArgs(connName string, desired map[string]string) []string {
	return []string{
		"connection", "add",
		"type", "vrf",
		"con-name", connName,
		"ifname", desired["connection.interface-name"],
		"table", desired["vrf.table"],
		"ipv4.method", desired["ipv4.method"],
		"ipv6.method", desired["ipv6.method"],
		"autoconnect", desired["connection.autoconnect"],
	}
}

func macvlanAddArgs(connName string, desired map[string]string) []string {
	args := []string{
		"connection", "add",
		"type", "macvlan",
		"con-name", connName,
		"ifname", desired["connection.interface-name"],
		"dev", desired["macvlan.parent"],
		"mode", desired["macvlan.mode"],
		"controller", desired["connection.controller"],
		"ethernet.cloned-mac-address", desired["802-3-ethernet.cloned-mac-address"],
		"ipv4.method", desired["ipv4.method"],
		"ipv4.route-table", desired["ipv4.route-table"],
		"ipv4.ignore-auto-dns", desired["ipv4.ignore-auto-dns"],
		"ipv6.method", desired["ipv6.method"],
	}
	if desired["ipv6.method"] == "auto" {
		if rt := desired["ipv6.route-table"]; rt != "" {
			args = append(args, "ipv6.route-table", rt)
		}
		args = append(args, "ipv6.ignore-auto-dns", desired["ipv6.ignore-auto-dns"])
	}
	args = append(args, "autoconnect", desired["connection.autoconnect"])
	return args
}

func (r *Reconciler) restoreProfile(ctx context.Context, connName, kind string, props map[string]string, activeConns map[string]bool) error {
	var desired map[string]string
	var addFn func() ([]string, error)

	switch kind {
	case kindVLAN:
		desired = map[string]string{
			"connection.type":           "vlan",
			"connection.interface-name": firstNonEmpty(props["connection.interface-name"], connName),
			"connection.autoconnect":    firstNonEmpty(props["connection.autoconnect"], "yes"),
			"vlan.parent":               props["vlan.parent"],
			"vlan.id":                   props["vlan.id"],
			"ipv4.method":               firstNonEmpty(props["ipv4.method"], "disabled"),
			"ipv6.method":               firstNonEmpty(props["ipv6.method"], "disabled"),
		}
		addFn = func() ([]string, error) {
			return vlanAddArgs(connName, desired), nil
		}

	case kindVRF:
		desired = map[string]string{
			"connection.type":           "vrf",
			"connection.interface-name": firstNonEmpty(props["connection.interface-name"], connName),
			"connection.autoconnect":    firstNonEmpty(props["connection.autoconnect"], "yes"),
			"vrf.table":                 props["vrf.table"],
			"ipv4.method":               firstNonEmpty(props["ipv4.method"], "disabled"),
			"ipv6.method":               firstNonEmpty(props["ipv6.method"], "disabled"),
		}
		addFn = func() ([]string, error) {
			return vrfAddArgs(connName, desired), nil
		}

	case kindMacvlan:
		ipv6Method := firstNonEmpty(props["ipv6.method"], "disabled")
		desired = map[string]string{
			"connection.type":                   "macvlan",
			"connection.interface-name":         firstNonEmpty(props["connection.interface-name"], connName),
			"connection.autoconnect":            firstNonEmpty(props["connection.autoconnect"], "yes"),
			"macvlan.parent":                    props["macvlan.parent"],
			"macvlan.mode":                      normalizeMacvlanMode(firstNonEmpty(props["macvlan.mode"], "private")),
			"connection.controller":             firstNonEmpty(props["connection.controller"], props["connection.master"]),
			"802-3-ethernet.cloned-mac-address": strings.ToLower(firstNonEmpty(props["802-3-ethernet.cloned-mac-address"], props["ethernet.cloned-mac-address"])),
			"ipv4.method":                       firstNonEmpty(props["ipv4.method"], "auto"),
			"ipv4.route-table":                  props["ipv4.route-table"],
			"ipv4.ignore-auto-dns":              firstNonEmpty(props["ipv4.ignore-auto-dns"], "yes"),
			"ipv6.method":                       ipv6Method,
		}
		if ipv6Method == "auto" {
			if rt := props["ipv6.route-table"]; rt != "" {
				desired["ipv6.route-table"] = rt
			}
			desired["ipv6.ignore-auto-dns"] = firstNonEmpty(props["ipv6.ignore-auto-dns"], "yes")
		}
		addFn = func() ([]string, error) {
			return macvlanAddArgs(connName, desired), nil
		}

	default:
		return fmt.Errorf("cannot restore unknown profile kind %q for %q", kind, connName)
	}

	mutated, _, err := r.ensureProfile(ctx, connName, kind, desired, addFn)
	if err != nil {
		return err
	}
	if mutated || !activeConns[connName] {
		if err := r.upConnection(ctx, connName); err != nil {
			return err
		}
	}
	if kind == kindVRF {
		tableID, err := strconv.Atoi(desired["vrf.table"])
		if err != nil || tableID <= 0 {
			return fmt.Errorf("invalid snapped VRF table %q for %q", desired["vrf.table"], connName)
		}
		if err := r.ensureVRFUnreachableRoute(ctx, tableID); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) upConnection(ctx context.Context, connName string) error {
	out, err := r.runner.Run(ctx, nil, "nmcli", "connection", "up", connName)
	if err != nil {
		return formatCmdErr(fmt.Sprintf("nmcli connection up %s", connName), out, err)
	}
	return nil
}

func (r *Reconciler) ensureVRFUnreachableRoute(ctx context.Context, tableID int) error {
	out, err := r.runner.Run(ctx, nil, "ip", "route", "replace", "unreachable", "default", "metric", vrfDefaultMetric, "table", strconv.Itoa(tableID))
	if err != nil {
		return formatCmdErr(fmt.Sprintf("ip route replace unreachable default metric %s table %d", vrfDefaultMetric, tableID), out, err)
	}
	return nil
}

func (r *Reconciler) hasVRFUnreachableRoute(ctx context.Context, tableID int) (bool, error) {
	out, err := r.runner.Run(ctx, nil, "ip", "route", "show", "table", strconv.Itoa(tableID))
	if err != nil {
		if isNMNotFoundErr(out, err) || strings.Contains(strings.ToLower(string(out)), "table does not exist") {
			return false, nil
		}
		return false, formatCmdErr(fmt.Sprintf("ip route show table %d", tableID), out, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "unreachable" && fields[1] == "default" {
			if slices.Contains(fields, vrfDefaultMetric) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *Reconciler) pollLiveDNS(ctx context.Context, ifname string, dhcpTimeout time.Duration) ([]string, error) {
	if dhcpTimeout <= 0 {
		dhcpTimeout = defaultDHCPTimeout
	}
	interval := dhcpTimeout / 4
	if interval > maxDHCPPollInterval {
		interval = maxDHCPPollInterval
	}
	if interval < minDHCPPollInterval {
		interval = minDHCPPollInterval
	}

	deadline := time.Now().Add(dhcpTimeout)
	for {
		dns, err := r.ReadLiveDNS(ctx, ifname)
		if err != nil {
			return nil, err
		}
		if len(dns) > 0 {
			return dns, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("timed out waiting %s for DHCP DNS on %s", dhcpTimeout, ifname)
		}
		waitFor := interval
		if remaining < waitFor {
			waitFor = remaining
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *Reconciler) pruneUnreferenced(ctx context.Context, prevOwned, newOwned []state.ManagedNetworkRecord) error {
	desired := make(map[string]bool, len(newOwned))
	for _, rec := range newOwned {
		if rec.Owned {
			desired[rec.ConnectionName] = true
		}
	}

	var toPrune []state.ManagedNetworkRecord
	seen := make(map[string]bool)
	for _, rec := range prevOwned {
		if !rec.Owned || !isManagedConnectionName(rec.ConnectionName) {
			continue
		}
		if desired[rec.ConnectionName] || seen[rec.ConnectionName] {
			continue
		}
		seen[rec.ConnectionName] = true
		toPrune = append(toPrune, rec)
	}

	sortDeleteRecords(toPrune)
	for _, rec := range toPrune {
		if err := r.deleteOwnedRecord(ctx, rec); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) deleteOwnedRecord(ctx context.Context, rec state.ManagedNetworkRecord) error {
	if !rec.Owned || !isManagedConnectionName(rec.ConnectionName) {
		return nil
	}
	if err := validateConnName(rec.ConnectionName); err != nil {
		return err
	}
	if rec.Kind == kindVRF || strings.HasPrefix(rec.ConnectionName, ManagedVRFPrefix) {
		if uidStr, ok := strings.CutPrefix(rec.ConnectionName, ManagedVRFPrefix); ok {
			if uid, err := strconv.Atoi(uidStr); err == nil && uid > 0 {
				_, _ = r.runner.Run(ctx, nil, "ip", "route", "del", "unreachable", "default", "metric", vrfDefaultMetric, "table", strconv.Itoa(vrfTableOffset+uid))
			}
		}
	}
	return r.deleteConnectionIfExists(ctx, rec.ConnectionName)
}

func (r *Reconciler) deleteConnectionIfExists(ctx context.Context, connName string) error {
	if !isManagedConnectionName(connName) {
		return fmt.Errorf("refusing to delete non-qm connection %q", connName)
	}
	out, err := r.runner.Run(ctx, nil, "nmcli", "connection", "delete", connName)
	if err != nil {
		if isNMNotFoundErr(out, err) {
			return nil
		}
		return formatCmdErr(fmt.Sprintf("nmcli connection delete %s", connName), out, err)
	}
	return nil
}

func (r *Reconciler) listConnectionNames(ctx context.Context) ([]string, error) {
	out, err := r.runner.Run(ctx, nil, "nmcli", "-t", "-f", "NAME", "connection", "show")
	if err != nil {
		return nil, formatCmdErr("nmcli -t -f NAME connection show", out, err)
	}
	return parseLineList(string(out)), nil
}

func (r *Reconciler) listActiveConnectionNames(ctx context.Context) (map[string]bool, error) {
	out, err := r.runner.Run(ctx, nil, "nmcli", "-t", "-f", "NAME", "connection", "show", "--active")
	if err != nil {
		return nil, formatCmdErr("nmcli -t -f NAME connection show --active", out, err)
	}
	active := make(map[string]bool)
	for _, name := range parseLineList(string(out)) {
		active[name] = true
	}
	return active, nil
}

func (r *Reconciler) readProfileProps(ctx context.Context, connName string) (map[string]string, bool, error) {
	out, err := r.runner.Run(ctx, nil, "nmcli", "-t", "connection", "show", connName)
	if err != nil {
		if isNMNotFoundErr(out, err) {
			return nil, false, nil
		}
		return nil, false, formatCmdErr(fmt.Sprintf("nmcli -t connection show %s", connName), out, err)
	}
	return parseNMCLIShowProps(string(out)), true, nil
}

func (r *Reconciler) desiredVLANProps(v desiredVLAN) map[string]string {
	return map[string]string{
		"connection.type":           "vlan",
		"connection.interface-name": v.DeviceName,
		"connection.autoconnect":    "yes",
		"vlan.parent":               r.trunkInterface,
		"vlan.id":                   strconv.Itoa(v.VLAN),
		"ipv4.method":               "disabled",
		"ipv6.method":               "disabled",
	}
}

func desiredVRFProps(rl desiredRootlessNet) map[string]string {
	return map[string]string{
		"connection.type":           "vrf",
		"connection.interface-name": rl.VRFName,
		"connection.autoconnect":    "yes",
		"vrf.table":                 strconv.Itoa(rl.TableID),
		"ipv4.method":               "disabled",
		"ipv6.method":               "disabled",
	}
}

func desiredMacvlanProps(rl desiredRootlessNet) map[string]string {
	props := map[string]string{
		"connection.type":                   "macvlan",
		"connection.interface-name":         rl.MacvlanName,
		"connection.autoconnect":            "yes",
		"macvlan.parent":                    rl.ParentIface,
		"macvlan.mode":                      rl.Mode,
		"connection.controller":             rl.VRFName,
		"802-3-ethernet.cloned-mac-address": rl.MAC,
		"ipv4.method":                       "auto",
		"ipv4.route-table":                  strconv.Itoa(rl.TableID),
		"ipv4.ignore-auto-dns":              "yes",
		"ipv6.method":                       "disabled",
	}
	if rl.IPv6 {
		props["ipv6.method"] = "auto"
		props["ipv6.route-table"] = strconv.Itoa(rl.TableID)
		props["ipv6.ignore-auto-dns"] = "yes"
	}
	return props
}

func propsMatch(actual, desired map[string]string) bool {
	for k, want := range desired {
		got := lookupProp(actual, k)
		switch k {
		case "macvlan.mode":
			if normalizeMacvlanMode(got) != normalizeMacvlanMode(want) {
				return false
			}
		case "802-3-ethernet.cloned-mac-address":
			if strings.ToLower(got) != strings.ToLower(want) {
				return false
			}
		case "connection.autoconnect":
			// NM omits or uses "yes" by default when autoconnect is enabled.
			if got == "" {
				got = "yes"
			}
			if got != want {
				return false
			}
		default:
			if got != want {
				return false
			}
		}
	}
	return true
}

func lookupProp(props map[string]string, key string) string {
	if v, ok := props[key]; ok {
		return v
	}
	switch key {
	case "connection.controller":
		return props["connection.master"]
	case "802-3-ethernet.cloned-mac-address":
		return props["ethernet.cloned-mac-address"]
	}
	return ""
}

func modifyPropName(key string) string {
	if key == "802-3-ethernet.cloned-mac-address" {
		return "ethernet.cloned-mac-address"
	}
	return key
}

func parseSnapshotProfile(name, raw string) map[string]string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "[") {
		return parseKeyfileProps(trimmed)
	}
	props := parseNMCLIShowProps(trimmed)
	if props["connection.id"] == "" {
		props["connection.id"] = name
	}
	return props
}

func parseNMCLIShowProps(raw string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		props[strings.TrimSpace(k)] = strings.TrimSpace(unescapeNMCLI(v))
	}
	return props
}

func parseKeyfileProps(raw string) map[string]string {
	props := make(map[string]string)
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "ethernet" {
				section = "802-3-ethernet"
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		key := section + "." + strings.TrimSpace(k)
		if key == "ethernet.cloned-mac-address" {
			key = "802-3-ethernet.cloned-mac-address"
		}
		props[key] = strings.TrimSpace(v)
	}
	return props
}

func inferProfileKind(name string, props map[string]string) string {
	if t := props["connection.type"]; t != "" {
		return t
	}
	switch {
	case strings.HasPrefix(name, "qm-vlan"):
		return kindVLAN
	case strings.HasPrefix(name, "qmv-"):
		return kindVRF
	default:
		return kindMacvlan
	}
}

func normalizeMacvlanMode(v string) string {
	lower := strings.ToLower(strings.TrimSpace(v))
	switch {
	case lower == "private" || strings.Contains(lower, "(private)") || lower == "1":
		return "private"
	case lower == "bridge" || strings.Contains(lower, "(bridge)") || lower == "2":
		return "bridge"
	default:
		return lower
	}
}

func sortDeleteRecords(recs []state.ManagedNetworkRecord) {
	slices.SortFunc(recs, func(a, b state.ManagedNetworkRecord) int {
		if ra, rb := deleteRank(a.Kind, a.ConnectionName), deleteRank(b.Kind, b.ConnectionName); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.ConnectionName, b.ConnectionName)
	})
}

func deleteRank(kind, name string) int {
	k := kind
	if k == "" {
		k = inferProfileKind(name, nil)
	}
	switch k {
	case kindMacvlan:
		return 0
	case kindVRF:
		return 1
	case kindVLAN:
		return 2
	default:
		return 3
	}
}

func createRank(kind string) int {
	switch kind {
	case kindVLAN:
		return 0
	case kindVRF:
		return 1
	case kindMacvlan:
		return 2
	default:
		return 3
	}
}

func collectRequestedVLANs(host *manifest.ResolvedHost) ([]int, bool, error) {
	seen := make(map[int]bool)
	var vlans []int
	hasNetworks := false
	for _, comp := range host.Components {
		if comp.Network == nil {
			continue
		}
		hasNetworks = true
		v := comp.Network.VLAN
		if v < 0 || v > 4094 {
			return nil, false, fmt.Errorf("component %q invalid VLAN %d (must be 0..4094)", comp.Name, v)
		}
		if !seen[v] {
			seen[v] = true
			vlans = append(vlans, v)
		}
	}
	slices.Sort(vlans)
	return vlans, hasNetworks, nil
}

func normalizeAndValidateMAC(compName, rawMAC string) (string, error) {
	if strings.TrimSpace(rawMAC) == "" {
		return "", fmt.Errorf("component %q network requires a MAC address", compName)
	}
	hw, err := net.ParseMAC(rawMAC)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("component %q invalid Ethernet MAC %q", compName, rawMAC)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("component %q invalid all-zero MAC %q", compName, rawMAC)
	}
	if hw[0]&0x01 != 0 {
		return "", fmt.Errorf("component %q MAC %q must be unicast", compName, rawMAC)
	}
	return strings.ToLower(hw.String()), nil
}

func validateIfName(kind, name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("%s must not be empty", kind)
	}
	if len(trimmed) > maxIfNameLen {
		return fmt.Errorf("%s %q exceeds %d-character Linux interface name limit", kind, trimmed, maxIfNameLen)
	}
	if strings.HasPrefix(trimmed, "-") || strings.ContainsAny(trimmed, " \t\r\n/\\:\x00") {
		return fmt.Errorf("%s %q contains invalid characters", kind, trimmed)
	}
	return nil
}

func validateConnName(name string) error {
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "\x00\r\n/\\") {
		return fmt.Errorf("invalid connection name %q", name)
	}
	return nil
}

func splitNMCLITerseFields(line string, maxFields int) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == ':' && (maxFields <= 0 || len(fields) < maxFields-1) {
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if escaped {
		cur.WriteByte('\\')
	}
	fields = append(fields, cur.String())
	return fields
}

func unescapeNMCLI(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseLineList(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		v := strings.TrimSpace(unescapeNMCLI(line))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseDNSList(raw string) []string {
	var out []string
	seen := make(map[string]bool)
	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '|' || r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == "--" {
			continue
		}
		addr, err := netip.ParseAddr(tok)
		if err != nil {
			continue
		}
		norm := addr.String()
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out
}

func isNMNotFoundErr(out []byte, err error) bool {
	combined := strings.ToLower(string(out) + " " + err.Error())
	return strings.Contains(combined, "no such connection") ||
		strings.Contains(combined, "unknown connection") ||
		strings.Contains(combined, "not found") ||
		strings.Contains(combined, "does not exist") ||
		strings.Contains(combined, "exit status 10")
}

func formatCmdErr(cmd string, out []byte, err error) error {
	detail := strings.TrimSpace(string(out))
	if detail != "" {
		return fmt.Errorf("%s: %w: %s", cmd, err, detail)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
