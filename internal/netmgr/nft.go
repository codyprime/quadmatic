package netmgr

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"quadmatic/internal/manifest"
)

const nftTableName = "quadmatic"

var nftCounterStatsRe = regexp.MustCompile(`\bcounter\s+packets\s+\d+\s+bytes\s+\d+\b`)

type nftGuardTarget struct {
	UID         int
	VRFName     string
	MacvlanName string
	CgroupPaths []string
}

func outboundGuardEnabled(netSpec *manifest.NetworkSpec) bool {
	if netSpec == nil {
		return false
	}
	if netSpec.OutboundGuard == nil {
		return true
	}
	return *netSpec.OutboundGuard
}

func resolveComponentWorkloadUnits(comp manifest.ResolvedComponent) []string {
	var units []string
	seen := make(map[string]bool)
	for _, qf := range comp.QuadletFiles {
		unit := quadletFileToWorkloadUnit(qf.RelPath)
		if unit == "" || seen[unit] {
			continue
		}
		seen[unit] = true
		units = append(units, unit)
	}
	if len(units) == 0 {
		units = []string{comp.Name + ".service"}
	}
	slices.Sort(units)
	return units
}

func quadletFileToWorkloadUnit(relPath string) string {
	base := path.Base(strings.TrimSuffix(relPath, ".tmpl"))
	switch {
	case strings.HasSuffix(base, ".container") && len(base) > len(".container"):
		return strings.TrimSuffix(base, ".container") + ".service"
	case strings.HasSuffix(base, ".pod") && len(base) > len(".pod"):
		return strings.TrimSuffix(base, ".pod") + "-pod.service"
	case strings.HasSuffix(base, ".kube") && len(base) > len(".kube"):
		return strings.TrimSuffix(base, ".kube") + ".service"
	default:
		return ""
	}
}

func expandCgroupPath(pattern string, uid int, user, compName, unit string) (string, int, error) {
	replacer := strings.NewReplacer(
		"{uid}", strconv.Itoa(uid),
		"{user}", user,
		"{component}", compName,
		"{unit}", unit,
	)
	expanded := strings.Trim(replacer.Replace(pattern), "/")
	if expanded == "" {
		return "", 0, fmt.Errorf("expanded cgroupv2 path for unit %q is empty", unit)
	}
	if strings.ContainsAny(expanded, "\x00\r\n\"\\") {
		return "", 0, fmt.Errorf("expanded cgroupv2 path %q contains forbidden characters", expanded)
	}
	segs := strings.Split(expanded, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", 0, fmt.Errorf("expanded cgroupv2 path %q contains invalid segment %q", expanded, seg)
		}
	}
	return expanded, len(segs), nil
}

func (r *Reconciler) collectNFTGuardTargets(host *manifest.ResolvedHost) ([]nftGuardTarget, error) {
	pattern := r.cgroupPattern
	if pattern == "" {
		pattern = DefaultCgroupPattern
	}
	var targets []nftGuardTarget
	for _, comp := range host.Components {
		if comp.Rootful || comp.Network == nil || !outboundGuardEnabled(comp.Network) {
			continue
		}
		if comp.UID <= 0 {
			return nil, fmt.Errorf("rootless component %q must have positive UID, got %d", comp.Name, comp.UID)
		}
		vrfName := fmt.Sprintf("qmv-%d", comp.UID)
		mvName := fmt.Sprintf("qm-%d", comp.UID)
		if err := validateIfName("vrf", vrfName); err != nil {
			return nil, err
		}
		if err := validateIfName("macvlan", mvName); err != nil {
			return nil, err
		}

		units := resolveComponentWorkloadUnits(comp)
		cgroups := make([]string, 0, len(units))
		seen := make(map[string]bool, len(units))
		for _, unit := range units {
			cgPath, _, err := expandCgroupPath(pattern, comp.UID, comp.Scope(), comp.Name, unit)
			if err != nil {
				return nil, err
			}
			if !seen[cgPath] && r.checkCgroupExists(cgPath) {
				seen[cgPath] = true
				cgroups = append(cgroups, cgPath)
			}
		}
		if len(cgroups) == 0 {
			continue
		}
		slices.Sort(cgroups)
		targets = append(targets, nftGuardTarget{
			UID:         comp.UID,
			VRFName:     vrfName,
			MacvlanName: mvName,
			CgroupPaths: cgroups,
		})
	}
	slices.SortFunc(targets, func(a, b nftGuardTarget) int {
		if a.UID != b.UID {
			return a.UID - b.UID
		}
		return strings.Compare(a.MacvlanName, b.MacvlanName)
	})
	return targets, nil
}

// ApplyNFTables renders and atomically replaces `table inet quadmatic` for all active rootless
// outbound_guard-enabled components in host (or deletes the table if none remain).
// Intended to run after workload systemd units are active so Linux nftables can resolve
// cgroupv2 paths to live cgroup inodes.
func (r *Reconciler) ApplyNFTables(ctx context.Context, host *manifest.ResolvedHost) (string, error) {
	if r == nil {
		return "", errors.New("netmgr reconciler is nil")
	}
	if host == nil {
		return "", errors.New("resolved host is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	targets, err := r.collectNFTGuardTargets(host)
	if err != nil {
		return "", err
	}
	return r.applyNFTables(ctx, targets)
}

func renderNFTablesTable(targets []nftGuardTarget) (string, error) {
	if len(targets) == 0 {
		return "", nil
	}

	var b strings.Builder
	b.WriteString("table inet ")
	b.WriteString(nftTableName)
	b.WriteString(" {\n")

	for _, t := range targets {
		if err := validateIfName("macvlan", t.MacvlanName); err != nil {
			return "", err
		}
		if err := validateIfName("vrf", t.VRFName); err != nil {
			return "", err
		}
		allowed := []string{t.MacvlanName, t.VRFName}
		slices.Sort(allowed)
		fmt.Fprintf(&b, "\tchain guard_%d {\n", t.UID)
		fmt.Fprintf(&b, "\t\toifname { %q, %q } accept\n", allowed[0], allowed[1])
		b.WriteString("\t\tcounter drop\n")
		b.WriteString("\t}\n\n")
	}

	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy accept;\n")
	for _, t := range targets {
		for _, cgPath := range t.CgroupPaths {
			level := strings.Count(cgPath, "/") + 1
			fmt.Fprintf(&b, "\t\tsocket cgroupv2 level %d %q jump guard_%d\n", level, cgPath, t.UID)
		}
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func (r *Reconciler) applyNFTables(ctx context.Context, targets []nftGuardTarget) (string, error) {
	if len(targets) == 0 {
		if err := r.deleteNFTablesIfPresent(ctx); err != nil {
			return "", err
		}
		return "", nil
	}

	tableText, err := renderNFTablesTable(targets)
	if err != nil {
		return "", err
	}
	script := fmt.Sprintf("table inet %s\ndelete table inet %s\n%s", nftTableName, nftTableName, tableText)
	out, err := r.runner.Run(ctx, []byte(script), "nft", "-f", "-")
	if err != nil {
		return "", formatCmdErr("nft -f -", out, err)
	}
	return sha256Hex([]byte(tableText)), nil
}

func (r *Reconciler) readNFTables(ctx context.Context) (string, bool, error) {
	out, err := r.runner.Run(ctx, nil, "nft", "list", "table", "inet", nftTableName)
	if err != nil {
		if isNFTNotFoundErr(out, err) {
			return "", false, nil
		}
		return "", false, formatCmdErr("nft list table inet quadmatic", out, err)
	}
	return string(out), true, nil
}

func (r *Reconciler) deleteNFTablesIfPresent(ctx context.Context) error {
	_, exists, err := r.readNFTables(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := r.runner.Run(ctx, nil, "nft", "delete", "table", "inet", nftTableName)
	if err != nil {
		if isNFTNotFoundErr(out, err) {
			return nil
		}
		return formatCmdErr("nft delete table inet quadmatic", out, err)
	}
	return nil
}

func (r *Reconciler) restoreNFTables(ctx context.Context, ruleset string) error {
	trimmed := strings.TrimSpace(ruleset)
	if trimmed == "" {
		return r.deleteNFTablesIfPresent(ctx)
	}
	script := fmt.Sprintf("table inet %s\ndelete table inet %s\n%s\n", nftTableName, nftTableName, trimmed)
	out, err := r.runner.Run(ctx, []byte(script), "nft", "-f", "-")
	if err != nil {
		return formatCmdErr("nft -f - (restore)", out, err)
	}
	return nil
}

func (r *Reconciler) hasNFTablesDrift(ctx context.Context, targets []nftGuardTarget) (bool, error) {
	live, exists, err := r.readNFTables(ctx)
	if err != nil {
		return false, err
	}
	if len(targets) == 0 {
		return exists, nil
	}
	if !exists {
		return true, nil
	}
	desired, err := renderNFTablesTable(targets)
	if err != nil {
		return false, err
	}
	return normalizeNFTRuleset(live) != normalizeNFTRuleset(desired), nil
}

func normalizeNFTRuleset(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = nftCounterStatsRe.ReplaceAllString(line, "counter")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		lines = append(lines, strings.Join(fields, " "))
	}
	return strings.Join(lines, "\n")
}

func isNFTNotFoundErr(out []byte, err error) bool {
	combined := strings.ToLower(string(out) + " " + err.Error())
	return strings.Contains(combined, "no such file or directory") ||
		strings.Contains(combined, "does not exist") ||
		strings.Contains(combined, "not found")
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
