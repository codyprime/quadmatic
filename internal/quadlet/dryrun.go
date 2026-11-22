package quadlet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"quadmatic/internal/manifest"
)

// DefaultQuadletBinary is the standard Fedora CoreOS path to the Podman quadlet generator.
const DefaultQuadletBinary = "/usr/libexec/podman/quadlet"

// GeneratedUnit holds a single systemd unit emitted by `quadlet --dryrun`.
type GeneratedUnit struct {
	Scope      string
	UnitName   string
	Content    string
	SHA256     string
	SecretRefs []string
}

// CommandRunner executes external commands with an explicit environment.
type CommandRunner interface {
	RunEnv(ctx context.Context, env []string, name string, args ...string) (stdout, stderr []byte, err error)
}

type execCommandRunner struct{}

func (execCommandRunner) RunEnv(ctx context.Context, env []string, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Validator stages rendered quadlet files and runs `quadlet --dryrun` per scope.
type Validator struct {
	binaryPath string
	runner     CommandRunner
}

// NewValidator constructs a Validator using binaryPath (defaulting to DefaultQuadletBinary
// when empty) and runner (defaulting to os/exec when nil).
func NewValidator(binaryPath string, runner CommandRunner) *Validator {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = DefaultQuadletBinary
	}
	if runner == nil {
		runner = execCommandRunner{}
	}
	return &Validator{
		binaryPath: binaryPath,
		runner:     runner,
	}
}

type scopeStage struct {
	destDir string
	files   map[string][]byte
}

// ValidateHost validates every rendered quadlet scope in host using `quadlet --dryrun`
// and returns all generated units keyed by "<scope>/<unitName>".
func (v *Validator) ValidateHost(ctx context.Context, host *manifest.RenderedHost) (map[string]GeneratedUnit, error) {
	if host == nil {
		return nil, fmt.Errorf("rendered host is nil")
	}

	scopes, err := collectScopeStages(host)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return map[string]GeneratedUnit{}, nil
	}

	scopeNames := make([]string, 0, len(scopes))
	for s := range scopes {
		scopeNames = append(scopeNames, s)
	}
	slices.Sort(scopeNames)

	result := make(map[string]GeneratedUnit)
	for _, scope := range scopeNames {
		units, err := v.validateScope(ctx, scope, scopes[scope])
		if err != nil {
			return nil, err
		}
		for k, u := range units {
			result[k] = u
		}
	}
	return result, nil
}

func collectScopeStages(host *manifest.RenderedHost) (map[string]*scopeStage, error) {
	stages := make(map[string]*scopeStage)
	for _, comp := range host.Components {
		scope := comp.Scope()
		if !comp.Rootful && strings.TrimSpace(scope) == "" {
			return nil, fmt.Errorf("rootless component %q has empty user scope", comp.Name)
		}

		for _, f := range comp.Files {
			if f.Kind != manifest.FileKindQuadlet {
				continue
			}
			cleanRel := filepath.ToSlash(filepath.Clean(f.RelPath))
			if cleanRel == "." || cleanRel == "" || strings.HasPrefix(cleanRel, "/") || strings.HasPrefix(cleanRel, "../") || strings.Contains(cleanRel, "/../") {
				return nil, fmt.Errorf("component %q quadlet file %q has invalid relative path", comp.Name, f.RelPath)
			}

			st, ok := stages[scope]
			if !ok {
				st = &scopeStage{
					destDir: scopeQuadletDir(comp),
					files:   make(map[string][]byte),
				}
				stages[scope] = st
			}
			if _, dup := st.files[cleanRel]; dup {
				return nil, fmt.Errorf("duplicate quadlet %q in scope %q", cleanRel, scope)
			}
			st.files[cleanRel] = f.Content
		}
	}
	return stages, nil
}

func scopeQuadletDir(comp manifest.RenderedComponent) string {
	if comp.Rootful {
		return "/etc/containers/systemd"
	}
	return path.Join("/etc/containers/systemd/users", strconv.Itoa(comp.UID))
}

func (v *Validator) validateScope(ctx context.Context, scope string, stage *scopeStage) (map[string]GeneratedUnit, error) {
	stageDir, err := os.MkdirTemp("", "quadmatic-quadlet-*")
	if err != nil {
		return nil, fmt.Errorf("create temp stage dir for scope %q: %w", scope, err)
	}
	defer os.RemoveAll(stageDir)

	for relPath, content := range stage.files {
		dst := filepath.Join(stageDir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, fmt.Errorf("create stage subdir for %s/%s: %w", scope, relPath, err)
		}
		if err := os.WriteFile(dst, content, 0o644); err != nil {
			return nil, fmt.Errorf("stage quadlet %s/%s: %w", scope, relPath, err)
		}
	}

	args := []string{"--dryrun"}
	if scope != "rootful" {
		args = append(args, "--user")
	}
	env := withEnv(os.Environ(), "QUADLET_UNIT_DIRS", stageDir)

	stdout, stderr, err := v.runner.RunEnv(ctx, env, v.binaryPath, args...)
	if err != nil {
		detail := strings.TrimSpace(string(stderr))
		if detail == "" {
			detail = strings.TrimSpace(string(stdout))
		}
		if detail != "" {
			return nil, fmt.Errorf("quadlet dry-run failed for scope %q: %w: %s", scope, err, detail)
		}
		return nil, fmt.Errorf("quadlet dry-run failed for scope %q: %w", scope, err)
	}

	// Normalize ephemeral stageDir paths (such as SourcePath=<stageDir>/...) to the
	// deterministic target quadlet directory so generated SHA-256 digests are reproducible.
	normalized := bytes.ReplaceAll(stdout, []byte(stageDir), []byte(stage.destDir))
	units := ParseDryRunOutput(scope, normalized)

	for key, unit := range units {
		if srcName, ok := resolveSourceQuadlet(unit, stage.files); ok {
			merged := mergeSecretRefs(unit.SecretRefs, extractSecretsFromQuadlet(stage.files[srcName]))
			unit.SecretRefs = merged
			units[key] = unit
		}
	}
	return units, nil
}

// ParseDryRunOutput parses `---<unitName>---` sections from `quadlet --dryrun` stdout,
// computes each unit's SHA-256 digest, and extracts referenced Podman secret names.
// Returned entries are keyed by "<scope>/<unitName>" when scope is non-empty.
func ParseDryRunOutput(scope string, stdout []byte) map[string]GeneratedUnit {
	units := make(map[string]GeneratedUnit)
	lines := strings.Split(string(stdout), "\n")

	var currentUnit string
	var currentLines []string

	flush := func() {
		if currentUnit == "" {
			return
		}
		content := normalizeUnitContent(currentLines)
		key := unitKey(scope, currentUnit)
		units[key] = GeneratedUnit{
			Scope:      scope,
			UnitName:   currentUnit,
			Content:    content,
			SHA256:     sha256Hex([]byte(content)),
			SecretRefs: extractSecretsFromGenerated(content),
		}
	}

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		if unitName, ok := parseUnitDelimiter(line); ok {
			flush()
			currentUnit = unitName
			currentLines = currentLines[:0]
			continue
		}
		if currentUnit != "" {
			currentLines = append(currentLines, line)
		}
	}
	flush()

	return units
}

func parseUnitDelimiter(line string) (string, bool) {
	if !strings.HasPrefix(line, "---") || !strings.HasSuffix(line, "---") || len(line) <= 6 {
		return "", false
	}
	name := strings.TrimSpace(line[3 : len(line)-3])
	if name == "" || strings.ContainsAny(name, " \t/") {
		return "", false
	}
	return name, true
}

func normalizeUnitContent(lines []string) string {
	joined := strings.Join(lines, "\n")
	trimmed := strings.Trim(joined, "\r\n")
	if trimmed == "" {
		return ""
	}
	return trimmed + "\n"
}

func unitKey(scope, unitName string) string {
	if scope == "" {
		return unitName
	}
	return scope + "/" + unitName
}

func resolveSourceQuadlet(unit GeneratedUnit, files map[string][]byte) (string, bool) {
	for _, rawLine := range strings.Split(unit.Content, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "SourcePath=") {
			srcBase := path.Base(strings.TrimSpace(strings.TrimPrefix(line, "SourcePath=")))
			if _, ok := files[srcBase]; ok {
				return srcBase, true
			}
		}
	}

	// Fallback to standard quadlet unit-to-source naming conventions when SourcePath=
	// is absent (for example in minimal synthetic unit tests).
	candidates := quadletSourceCandidates(unit.UnitName)
	for _, cand := range candidates {
		if _, ok := files[cand]; ok {
			return cand, true
		}
	}
	return "", false
}

func quadletSourceCandidates(unitName string) []string {
	if !strings.HasSuffix(unitName, ".service") {
		return nil
	}
	stem := strings.TrimSuffix(unitName, ".service")
	suffixMap := []struct {
		unitSuffix string
		ext        string
	}{
		{"-volume", ".volume"},
		{"-network", ".network"},
		{"-pod", ".pod"},
		{"-image", ".image"},
		{"-kube", ".kube"},
		{"-build", ".build"},
	}
	for _, m := range suffixMap {
		if strings.HasSuffix(stem, m.unitSuffix) {
			return []string{strings.TrimSuffix(stem, m.unitSuffix) + m.ext}
		}
	}
	return []string{stem + ".container"}
}

func extractSecretsFromQuadlet(content []byte) []string {
	return extractSecretsFromLines(string(content), false)
}

func extractSecretsFromGenerated(content string) []string {
	return extractSecretsFromLines(content, true)
}

func extractSecretsFromLines(text string, includeCLIFlags bool) []string {
	var refs []string
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "Secret" {
			if name := parseSecretName(v); name != "" {
				refs = append(refs, name)
			}
		}
		if includeCLIFlags {
			fields := strings.Fields(line)
			for i := 0; i < len(fields); i++ {
				tok := fields[i]
				switch {
				case tok == "--secret" && i+1 < len(fields):
					if name := parseSecretName(fields[i+1]); name != "" {
						refs = append(refs, name)
					}
					i++
				case strings.HasPrefix(tok, "--secret="):
					if name := parseSecretName(strings.TrimPrefix(tok, "--secret=")); name != "" {
						refs = append(refs, name)
					}
				}
			}
		}
	}
	return dedupSorted(refs)
}

func parseSecretName(raw string) string {
	val := strings.TrimSpace(raw)
	if idx := strings.IndexByte(val, ','); idx >= 0 {
		val = val[:idx]
	}
	val = strings.TrimSpace(val)
	val = strings.Trim(val, "\"'")
	return val
}

func mergeSecretRefs(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	combined := make([]string, 0, len(a)+len(b))
	combined = append(combined, a...)
	combined = append(combined, b...)
	return dedupSorted(combined)
}

func dedupSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	sorted := slices.Clone(items)
	slices.Sort(sorted)
	out := sorted[:0]
	for _, item := range sorted {
		if item == "" {
			continue
		}
		if len(out) == 0 || out[len(out)-1] != item {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func withEnv(base []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	out = append(out, prefix+value)
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
