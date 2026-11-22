package gitops

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"quadmatic/internal/config"
)

const defaultBranch = "main"

// Client manages verified Git repository fetching, signature and fast-forward
// validation, commit tree export, and historical commit file reads.
type Client struct {
	cfg           *config.HostConfig
	mu            sync.RWMutex
	activeRepoDir string
}

// NewClient constructs a Client backed by cfg.RepoDir for remote SSH fetch and verification.
func NewClient(cfg *config.HostConfig) *Client {
	var repoDir string
	if cfg != nil {
		repoDir = cfg.RepoDir
	}
	return &Client{
		cfg:           cfg,
		activeRepoDir: repoDir,
	}
}

// NewLocalClient constructs a Client targeting an existing local repository path.
func NewLocalClient(repoPath string, cfg *config.HostConfig) *Client {
	return &Client{
		cfg:           cfg,
		activeRepoDir: repoPath,
	}
}

func (c *Client) activeRepo() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeRepoDir
}

func (c *Client) setActiveRepo(repoDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeRepoDir = repoDir
}

// BuildSSHCommand constructs a hardened GIT_SSH_COMMAND string with strict host key
// checking, pinned known_hosts, and non-interactive key-only authentication.
func BuildSSHCommand(sshKey, knownHosts string) string {
	return strings.Join([]string{
		"ssh",
		"-i", shellQuote(sshKey),
		"-o", shellQuote("UserKnownHostsFile=" + knownHosts),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
	}, " ")
}

// FetchAndVerify fetches the configured branch from cfg.RepoURL over SSH into the bare
// repository at cfg.RepoDir, verifies the fetched commit's SSH signature against
// cfg.AllowedSigners, enforces fast-forward history relative to appliedSHA unless
// break-glass allowNonFF (or cfg.AllowNonFF) is enabled, and returns the verified commit SHA.
// Signature verification is never bypassed by allowNonFF.
func (c *Client) FetchAndVerify(ctx context.Context, appliedSHA string, allowNonFF bool) (string, error) {
	if c == nil || c.cfg == nil {
		return "", errors.New("host config must not be nil")
	}
	if err := validateNoControlOrLeadingDash("repo_url", c.cfg.RepoURL); err != nil {
		return "", err
	}
	branch := c.cfg.Branch
	if strings.TrimSpace(branch) == "" {
		branch = defaultBranch
	}
	if err := validateGitRefArg("branch", branch); err != nil {
		return "", err
	}
	if err := validatePathArg("repo_dir", c.cfg.RepoDir); err != nil {
		return "", err
	}
	if err := validatePathArg("ssh_key", c.cfg.SSHKey); err != nil {
		return "", err
	}
	if err := validatePathArg("ssh_known_hosts", c.cfg.SSHKnownHosts); err != nil {
		return "", err
	}
	if err := validatePathArg("allowed_signers", c.cfg.AllowedSigners); err != nil {
		return "", err
	}
	if appliedSHA != "" {
		if err := validateGitRefArg("applied_sha", appliedSHA); err != nil {
			return "", err
		}
	}

	repoDir := c.cfg.RepoDir
	if err := ensureBareRepo(ctx, repoDir, branch); err != nil {
		return "", err
	}

	// Fetch with '+' into a remote tracking ref so force-pushed tips can still
	// be retrieved and explicitly evaluated by signature and fast-forward checks
	// without mutating refs/heads/<branch> beforehand.
	remoteRef := "refs/remotes/origin/" + branch
	refspec := "+refs/heads/" + branch + ":" + remoteRef
	sshCmd := BuildSSHCommand(c.cfg.SSHKey, c.cfg.SSHKnownHosts)

	if _, err := runGit(ctx, repoDir, []string{"GIT_SSH_COMMAND=" + sshCmd}, "fetch", "--no-tags", "--", c.cfg.RepoURL, refspec); err != nil {
		return "", fmt.Errorf("fetch branch %q from %q: %w", branch, c.cfg.RepoURL, err)
	}

	newSHA, err := resolveCommitSHA(ctx, repoDir, remoteRef)
	if err != nil {
		return "", fmt.Errorf("resolve fetched branch %q: %w", branch, err)
	}

	if err := verifyCommitSignature(ctx, repoDir, c.cfg.AllowedSigners, newSHA); err != nil {
		return "", err
	}

	effectiveAllowNonFF := allowNonFF || c.cfg.AllowNonFF
	if err := enforceFastForward(ctx, repoDir, appliedSHA, newSHA, effectiveAllowNonFF); err != nil {
		return "", err
	}

	if _, err := runGit(ctx, repoDir, nil, "update-ref", "refs/heads/"+branch, newSHA); err != nil {
		return "", fmt.Errorf("update local branch %q to %s: %w", branch, newSHA, err)
	}

	c.setActiveRepo(repoDir)
	return newSHA, nil
}

// VerifyLocalRepo validates an existing local repository at repoPath without fetching.
// Unless noVerify is true, it verifies the commit's SSH signature against cfg.AllowedSigners.
// Unless allowNonFF (or cfg.AllowNonFF) is true, it enforces fast-forward history relative to appliedSHA.
func (c *Client) VerifyLocalRepo(ctx context.Context, repoPath, appliedSHA string, allowNonFF, noVerify bool) (string, error) {
	if c == nil {
		return "", errors.New("gitops client must not be nil")
	}
	if err := validatePathArg("repo_path", repoPath); err != nil {
		return "", err
	}
	if appliedSHA != "" {
		if err := validateGitRefArg("applied_sha", appliedSHA); err != nil {
			return "", err
		}
	}

	info, err := os.Stat(repoPath)
	if err != nil {
		return "", fmt.Errorf("stat local repo %q: %w", repoPath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local repo %q is not a directory", repoPath)
	}
	if _, err := runGit(ctx, repoPath, nil, "rev-parse", "--git-dir"); err != nil {
		return "", fmt.Errorf("open local git repository %q: %w", repoPath, err)
	}

	sha, err := resolveCommitSHA(ctx, repoPath, "HEAD")
	if err != nil && c.cfg != nil && strings.TrimSpace(c.cfg.Branch) != "" {
		if bErr := validateGitRefArg("branch", c.cfg.Branch); bErr == nil {
			if branchSHA, rErr := resolveCommitSHA(ctx, repoPath, "refs/heads/"+c.cfg.Branch); rErr == nil {
				sha = branchSHA
				err = nil
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("resolve local repo commit in %q: %w", repoPath, err)
	}

	if !noVerify {
		if c.cfg == nil {
			return "", errors.New("host config must not be nil when signature verification is enabled")
		}
		if err := validatePathArg("allowed_signers", c.cfg.AllowedSigners); err != nil {
			return "", err
		}
		if err := verifyCommitSignature(ctx, repoPath, c.cfg.AllowedSigners, sha); err != nil {
			return "", err
		}
	}

	effectiveAllowNonFF := allowNonFF || (c.cfg != nil && c.cfg.AllowNonFF)
	if err := enforceFastForward(ctx, repoPath, appliedSHA, sha, effectiveAllowNonFF); err != nil {
		return "", err
	}

	c.setActiveRepo(repoPath)
	return sha, nil
}

// ExportCommit extracts a clean tree for sha via `git archive` into destDir,
// rejecting path traversal, symlinks escaping destDir, and unsafe tar entry types.
func (c *Client) ExportCommit(ctx context.Context, sha, destDir string) error {
	if c == nil {
		return errors.New("gitops client must not be nil")
	}
	if err := validateGitRefArg("commit_sha", sha); err != nil {
		return err
	}
	if err := validatePathArg("dest_dir", destDir); err != nil {
		return err
	}
	repoDir := c.activeRepo()
	if strings.TrimSpace(repoDir) == "" {
		return errors.New("repository directory is not configured")
	}

	resolvedSHA, err := resolveCommitSHA(ctx, repoDir, sha)
	if err != nil {
		return fmt.Errorf("resolve commit %q for export: %w", sha, err)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create export directory %q: %w", destDir, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "git", "-C", repoDir, "archive", "--format=tar", resolvedSHA)
	cmd.Env = sanitizedGitEnv(nil)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create git archive pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start git archive for %s: %w", resolvedSHA, err)
	}

	extractErr := extractTarSafely(stdout, destDir)
	if extractErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()

	if extractErr != nil {
		return fmt.Errorf("extract commit %s to %q: %w", resolvedSHA, destDir, extractErr)
	}
	if waitErr != nil {
		return fmt.Errorf("git archive %s: %w", resolvedSHA, formatCommandErr(waitErr, stderr.Bytes(), nil))
	}
	return nil
}

// ReadFileAtCommit returns the raw contents of relPath at commit sha without
// modifying the repository working tree.
func (c *Client) ReadFileAtCommit(ctx context.Context, sha, relPath string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("gitops client must not be nil")
	}
	if err := validateGitRefArg("commit_sha", sha); err != nil {
		return nil, err
	}
	if err := validateSafeRelPath(relPath); err != nil {
		return nil, err
	}
	repoDir := c.activeRepo()
	if strings.TrimSpace(repoDir) == "" {
		return nil, errors.New("repository directory is not configured")
	}

	resolvedSHA, err := resolveCommitSHA(ctx, repoDir, sha)
	if err != nil {
		return nil, fmt.Errorf("resolve commit %q: %w", sha, err)
	}

	// Verify relPath refers to a regular file blob (not a tree or symlink).
	// Use Git's :(literal) pathspec so wildcard characters in filenames are not expanded.
	lsOut, err := runGitRaw(ctx, repoDir, nil, "ls-tree", "--full-tree", "-z", resolvedSHA, "--", ":(literal)"+relPath)
	if err != nil {
		return nil, fmt.Errorf("inspect %q at commit %s: %w", relPath, resolvedSHA, err)
	}
	if err := verifyTreeEntryRegularBlob(lsOut, relPath, resolvedSHA); err != nil {
		return nil, err
	}

	data, err := runGitRaw(ctx, repoDir, nil, "--no-pager", "show", resolvedSHA+":"+relPath)
	if err != nil {
		return nil, fmt.Errorf("read %q at commit %s: %w", relPath, resolvedSHA, err)
	}
	return data, nil
}

func ensureBareRepo(ctx context.Context, repoDir, branch string) error {
	headPath := filepath.Join(repoDir, "HEAD")
	if _, err := os.Stat(headPath); err == nil {
		isBare, bareErr := runGit(ctx, repoDir, nil, "rev-parse", "--is-bare-repository")
		if bareErr != nil {
			return fmt.Errorf("inspect existing repo %q: %w", repoDir, bareErr)
		}
		if strings.TrimSpace(isBare) != "true" {
			return fmt.Errorf("repo_dir %q exists and is not a bare repository", repoDir)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat repo_dir %q: %w", repoDir, err)
	}

	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		return fmt.Errorf("create repo_dir %q: %w", repoDir, err)
	}
	if _, err := runGit(ctx, "", nil, "init", "--bare", repoDir); err != nil {
		return fmt.Errorf("init bare repository %q: %w", repoDir, err)
	}
	if _, err := runGit(ctx, repoDir, nil, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
		return fmt.Errorf("set bare repository HEAD branch %q: %w", branch, err)
	}
	return nil
}

func resolveCommitSHA(ctx context.Context, repoDir, ref string) (string, error) {
	out, err := runGit(ctx, repoDir, nil, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if sha == "" {
		return "", fmt.Errorf("empty commit SHA for ref %q", ref)
	}
	return sha, nil
}

func verifyCommitSignature(ctx context.Context, repoDir, allowedSigners, sha string) error {
	info, err := os.Stat(allowedSigners)
	if err != nil {
		return fmt.Errorf("stat allowed_signers %q: %w", allowedSigners, err)
	}
	if info.IsDir() {
		return fmt.Errorf("allowed_signers %q must be a file, not a directory", allowedSigners)
	}
	if _, err := runGit(ctx, repoDir, nil,
		"-c", "gpg.format=ssh",
		"-c", "gpg.ssh.allowedSignersFile="+allowedSigners,
		"verify-commit", sha,
	); err != nil {
		return fmt.Errorf("verify SSH commit signature for %s: %w", sha, err)
	}
	return nil
}

func enforceFastForward(ctx context.Context, repoDir, appliedSHA, newSHA string, allowNonFF bool) error {
	if appliedSHA == "" || appliedSHA == newSHA || allowNonFF {
		return nil
	}
	if _, err := runGit(ctx, repoDir, nil, "merge-base", "--is-ancestor", appliedSHA, newSHA); err != nil {
		return fmt.Errorf("non-fast-forward update from %s to %s rejected (pass --allow-non-ff or set allow_non_ff=true to override): %w", appliedSHA, newSHA, err)
	}
	return nil
}

func verifyTreeEntryRegularBlob(lsOut []byte, relPath, sha string) error {
	trimmed := bytes.TrimSuffix(lsOut, []byte{0})
	if len(trimmed) == 0 {
		return fmt.Errorf("path %q not found at commit %s", relPath, sha)
	}
	entries := bytes.Split(trimmed, []byte{0})
	for _, entry := range entries {
		meta, entryPath, ok := strings.Cut(string(entry), "\t")
		if !ok || entryPath != relPath {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) < 3 {
			return fmt.Errorf("unexpected ls-tree output for %q at commit %s: %q", relPath, sha, string(entry))
		}
		mode, objType := fields[0], fields[1]
		if objType != "blob" {
			return fmt.Errorf("path %q at commit %s has type %q, expected regular file blob", relPath, sha, objType)
		}
		if mode != "100644" && mode != "100755" {
			return fmt.Errorf("path %q at commit %s has mode %s, expected regular file", relPath, sha, mode)
		}
		return nil
	}
	return fmt.Errorf("path %q not found at commit %s", relPath, sha)
}

func extractTarSafely(r io.Reader, destDir string) error {
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve dest directory %q: %w", destDir, err)
	}
	realDest, err := filepath.EvalSymlinks(absDest)
	if err != nil {
		return fmt.Errorf("canonicalize dest directory %q: %w", destDir, err)
	}
	info, err := os.Stat(realDest)
	if err != nil {
		return fmt.Errorf("stat dest directory %q: %w", realDest, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("dest %q is not a directory", realDest)
	}

	var createdSymlinks []string
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		}

		cleanRel, isRoot, err := validateTarEntryPath(hdr.Name, hdr.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		if isRoot {
			continue
		}

		targetPath := filepath.Join(realDest, filepath.FromSlash(cleanRel))
		if err := ensureInside(realDest, targetPath); err != nil {
			return fmt.Errorf("tar entry %q escapes destination: %w", hdr.Name, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllNoSymlinks(realDest, targetPath, 0o755); err != nil {
				return err
			}
			dirMode := (fs.FileMode(hdr.Mode) & 0o777) | 0o700
			if err := os.Chmod(targetPath, dirMode); err != nil {
				return fmt.Errorf("chmod directory %q: %w", targetPath, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			parentDir := filepath.Dir(targetPath)
			if err := mkdirAllNoSymlinks(realDest, parentDir, 0o755); err != nil {
				return err
			}
			if _, lerr := os.Lstat(targetPath); lerr == nil {
				return fmt.Errorf("tar entry %q collides with existing path", hdr.Name)
			} else if !errors.Is(lerr, os.ErrNotExist) {
				return fmt.Errorf("lstat %q: %w", targetPath, lerr)
			}

			fileMode := fs.FileMode(hdr.Mode) & 0o777
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
			if err != nil {
				return fmt.Errorf("create file %q: %w", targetPath, err)
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return fmt.Errorf("write file %q: %w", targetPath, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close file %q: %w", targetPath, closeErr)
			}

		case tar.TypeSymlink:
			if err := validateSymlinkTarget(realDest, targetPath, hdr.Name, hdr.Linkname); err != nil {
				return err
			}
			if err := mkdirAllNoSymlinks(realDest, filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			if _, lerr := os.Lstat(targetPath); lerr == nil {
				return fmt.Errorf("tar symlink %q collides with existing path", hdr.Name)
			} else if !errors.Is(lerr, os.ErrNotExist) {
				return fmt.Errorf("lstat %q: %w", targetPath, lerr)
			}
			if err := os.Symlink(filepath.FromSlash(hdr.Linkname), targetPath); err != nil {
				return fmt.Errorf("create symlink %q -> %q: %w", targetPath, hdr.Linkname, err)
			}
			createdSymlinks = append(createdSymlinks, targetPath)

		default:
			return fmt.Errorf("unsupported tar entry %q (type %q)", hdr.Name, hdr.Typeflag)
		}
	}

	// Re-verify all extracted symlinks after full extraction so out-of-order
	// chained symlinks or symlink loops cannot escape realDest.
	for _, linkPath := range createdSymlinks {
		linkTarget, err := os.Readlink(linkPath)
		if err != nil {
			return fmt.Errorf("read extracted symlink %q: %w", linkPath, err)
		}
		if _, err := resolveSymlinkWithinRoot(realDest, filepath.Dir(linkPath), linkTarget, 0); err != nil {
			for _, p := range createdSymlinks {
				_ = os.Remove(p)
			}
			return fmt.Errorf("extracted symlink %q escapes destination: %w", linkPath, err)
		}
	}
	return nil
}

func validateTarEntryPath(name string, isDir bool) (cleanRel string, isRoot bool, err error) {
	if name == "" || strings.ContainsAny(name, "\x00\r\n\\") {
		return "", false, fmt.Errorf("invalid tar entry path %q", name)
	}
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", false, fmt.Errorf("tar entry path %q must be relative", name)
	}
	if isDir && (name == "." || name == "./") {
		return "", true, nil
	}
	trimmed := name
	if isDir {
		trimmed = strings.TrimSuffix(name, "/")
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false, fmt.Errorf("tar entry path %q contains invalid segment %q", name, seg)
		}
	}
	clean := path.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, fmt.Errorf("tar entry path %q escapes destination", name)
	}
	return clean, false, nil
}

const maxSymlinkHops = 40

func validateSymlinkTarget(realDest, linkPath, entryName, linkTarget string) error {
	if linkTarget == "" || strings.ContainsAny(linkTarget, "\x00\r\n\\") {
		return fmt.Errorf("tar symlink %q has invalid target %q", entryName, linkTarget)
	}
	if strings.HasPrefix(linkTarget, "/") || filepath.IsAbs(linkTarget) {
		return fmt.Errorf("tar symlink %q has absolute target %q", entryName, linkTarget)
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(linkTarget)))
	if err := ensureInsideOrEqual(realDest, resolved); err != nil {
		return fmt.Errorf("tar symlink %q target %q escapes destination: %w", entryName, linkTarget, err)
	}
	if _, err := resolveSymlinkWithinRoot(realDest, filepath.Dir(linkPath), linkTarget, 0); err != nil {
		return fmt.Errorf("tar symlink %q target %q escapes destination: %w", entryName, linkTarget, err)
	}
	return nil
}

func resolveSymlinkWithinRoot(realDest, startDir, relTarget string, depth int) (string, error) {
	if depth > maxSymlinkHops {
		return "", errors.New("too many levels of symbolic links")
	}
	if strings.HasPrefix(relTarget, "/") || filepath.IsAbs(relTarget) {
		return "", fmt.Errorf("absolute symlink target %q", relTarget)
	}
	cur := startDir
	if err := ensureInsideOrEqual(realDest, cur); err != nil {
		return "", err
	}
	for _, seg := range strings.Split(filepath.ToSlash(relTarget), "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if cur == realDest {
				return "", fmt.Errorf("path %q escapes root %q", relTarget, realDest)
			}
			cur = filepath.Dir(cur)
		default:
			next := filepath.Join(cur, seg)
			info, err := os.Lstat(next)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					cur = next
					continue
				}
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				nextTarget, err := os.Readlink(next)
				if err != nil {
					return "", err
				}
				resolvedNext, err := resolveSymlinkWithinRoot(realDest, cur, nextTarget, depth+1)
				if err != nil {
					return "", err
				}
				cur = resolvedNext
			} else {
				cur = next
			}
		}
	}
	return cur, nil
}

func mkdirAllNoSymlinks(realDest, targetDir string, perm fs.FileMode) error {
	if err := ensureInsideOrEqual(realDest, targetDir); err != nil {
		return fmt.Errorf("directory %q escapes destination %q: %w", targetDir, realDest, err)
	}
	rel, err := filepath.Rel(realDest, targetDir)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	cur := realDest
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid directory segment %q in %q", seg, targetDir)
		}
		cur = filepath.Join(cur, seg)
		info, err := os.Lstat(cur)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to traverse symlink directory %q", cur)
			}
			if !info.IsDir() {
				return fmt.Errorf("path %q exists and is not a directory", cur)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("lstat directory %q: %w", cur, err)
		}
		if err := os.Mkdir(cur, perm); err != nil {
			return fmt.Errorf("mkdir %q: %w", cur, err)
		}
	}
	return nil
}

func ensureInside(baseDir, targetPath string) error {
	rel, err := filepath.Rel(baseDir, targetPath)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%q is outside %q", targetPath, baseDir)
	}
	return nil
}

func ensureInsideOrEqual(baseDir, targetPath string) error {
	rel, err := filepath.Rel(baseDir, targetPath)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%q is outside %q", targetPath, baseDir)
	}
	return nil
}

func validateNoControlOrLeadingDash(label, val string) error {
	if err := validatePathArg(label, val); err != nil {
		return err
	}
	if strings.HasPrefix(val, "-") {
		return fmt.Errorf("%s %q must not start with '-'", label, val)
	}
	return nil
}

func validatePathArg(label, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.ContainsAny(val, "\x00\r\n") {
		return fmt.Errorf("%s %q contains invalid control characters", label, val)
	}
	return nil
}

func validateGitRefArg(label, val string) error {
	if err := validateNoControlOrLeadingDash(label, val); err != nil {
		return err
	}
	if strings.ContainsAny(val, " \t:\\") || strings.Contains(val, "..") {
		return fmt.Errorf("%s %q contains invalid git ref characters", label, val)
	}
	return nil
}

func validateSafeRelPath(rel string) error {
	if rel == "" {
		return errors.New("relPath must not be empty")
	}
	if strings.ContainsAny(rel, "\x00\r\n\\") {
		return fmt.Errorf("relPath %q contains forbidden characters", rel)
	}
	if strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) {
		return fmt.Errorf("relPath %q must be relative", rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("relPath %q contains invalid segment %q", rel, seg)
		}
	}
	return nil
}

func shellQuote(s string) string {
	if s != "" && isShellSafeUnquoted(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isShellSafeUnquoted(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '_', '.', '/', '@', '%', '+', '=', ',', ':', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func runGit(ctx context.Context, repoDir string, extraEnv []string, args ...string) (string, error) {
	out, err := runGitRaw(ctx, repoDir, extraEnv, args...)
	return string(out), err
}

func runGitRaw(ctx context.Context, repoDir string, extraEnv []string, args ...string) ([]byte, error) {
	fullArgs := args
	if repoDir != "" {
		fullArgs = make([]string, 0, len(args)+2)
		fullArgs = append(fullArgs, "-C", repoDir)
		fullArgs = append(fullArgs, args...)
	}
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Env = sanitizedGitEnv(extraEnv)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, formatCommandErr(err, stderr.Bytes(), stdout.Bytes())
	}
	return stdout.Bytes(), nil
}

func formatCommandErr(err error, stderr, stdout []byte) error {
	detail := strings.TrimSpace(string(stderr))
	if detail == "" {
		detail = strings.TrimSpace(string(stdout))
	}
	if detail != "" {
		return fmt.Errorf("%w: %s", err, detail)
	}
	return err
}

func sanitizedGitEnv(extra []string) []string {
	blocked := map[string]bool{
		"GIT_DIR":                          true,
		"GIT_WORK_TREE":                    true,
		"GIT_INDEX_FILE":                   true,
		"GIT_OBJECT_DIRECTORY":             true,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": true,
		"GIT_COMMON_DIR":                   true,
		"GIT_CONFIG_PARAMETERS":            true,
		"GIT_CONFIG_COUNT":                 true,
		"GIT_SSH":                          true,
		"GIT_SSH_COMMAND":                  true,
		"GIT_TERMINAL_PROMPT":              true,
		"LC_ALL":                           true,
	}
	extraKeys := make(map[string]bool, len(extra))
	for _, entry := range extra {
		if k, _, ok := strings.Cut(entry, "="); ok {
			extraKeys[k] = true
		}
	}

	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra)+2)
	for _, entry := range base {
		k, _, ok := strings.Cut(entry, "=")
		if !ok || blocked[k] || extraKeys[k] {
			continue
		}
		out = append(out, entry)
	}
	out = append(out, "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	out = append(out, extra...)
	return out
}
