package gitops

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"quadmatic/internal/config"
)

func TestBuildSSHCommandFlags(t *testing.T) {
	cmd := BuildSSHCommand("/etc/quadmatic/deploy_key", "/etc/quadmatic/known_hosts")

	expectedFragments := []string{
		"-i /etc/quadmatic/deploy_key",
		"-o UserKnownHostsFile=/etc/quadmatic/known_hosts",
		"-o StrictHostKeyChecking=yes",
		"-o IdentitiesOnly=yes",
		"-o BatchMode=yes",
	}
	for _, frag := range expectedFragments {
		if !strings.Contains(cmd, frag) {
			t.Fatalf("expected %q in SSH command %q", frag, cmd)
		}
	}
	if !strings.HasPrefix(cmd, "ssh ") {
		t.Fatalf("expected SSH command to start with 'ssh ', got %q", cmd)
	}

	// Paths containing spaces and single quotes must be shell-quoted so /bin/sh
	// preserves them as single arguments without injection or word splitting.
	keyWithSpaces := "/tmp/my keys/id'ed25519"
	khWithSpaces := "/tmp/known hosts/kh'1;echo pwn"
	quotedCmd := BuildSSHCommand(keyWithSpaces, khWithSpaces)

	// Parse via /bin/sh using a dummy 'ssh' function to verify exact argv.
	shScript := `ssh() { for a in "$@"; do printf '%s\0' "$a"; done; }; ` + quotedCmd
	out, err := exec.Command("sh", "-c", shScript).Output()
	if err != nil {
		t.Fatalf("shell execution failed for %q: %v", quotedCmd, err)
	}
	args := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	wantArgs := []string{
		"-i", keyWithSpaces,
		"-o", "UserKnownHostsFile=" + khWithSpaces,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
	}
	if len(args) != len(wantArgs) {
		t.Fatalf("expected %d ssh args %q, got %d %q", len(wantArgs), wantArgs, len(args), args)
	}
	for i := range wantArgs {
		if args[i] != wantArgs[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, args[i], wantArgs[i])
		}
	}
}

func TestFetchAndVerifySetsGITSSHCommand(t *testing.T) {
	fx := setupTestGitFixture(t)
	sha := fx.commitSigned(t, "file.txt", "hello\n", "signed commit", fx.goodKey)
	fx.pushToRemote(t, "main", false)

	binDir := t.TempDir()
	argsLog := filepath.Join(t.TempDir(), "ssh-args.log")
	sshShim := filepath.Join(binDir, "ssh")
	shimContent := `#!/bin/sh
set -eu
for a in "$@"; do
  printf '%s\n' "$a" >> "` + argsLog + `"
done
# Last arg is the remote command, e.g. git-upload-pack '/repo.git'
eval "last=\${$#}"
case "$last" in
  git-upload-pack*)
    exec git-upload-pack "` + fx.remoteBare + `"
    ;;
  *)
    echo "unexpected remote cmd: $last" >&2
    exit 1
    ;;
esac
`
	if err := os.WriteFile(sshShim, []byte(shimContent), 0o755); err != nil {
		t.Fatalf("write ssh shim: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := &config.HostConfig{
		RepoURL:        "ssh://git@git.example.invalid/repo.git",
		Branch:         "main",
		SSHKey:         filepath.Join(fx.dir, "deploy_key"),
		SSHKnownHosts:  filepath.Join(fx.dir, "known_hosts"),
		AllowedSigners: fx.allowedSigners,
		RepoDir:        filepath.Join(fx.dir, "mirror.git"),
	}
	client := NewClient(cfg)
	gotSHA, err := client.FetchAndVerify(context.Background(), "", false)
	if err != nil {
		t.Fatalf("FetchAndVerify failed: %v", err)
	}
	if gotSHA != sha {
		t.Fatalf("got SHA %q, want %q", gotSHA, sha)
	}

	loggedBytes, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("read ssh args log: %v", err)
	}
	logged := string(loggedBytes)
	for _, want := range []string{
		"-i\n" + cfg.SSHKey + "\n",
		"UserKnownHostsFile=" + cfg.SSHKnownHosts + "\n",
		"StrictHostKeyChecking=yes\n",
		"IdentitiesOnly=yes\n",
		"BatchMode=yes\n",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("expected ssh args log to contain %q, got:\n%s", want, logged)
		}
	}
}

func TestVerifyCommitSignedTrustedPassesAndUntrustedOrUnsignedFails(t *testing.T) {
	fx := setupTestGitFixture(t)
	ctx := context.Background()

	// 1. Trusted signed commit passes.
	shaGood := fx.commitSigned(t, "app.txt", "trusted\n", "trusted commit", fx.goodKey)
	fx.pushToRemote(t, "main", false)

	cfg := fx.newHostConfig(filepath.Join(fx.dir, "mirror.git"))
	client := NewClient(cfg)
	got, err := client.FetchAndVerify(ctx, "", false)
	if err != nil {
		t.Fatalf("expected trusted commit to pass, got error: %v", err)
	}
	if got != shaGood {
		t.Fatalf("got SHA %q, want %q", got, shaGood)
	}

	// 2. Untrusted key signed commit fails.
	_ = fx.commitSigned(t, "app.txt", "untrusted\n", "untrusted commit", fx.badKey)
	fx.pushToRemote(t, "main", false)
	if _, err := client.FetchAndVerify(ctx, shaGood, false); err == nil {
		t.Fatalf("expected untrusted commit signature to fail")
	}
	// Verify local mirror refs/heads/main did not advance to rejected commit.
	mirrorHead := mustGit(t, cfg.RepoDir, "rev-parse", "refs/heads/main")
	if mirrorHead != shaGood {
		t.Fatalf("mirror refs/heads/main advanced on failed verify: got %q, want %q", mirrorHead, shaGood)
	}

	// 3. Unsigned commit fails.
	_ = fx.commitUnsigned(t, "app.txt", "unsigned\n", "unsigned commit")
	fx.pushToRemote(t, "main", false)
	if _, err := client.FetchAndVerify(ctx, shaGood, false); err == nil {
		t.Fatalf("expected unsigned commit to fail")
	}

	// 4. Missing allowed-signers file fails even for trusted commit.
	fx.pushResetToRemote(t, "main", shaGood)
	cfgMissing := fx.newHostConfig(filepath.Join(fx.dir, "mirror-missing.git"))
	cfgMissing.AllowedSigners = filepath.Join(fx.dir, "does-not-exist")
	if _, err := NewClient(cfgMissing).FetchAndVerify(ctx, "", false); err == nil {
		t.Fatalf("expected missing allowed-signers file to fail")
	}

	// 5. VerifyLocalRepo enforces signatures by default, allows bypass only with noVerify=true.
	localUnsigned := setupLocalRepoWithUnsignedCommit(t)
	localClient := NewClient(cfg)
	if _, err := localClient.VerifyLocalRepo(ctx, localUnsigned, "", false, false); err == nil {
		t.Fatalf("expected VerifyLocalRepo to fail on unsigned commit when noVerify=false")
	}
	shaUnsigned, err := localClient.VerifyLocalRepo(ctx, localUnsigned, "", false, true)
	if err != nil {
		t.Fatalf("expected VerifyLocalRepo with noVerify=true to succeed, got: %v", err)
	}
	if shaUnsigned == "" {
		t.Fatalf("expected non-empty SHA from VerifyLocalRepo")
	}
}

func TestFastForwardEnforcementAndBreakGlass(t *testing.T) {
	fx := setupTestGitFixture(t)
	ctx := context.Background()

	shaA := fx.commitSigned(t, "version.txt", "A\n", "commit A", fx.goodKey)
	fx.pushToRemote(t, "main", false)

	cfg := fx.newHostConfig(filepath.Join(fx.dir, "mirror.git"))
	client := NewClient(cfg)
	gotA, err := client.FetchAndVerify(ctx, "", false)
	if err != nil {
		t.Fatalf("initial fetch of A failed: %v", err)
	}
	if gotA != shaA {
		t.Fatalf("got %q, want %q", gotA, shaA)
	}

	// Advance A -> B (fast-forward).
	shaB := fx.commitSigned(t, "version.txt", "B\n", "commit B", fx.goodKey)
	fx.pushToRemote(t, "main", false)

	gotB, err := client.FetchAndVerify(ctx, shaA, false)
	if err != nil {
		t.Fatalf("fast-forward A -> B failed: %v", err)
	}
	if gotB != shaB {
		t.Fatalf("got %q, want %q", gotB, shaB)
	}

	// Force-push back to A.
	fx.pushResetToRemote(t, "main", shaA)

	// Without break-glass, non-FF must fail.
	if _, err := client.FetchAndVerify(ctx, shaB, false); err == nil {
		t.Fatalf("expected non-fast-forward rollback B -> A to fail when allowNonFF=false")
	}

	// With break-glass allowNonFF=true, validly signed A succeeds.
	gotRollback, err := client.FetchAndVerify(ctx, shaB, true)
	if err != nil {
		t.Fatalf("expected signed non-FF with allowNonFF=true to succeed, got: %v", err)
	}
	if gotRollback != shaA {
		t.Fatalf("got %q, want %q", gotRollback, shaA)
	}

	// Config-level allow_non_ff=true also enables break-glass.
	cfgAllowNonFF := fx.newHostConfig(filepath.Join(fx.dir, "mirror-cfg-nonff.git"))
	cfgAllowNonFF.AllowNonFF = true
	gotCfgRollback, err := NewClient(cfgAllowNonFF).FetchAndVerify(ctx, shaB, false)
	if err != nil {
		t.Fatalf("expected cfg.AllowNonFF=true to allow signed non-FF, got: %v", err)
	}
	if gotCfgRollback != shaA {
		t.Fatalf("got %q, want %q", gotCfgRollback, shaA)
	}

	// Force-push an unsigned commit C: break-glass MUST NEVER bypass signature verification.
	mustGit(t, fx.workDir, "reset", "--hard", shaA)
	_ = fx.commitUnsigned(t, "version.txt", "unsigned\n", "unsigned force push")
	fx.pushToRemote(t, "main", true)
	if _, err := client.FetchAndVerify(ctx, shaA, true); err == nil {
		t.Fatalf("expected unsigned force-push to fail even with allowNonFF=true")
	}

	// Local repo mode fast-forward enforcement and break-glass.
	mustGit(t, fx.workDir, "reset", "--hard", shaA)
	localClient := NewClient(cfg)
	if _, err := localClient.VerifyLocalRepo(ctx, fx.workDir, shaB, false, false); err == nil {
		t.Fatalf("expected VerifyLocalRepo non-FF to fail when allowNonFF=false")
	}
	gotLocalA, err := localClient.VerifyLocalRepo(ctx, fx.workDir, shaB, true, false)
	if err != nil {
		t.Fatalf("expected VerifyLocalRepo signed non-FF with allowNonFF=true to succeed, got: %v", err)
	}
	if gotLocalA != shaA {
		t.Fatalf("got %q, want %q", gotLocalA, shaA)
	}
}

func TestExportCommitAndReadFileAtCommit(t *testing.T) {
	fx := setupTestGitFixture(t)
	ctx := context.Background()

	// Commit 1: secret v1, config, executable script, intra-repo relative symlink, wildcard filename.
	fx.writeFile(t, "secrets/app.age", "ciphertext-v1\n", 0o644)
	fx.writeFile(t, "secrets/a*.age", "literal-star\n", 0o644)
	fx.writeFile(t, "secrets/ab.age", "not-star\n", 0o644)
	fx.writeFile(t, "components/app/run.sh", "#!/bin/sh\necho v1\n", 0o755)
	fx.writeFile(t, "docs/v1.txt", "release 1\n", 0o644)
	if err := os.Symlink("v1.txt", filepath.Join(fx.workDir, "docs", "latest")); err != nil {
		t.Fatalf("create relative symlink: %v", err)
	}
	sha1 := fx.commitAllSigned(t, "commit 1", fx.goodKey)

	// Commit 2: secret v2 + new file.
	fx.writeFile(t, "secrets/app.age", "ciphertext-v2\n", 0o644)
	fx.writeFile(t, "extra.txt", "only in v2\n", 0o644)
	sha2 := fx.commitAllSigned(t, "commit 2", fx.goodKey)
	fx.pushToRemote(t, "main", false)

	// Dirty uncommitted file in workDir must never leak into ExportCommit or ReadFileAtCommit.
	fx.writeFile(t, "secrets/app.age", "dirty-uncommitted\n", 0o644)
	fx.writeFile(t, "dirty.txt", "should not export\n", 0o644)

	// Test via mirror (FetchAndVerify -> ExportCommit & ReadFileAtCommit).
	cfg := fx.newHostConfig(filepath.Join(fx.dir, "mirror.git"))
	client := NewClient(cfg)
	gotSHA, err := client.FetchAndVerify(ctx, "", false)
	if err != nil {
		t.Fatalf("FetchAndVerify failed: %v", err)
	}
	if gotSHA != sha2 {
		t.Fatalf("got SHA %q, want %q", gotSHA, sha2)
	}

	exportV1 := filepath.Join(t.TempDir(), "export-v1")
	if err := client.ExportCommit(ctx, sha1, exportV1); err != nil {
		t.Fatalf("ExportCommit(v1) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(exportV1, ".git")); !os.IsNotExist(err) {
		t.Fatalf("expected no .git directory in exported tree")
	}
	if _, err := os.Stat(filepath.Join(exportV1, "extra.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected extra.txt from v2 to be absent from v1 export")
	}
	gotSecretExport, err := os.ReadFile(filepath.Join(exportV1, "secrets", "app.age"))
	if err != nil {
		t.Fatalf("read exported secret: %v", err)
	}
	if string(gotSecretExport) != "ciphertext-v1\n" {
		t.Fatalf("exported secret = %q, want %q", string(gotSecretExport), "ciphertext-v1\n")
	}
	info, err := os.Stat(filepath.Join(exportV1, "components", "app", "run.sh"))
	if err != nil {
		t.Fatalf("stat exported run.sh: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("expected run.sh to preserve executable bit, got %v", info.Mode().Perm())
	}
	linkTarget, err := os.Readlink(filepath.Join(exportV1, "docs", "latest"))
	if err != nil || linkTarget != "v1.txt" {
		t.Fatalf("expected intra-repo symlink docs/latest -> v1.txt, got %q (err=%v)", linkTarget, err)
	}

	// Read older commit file without mutating repository.
	v1Bytes, err := client.ReadFileAtCommit(ctx, sha1, "secrets/app.age")
	if err != nil {
		t.Fatalf("ReadFileAtCommit(v1) failed: %v", err)
	}
	if string(v1Bytes) != "ciphertext-v1\n" {
		t.Fatalf("ReadFileAtCommit(v1) = %q, want %q", string(v1Bytes), "ciphertext-v1\n")
	}

	// Literal pathspec matching prevents glob expansion on wildcard filenames.
	starBytes, err := client.ReadFileAtCommit(ctx, sha1, "secrets/a*.age")
	if err != nil || string(starBytes) != "literal-star\n" {
		t.Fatalf("ReadFileAtCommit(literal star) = %q (err=%v), want %q", string(starBytes), err, "literal-star\n")
	}

	// Test local repo mode via VerifyLocalRepo -> ExportCommit & ReadFileAtCommit.
	localClient := NewClient(cfg)
	// Reset HEAD back to sha2 cleanly for local verification, keeping dirty worktree files.
	localSHA, err := localClient.VerifyLocalRepo(ctx, fx.workDir, "", false, false)
	if err != nil {
		t.Fatalf("VerifyLocalRepo failed: %v", err)
	}
	if localSHA != sha2 {
		t.Fatalf("localSHA = %q, want %q", localSHA, sha2)
	}
	exportLocalV2 := t.TempDir()
	if err := localClient.ExportCommit(ctx, localSHA, exportLocalV2); err != nil {
		t.Fatalf("local ExportCommit failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(exportLocalV2, "dirty.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected uncommitted dirty.txt not to be exported")
	}
	localV1Bytes, err := localClient.ReadFileAtCommit(ctx, sha1, "secrets/app.age")
	if err != nil {
		t.Fatalf("local ReadFileAtCommit(v1) failed: %v", err)
	}
	if string(localV1Bytes) != "ciphertext-v1\n" {
		t.Fatalf("local ReadFileAtCommit(v1) = %q, want %q", string(localV1Bytes), "ciphertext-v1\n")
	}
	// Working tree must remain untouched.
	wtBytes, err := os.ReadFile(filepath.Join(fx.workDir, "secrets", "app.age"))
	if err != nil || string(wtBytes) != "dirty-uncommitted\n" {
		t.Fatalf("expected working tree file untouched, got %q (err=%v)", string(wtBytes), err)
	}

	// Also verify NewLocalClient works directly without calling VerifyLocalRepo first.
	directLocal := NewLocalClient(fx.workDir, cfg)
	directBytes, err := directLocal.ReadFileAtCommit(ctx, sha1, "secrets/app.age")
	if err != nil || string(directBytes) != "ciphertext-v1\n" {
		t.Fatalf("NewLocalClient ReadFileAtCommit = %q (err=%v), want ciphertext-v1", string(directBytes), err)
	}

	// Reject unsafe relPaths and non-regular objects in ReadFileAtCommit.
	badPaths := []string{
		"",
		"/",
		"/etc/passwd",
		"../etc/passwd",
		"secrets/../etc/passwd",
		"secrets/./app.age",
		`secrets\app.age`,
		"secrets/",
		"docs",        // directory (tree), not blob
		"docs/latest", // symlink, not regular file
	}
	for _, bp := range badPaths {
		if _, err := client.ReadFileAtCommit(ctx, sha1, bp); err == nil {
			t.Fatalf("expected ReadFileAtCommit(%q) to fail", bp)
		}
	}
}

func TestExportCommitRejectsSymlinkAndTarTraversal(t *testing.T) {
	ctx := context.Background()

	// Real git commit with escaping relative symlink.
	t.Run("git_escaping_relative_symlink", func(t *testing.T) {
		fx := setupTestGitFixture(t)
		if err := os.MkdirAll(filepath.Join(fx.workDir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../outside.txt", filepath.Join(fx.workDir, "sub", "escape")); err != nil {
			t.Fatal(err)
		}
		sha := fx.commitAllSigned(t, "escaping symlink", fx.goodKey)
		fx.pushToRemote(t, "main", false)

		cfg := fx.newHostConfig(filepath.Join(fx.dir, "mirror.git"))
		client := NewClient(cfg)
		if _, err := client.FetchAndVerify(ctx, "", false); err != nil {
			t.Fatalf("FetchAndVerify failed: %v", err)
		}
		dest := t.TempDir()
		if err := client.ExportCommit(ctx, sha, dest); err == nil {
			t.Fatalf("expected ExportCommit to reject escaping symlink")
		}
		if _, err := os.Lstat(filepath.Join(dest, "sub", "escape")); !os.IsNotExist(err) {
			t.Fatalf("escaping symlink should not exist in dest")
		}
	})

	// Real git commit with absolute symlink.
	t.Run("git_absolute_symlink", func(t *testing.T) {
		fx := setupTestGitFixture(t)
		if err := os.Symlink("/etc/passwd", filepath.Join(fx.workDir, "abslink")); err != nil {
			t.Fatal(err)
		}
		sha := fx.commitAllSigned(t, "abs symlink", fx.goodKey)
		fx.pushToRemote(t, "main", false)

		cfg := fx.newHostConfig(filepath.Join(fx.dir, "mirror.git"))
		client := NewClient(cfg)
		if _, err := client.FetchAndVerify(ctx, "", false); err != nil {
			t.Fatalf("FetchAndVerify failed: %v", err)
		}
		dest := t.TempDir()
		if err := client.ExportCommit(ctx, sha, dest); err == nil {
			t.Fatalf("expected ExportCommit to reject absolute symlink")
		}
	})

	// Crafted malicious tar streams covering path traversal, symlink dir pivot, hardlink escape, and special nodes.
	t.Run("crafted_malicious_tar_streams", func(t *testing.T) {
		cases := []struct {
			name    string
			entries []tarEntrySpec
		}{
			{
				name: "dotdot_traversal",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "../outside.txt", Typeflag: tar.TypeReg, Mode: 0o644}, body: "pwn"},
				},
			},
			{
				name: "absolute_path",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "/tmp/pwn.txt", Typeflag: tar.TypeReg, Mode: 0o644}, body: "pwn"},
				},
			},
			{
				name: "symlink_dir_pivot",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "sub", Typeflag: tar.TypeSymlink, Linkname: ".", Mode: 0o777}},
					{hdr: tar.Header{Name: "sub/evil.txt", Typeflag: tar.TypeReg, Mode: 0o644}, body: "pwn"},
				},
			},
			{
				name: "hardlink_escape",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "hl", Typeflag: tar.TypeLink, Linkname: "../../etc/passwd", Mode: 0o644}},
				},
			},
			{
				name: "device_node",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o600}},
				},
			},
			{
				name: "chained_symlink_escape_forward",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "a/b", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0o777}},
					{hdr: tar.Header{Name: "c", Typeflag: tar.TypeSymlink, Linkname: "a/b/..", Mode: 0o777}},
				},
			},
			{
				name: "chained_symlink_escape_reverse",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "c", Typeflag: tar.TypeSymlink, Linkname: "a/b/..", Mode: 0o777}},
					{hdr: tar.Header{Name: "a/b", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0o777}},
				},
			},
			{
				name: "symlink_loop",
				entries: []tarEntrySpec{
					{hdr: tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: "y", Mode: 0o777}},
					{hdr: tar.Header{Name: "y", Typeflag: tar.TypeSymlink, Linkname: "x", Mode: 0o777}},
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				parent := t.TempDir()
				dest := filepath.Join(parent, "dest")
				if err := os.MkdirAll(dest, 0o755); err != nil {
					t.Fatal(err)
				}
				stream := buildTestTar(t, tc.entries)
				if err := extractTarSafely(stream, dest); err == nil {
					t.Fatalf("expected extractTarSafely(%s) to fail", tc.name)
				}
				if _, err := os.Stat(filepath.Join(parent, "outside.txt")); !os.IsNotExist(err) {
					t.Fatalf("unexpected outside file created by %s", tc.name)
				}
			})
		}
	})
}

type tarEntrySpec struct {
	hdr  tar.Header
	body string
}

func buildTestTar(t *testing.T, entries []tarEntrySpec) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", hdr.Name, err)
		}
		if hdr.Typeflag == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("Write body %q: %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close tar writer: %v", err)
	}
	return &buf
}

type gitTestFixture struct {
	dir            string
	goodKey        string
	badKey         string
	allowedSigners string
	remoteBare     string
	workDir        string
}

func setupTestGitFixture(t *testing.T) *gitTestFixture {
	t.Helper()
	dir := t.TempDir()

	goodKey := filepath.Join(dir, "good_ed25519")
	badKey := filepath.Join(dir, "bad_ed25519")
	generateSSHKey(t, goodKey)
	generateSSHKey(t, badKey)

	goodPub, err := os.ReadFile(goodKey + ".pub")
	if err != nil {
		t.Fatalf("read good pubkey: %v", err)
	}
	allowedSigners := filepath.Join(dir, "allowed-signers")
	if err := os.WriteFile(allowedSigners, []byte("ci@example.lan "+strings.TrimSpace(string(goodPub))+"\n"), 0o600); err != nil {
		t.Fatalf("write allowed-signers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy_key"), []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	remoteBare := filepath.Join(dir, "remote.git")
	mustGit(t, "", "init", "--bare", "-b", "main", remoteBare)

	workDir := filepath.Join(dir, "work")
	mustGit(t, "", "init", "-b", "main", workDir)
	mustGit(t, workDir, "config", "user.name", "CI Signer")
	mustGit(t, workDir, "config", "user.email", "ci@example.lan")
	mustGit(t, workDir, "config", "gpg.format", "ssh")
	mustGit(t, workDir, "remote", "add", "origin", remoteBare)

	return &gitTestFixture{
		dir:            dir,
		goodKey:        goodKey,
		badKey:         badKey,
		allowedSigners: allowedSigners,
		remoteBare:     remoteBare,
		workDir:        workDir,
	}
}

func (fx *gitTestFixture) newHostConfig(mirrorDir string) *config.HostConfig {
	return &config.HostConfig{
		Hostname:       "test-host",
		RepoURL:        fx.remoteBare,
		Branch:         "main",
		SSHKey:         filepath.Join(fx.dir, "deploy_key"),
		SSHKnownHosts:  filepath.Join(fx.dir, "known_hosts"),
		AllowedSigners: fx.allowedSigners,
		RepoDir:        mirrorDir,
	}
}

func (fx *gitTestFixture) writeFile(t *testing.T, relPath, content string, perm os.FileMode) {
	t.Helper()
	dst := filepath.Join(fx.workDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir for %q: %v", relPath, err)
	}
	if err := os.WriteFile(dst, []byte(content), perm); err != nil {
		t.Fatalf("write %q: %v", relPath, err)
	}
}

func (fx *gitTestFixture) commitSigned(t *testing.T, relPath, content, msg, keyPath string) string {
	t.Helper()
	fx.writeFile(t, relPath, content, 0o644)
	return fx.commitAllSigned(t, msg, keyPath)
}

func (fx *gitTestFixture) commitAllSigned(t *testing.T, msg, keyPath string) string {
	t.Helper()
	mustGit(t, fx.workDir, "add", "-A")
	mustGit(t, fx.workDir, "-c", "user.signingkey="+keyPath, "commit", "-S", "-m", msg)
	return mustGit(t, fx.workDir, "rev-parse", "HEAD")
}

func (fx *gitTestFixture) commitUnsigned(t *testing.T, relPath, content, msg string) string {
	t.Helper()
	fx.writeFile(t, relPath, content, 0o644)
	mustGit(t, fx.workDir, "add", "-A")
	mustGit(t, fx.workDir, "commit", "--no-gpg-sign", "-m", msg)
	return mustGit(t, fx.workDir, "rev-parse", "HEAD")
}

func (fx *gitTestFixture) pushToRemote(t *testing.T, branch string, force bool) {
	t.Helper()
	args := []string{"push"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, "origin", "HEAD:refs/heads/"+branch)
	mustGit(t, fx.workDir, args...)
}

func (fx *gitTestFixture) pushResetToRemote(t *testing.T, branch, sha string) {
	t.Helper()
	mustGit(t, fx.workDir, "push", "--force", "origin", sha+":refs/heads/"+branch)
}

func setupLocalRepoWithUnsignedCommit(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "local")
	mustGit(t, "", "init", "-b", "main", repo)
	mustGit(t, repo, "config", "user.name", "Dev")
	mustGit(t, repo, "config", "user.email", "dev@example.lan")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, repo, "add", "-A")
	mustGit(t, repo, "commit", "--no-gpg-sign", "-m", "unsigned local")
	return repo
}

func generateSSHKey(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %q failed: %v\n%s", path, err, string(out))
	}
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	var fullArgs []string
	if dir != "" {
		fullArgs = append(fullArgs, "-C", dir)
	}
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("git", fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", fullArgs, err, string(out))
	}
	return strings.TrimSpace(string(out))
}
