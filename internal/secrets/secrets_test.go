package secrets_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"

	"quadmatic/internal/secrets"
)

type recordedCall struct {
	stdin []byte
	name  string
	args  []string
}

type fakeExecRunner struct {
	calls []recordedCall
	out   []byte
	err   error
}

func (f *fakeExecRunner) RunWithStdin(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{
		stdin: bytes.Clone(stdin),
		name:  name,
		args:  slices.Clone(args),
	})
	return f.out, f.err
}

func encryptAge(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("age write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("age close: %v", err)
	}
	return buf.Bytes()
}

func encryptAgeArmored(t *testing.T, plaintext []byte, recipients ...age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("age write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("age close: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.Bytes()
}

func TestLoadIdentitiesAndDecryptNativeAge(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	wrongID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity (wrong): %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age.key")
	keyContent := "# generated test key\n\n" + id.String() + "\n"
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	wrongKeyPath := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrongKeyPath, []byte(wrongID.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write wrong key file: %v", err)
	}

	plaintext := []byte("super-secret-webui-token\nwith-second-line")
	ciphertext := encryptAge(t, plaintext, id.Recipient())

	ids, err := secrets.LoadIdentities(keyPath)
	if err != nil {
		t.Fatalf("LoadIdentities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(ids))
	}

	multiKeyPath := filepath.Join(dir, "multi.key")
	multiContent := "# key 1\n" + wrongID.String() + "\n# key 2\n" + id.String() + "\n"
	if err := os.WriteFile(multiKeyPath, []byte(multiContent), 0o600); err != nil {
		t.Fatalf("write multi key file: %v", err)
	}
	multiIDs, err := secrets.LoadIdentities(multiKeyPath)
	if err != nil {
		t.Fatalf("LoadIdentities(multi): %v", err)
	}
	if len(multiIDs) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(multiIDs))
	}
	if gotMulti, err := secrets.Decrypt(ciphertext, multiIDs); err != nil || !bytes.Equal(gotMulti, plaintext) {
		t.Fatalf("Decrypt(multi) = (%q, %v), want (%q, nil)", gotMulti, err, plaintext)
	}

	got, err := secrets.Decrypt(ciphertext, ids)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", got, plaintext)
	}

	armored := encryptAgeArmored(t, plaintext, id.Recipient())
	gotArmored, err := secrets.Decrypt(armored, ids)
	if err != nil {
		t.Fatalf("Decrypt armored: %v", err)
	}
	if !bytes.Equal(gotArmored, plaintext) {
		t.Fatalf("decrypted armored mismatch: got %q, want %q", gotArmored, plaintext)
	}

	wrongIDs, err := secrets.LoadIdentities(wrongKeyPath)
	if err != nil {
		t.Fatalf("LoadIdentities wrong: %v", err)
	}
	if _, err := secrets.Decrypt(ciphertext, wrongIDs); err == nil {
		t.Fatal("expected Decrypt with wrong identity to fail, got nil")
	}
}

func TestLoadIdentitiesAndDecryptSSHEd25519(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privPath, "-C", "quadmatic-test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, out)
	}

	pubBytes, err := os.ReadFile(privPath + ".pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	recipient, err := agessh.ParseRecipient(strings.TrimSpace(string(pubBytes)))
	if err != nil {
		t.Fatalf("agessh.ParseRecipient: %v", err)
	}

	plaintext := []byte("ssh-encrypted-database-password")
	ciphertext := encryptAge(t, plaintext, recipient)

	ids, err := secrets.LoadIdentities(privPath)
	if err != nil {
		t.Fatalf("LoadIdentities(ssh): %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 ssh identity, got %d", len(ids))
	}

	got, err := secrets.Decrypt(ciphertext, ids)
	if err != nil {
		t.Fatalf("Decrypt(ssh): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted ssh mismatch: got %q, want %q", got, plaintext)
	}
}

func TestLoadIdentitiesAndDecryptErrors(t *testing.T) {
	dir := t.TempDir()
	badKeyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badKeyPath, []byte("not-a-valid-age-or-ssh-key"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}

	if _, err := secrets.LoadIdentities(""); err == nil {
		t.Fatal("expected empty path to fail")
	}
	if _, err := secrets.LoadIdentities(filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("expected missing key file to fail")
	}
	if _, err := secrets.LoadIdentities(badKeyPath); err == nil {
		t.Fatal("expected invalid key file to fail")
	} else if strings.Contains(err.Error(), "not-a-valid-age-or-ssh-key") {
		t.Fatalf("error leaked key file contents: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	if _, err := secrets.Decrypt([]byte("not-ciphertext"), nil); err == nil {
		t.Fatal("expected empty identities to fail")
	}
	if _, err := secrets.Decrypt([]byte("not-ciphertext"), []age.Identity{id}); err == nil {
		t.Fatal("expected invalid ciphertext to fail")
	}
}

func TestDigest(t *testing.T) {
	plaintext := []byte("digest-payload")
	sum := sha256.Sum256(plaintext)
	want := hex.EncodeToString(sum[:])

	if got := secrets.Digest(plaintext); got != want {
		t.Fatalf("Digest = %q, want %q", got, want)
	}
}

func TestManagerUpsertPipesViaStdinNeverInArgv(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("top-secret-value-!@#")

	t.Run("rootful", func(t *testing.T) {
		runner := &fakeExecRunner{}
		mgr := secrets.NewManager(runner)

		if err := mgr.Upsert(ctx, "rootful", "webui_secret_key", plaintext); err != nil {
			t.Fatalf("Upsert rootful: %v", err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(runner.calls))
		}
		call := runner.calls[0]
		if call.name != "podman" {
			t.Fatalf("binary = %q, want podman", call.name)
		}
		wantArgs := []string{"secret", "create", "--replace", "webui_secret_key", "-"}
		if !slices.Equal(call.args, wantArgs) {
			t.Fatalf("args = %v, want %v", call.args, wantArgs)
		}
		if !bytes.Equal(call.stdin, plaintext) {
			t.Fatalf("stdin = %q, want %q", call.stdin, plaintext)
		}
		for _, arg := range call.args {
			if strings.Contains(arg, string(plaintext)) {
				t.Fatalf("plaintext leaked into argv: %q", arg)
			}
		}
	})

	t.Run("rootless", func(t *testing.T) {
		runner := &fakeExecRunner{}
		mgr := secrets.NewManager(runner)

		if err := mgr.Upsert(ctx, "openwebui", "webui_secret_key", plaintext); err != nil {
			t.Fatalf("Upsert rootless: %v", err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(runner.calls))
		}
		call := runner.calls[0]
		if call.name != "systemd-run" {
			t.Fatalf("binary = %q, want systemd-run", call.name)
		}
		wantArgs := []string{
			"--machine=openwebui@.host",
			"--user",
			"--pipe",
			"--wait",
			"--quiet",
			"podman",
			"secret",
			"create",
			"--replace",
			"webui_secret_key",
			"-",
		}
		if !slices.Equal(call.args, wantArgs) {
			t.Fatalf("args = %v, want %v", call.args, wantArgs)
		}
		if !bytes.Equal(call.stdin, plaintext) {
			t.Fatalf("stdin = %q, want %q", call.stdin, plaintext)
		}
		for _, arg := range call.args {
			if strings.Contains(arg, string(plaintext)) {
				t.Fatalf("plaintext leaked into argv: %q", arg)
			}
		}
	})

	t.Run("error does not leak plaintext", func(t *testing.T) {
		runner := &fakeExecRunner{
			out: []byte("permission denied"),
			err: errors.New("exit status 125"),
		}
		mgr := secrets.NewManager(runner)

		err := mgr.Upsert(ctx, "rootful", "webui_secret_key", plaintext)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if strings.Contains(err.Error(), string(plaintext)) {
			t.Fatalf("error leaked plaintext: %v", err)
		}
	})
}

func TestManagerRemove(t *testing.T) {
	ctx := context.Background()

	t.Run("rootful", func(t *testing.T) {
		runner := &fakeExecRunner{}
		mgr := secrets.NewManager(runner)

		if err := mgr.Remove(ctx, "rootful", "webui_secret_key"); err != nil {
			t.Fatalf("Remove rootful: %v", err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(runner.calls))
		}
		call := runner.calls[0]
		if call.name != "podman" {
			t.Fatalf("binary = %q, want podman", call.name)
		}
		wantArgs := []string{"secret", "rm", "--ignore", "webui_secret_key"}
		if !slices.Equal(call.args, wantArgs) {
			t.Fatalf("args = %v, want %v", call.args, wantArgs)
		}
		if call.stdin != nil {
			t.Fatalf("expected nil stdin for remove, got %q", call.stdin)
		}
	})

	t.Run("rootless", func(t *testing.T) {
		runner := &fakeExecRunner{}
		mgr := secrets.NewManager(runner)

		if err := mgr.Remove(ctx, "openwebui", "webui_secret_key"); err != nil {
			t.Fatalf("Remove rootless: %v", err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(runner.calls))
		}
		call := runner.calls[0]
		if call.name != "systemd-run" {
			t.Fatalf("binary = %q, want systemd-run", call.name)
		}
		wantArgs := []string{
			"--machine=openwebui@.host",
			"--user",
			"--pipe",
			"--wait",
			"--quiet",
			"podman",
			"secret",
			"rm",
			"--ignore",
			"webui_secret_key",
		}
		if !slices.Equal(call.args, wantArgs) {
			t.Fatalf("args = %v, want %v", call.args, wantArgs)
		}
		if call.stdin != nil {
			t.Fatalf("expected nil stdin for remove, got %q", call.stdin)
		}
	})
}

func TestManagerRejectsInvalidScopeAndName(t *testing.T) {
	ctx := context.Background()
	runner := &fakeExecRunner{}
	mgr := secrets.NewManager(runner)

	badScopes := []string{"", " ", "-user", "--help", ".", "..", "user@host", "user/name", "user name", "a\nb"}
	for _, scope := range badScopes {
		if err := mgr.Upsert(ctx, scope, "valid_secret", []byte("val")); err == nil {
			t.Errorf("Upsert accepted invalid scope %q", scope)
		}
		if err := mgr.Remove(ctx, scope, "valid_secret"); err == nil {
			t.Errorf("Remove accepted invalid scope %q", scope)
		}
	}

	badNames := []string{"", " ", "-replace", "--help", ".", "..", "a/b", `a\b`, "a,b", "a b", "a=b", "a\x00b"}
	for _, name := range badNames {
		if err := mgr.Upsert(ctx, "rootful", name, []byte("val")); err == nil {
			t.Errorf("Upsert accepted invalid secret name %q", name)
		}
		if err := mgr.Remove(ctx, "rootful", name); err == nil {
			t.Errorf("Remove accepted invalid secret name %q", name)
		}
	}

	if len(runner.calls) != 0 {
		t.Fatalf("expected no runner calls on validation failures, got %d", len(runner.calls))
	}

	var nilMgr *secrets.Manager
	if err := nilMgr.Upsert(ctx, "rootful", "valid_secret", []byte("val")); err == nil {
		t.Fatal("expected nil manager Upsert to fail")
	}
	if err := nilMgr.Remove(ctx, "rootful", "valid_secret"); err == nil {
		t.Fatal("expected nil manager Remove to fail")
	}
	if mgrNilRunner := secrets.NewManager(nil); mgrNilRunner == nil {
		t.Fatal("NewManager(nil) returned nil")
	}
}
