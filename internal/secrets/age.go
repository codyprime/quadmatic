package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

// LoadIdentities reads an age or OpenSSH private key file into memory and parses
// its identities. Native age identities are tried first; if that fails, it falls
// back to agessh.ParseIdentity for unencrypted SSH keys (such as Ed25519).
func LoadIdentities(path string) ([]age.Identity, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("identity path must not be empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file %q: %w", path, err)
	}
	defer clear(raw)

	if ids, err := age.ParseIdentities(bytes.NewReader(raw)); err == nil {
		return ids, nil
	}

	if sshID, err := agessh.ParseIdentity(raw); err == nil {
		return []age.Identity{sshID}, nil
	}

	return nil, fmt.Errorf("parse identities from %q: file is neither a valid age key file nor a supported SSH private key", path)
}

// Decrypt decrypts an age-encrypted payload (binary or ASCII-armored) purely in
// memory using the supplied identities.
func Decrypt(ciphertext []byte, ids []age.Identity) ([]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no age identities provided")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}

	var src io.Reader = bytes.NewReader(ciphertext)
	if bytes.HasPrefix(bytes.TrimSpace(ciphertext), []byte(armor.Header)) {
		src = armor.NewReader(bytes.NewReader(ciphertext))
	}

	r, err := age.Decrypt(src, ids...)
	if err != nil {
		return nil, fmt.Errorf("decrypt age payload: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted age payload: %w", err)
	}
	return plaintext, nil
}

// Digest returns the lowercase hexadecimal SHA-256 digest of plaintext.
func Digest(plaintext []byte) string {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:])
}
