package hashutil

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	if got, want := SHA256Hex(nil), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("SHA256Hex(nil) = %q, want %q", got, want)
	}
	if got, want := SHA256Hex([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("SHA256Hex(\"abc\") = %q, want %q", got, want)
	}
	input := []byte("quadmatic")
	want := fmt.Sprintf("%x", sha256.Sum256(input))
	if got := SHA256Hex(input); got != want {
		t.Fatalf("SHA256Hex(\"quadmatic\") = %q, want %q", got, want)
	}
}
