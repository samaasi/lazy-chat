package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/samaasi/lazy-chat/internal/vault"
)

func testVault(t *testing.T, b byte) *vault.Vault {
	t.Helper()
	v, err := vault.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealedKeyIsEncryptedOnDiskAndStable(t *testing.T) {
	dir := t.TempDir()
	v := testVault(t, 1)
	first, err := LoadOrCreateSealed(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, KeyFileName))
	if !bytes.HasPrefix(raw, []byte(sealedHeader)) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatalf("private key not encrypted on disk:\n%s", raw)
	}
	second, err := LoadOrCreateSealed(dir, v)
	if err != nil || second.ID() != first.ID() {
		t.Fatalf("identity changed or failed to load: %v", err)
	}
}

func TestPlaintextKeyIsEncryptedInPlace(t *testing.T) {
	dir := t.TempDir()
	before, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, KeyFileName)
	if raw, _ := os.ReadFile(path); !bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("setup: expected a plaintext key")
	}

	v := testVault(t, 2)
	after, err := LoadOrCreateSealed(dir, v)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID() != before.ID() {
		t.Fatal("encrypting the key changed the peer's identity")
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || !bytes.HasPrefix(raw, []byte(sealedHeader)) {
		t.Fatal("plaintext key was left on disk")
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temporary file left behind")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	if again, err := LoadOrCreateSealed(dir, v); err != nil || again.ID() != before.ID() {
		t.Fatalf("reload after migration: %v", err)
	}
}

func TestSealedKeyIsNeverReplacedByANewIdentity(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreateSealed(dir, testVault(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, KeyFileName)
	orig, _ := os.ReadFile(path)

	if _, err := LoadOrCreate(dir); !errors.Is(err, ErrSealed) {
		t.Fatalf("no sealer: got %v, want ErrSealed", err)
	}
	if _, err := LoadOrCreateSealed(dir, testVault(t, 4)); err == nil {
		t.Fatal("opened with the wrong key")
	}
	tampered := bytes.Clone(orig)
	tampered[len(tampered)-5] ^= 1
	_ = os.WriteFile(path, tampered, 0o600)
	if _, err := LoadOrCreateSealed(dir, testVault(t, 3)); err == nil {
		t.Fatal("tampered key file accepted")
	}

	// Through all of that the original file must be unchanged or recoverable.
	_ = os.WriteFile(path, orig, 0o600)
	if back, err := LoadOrCreateSealed(dir, testVault(t, 3)); err != nil || back.ID() != id.ID() {
		t.Fatalf("original key lost: %v", err)
	}
}
