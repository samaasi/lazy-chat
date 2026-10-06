package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKeyring is an in-memory secret store with switches for failures.
type fakeKeyring struct {
	mu      sync.Mutex
	items   map[string]string
	failSet error
	failGet error
	block   chan struct{} // when set, Get waits on it (a keychain waiting for a prompt)
}

func newFake() *fakeKeyring { return &fakeKeyring{items: map[string]string{}} }

func (f *fakeKeyring) Set(service, user, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet != nil {
		return f.failSet
	}
	f.items[service+"/"+user] = secret
	return nil
}

func (f *fakeKeyring) Get(service, user string) (string, error) {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failGet != nil {
		return "", f.failGet
	}
	v, ok := f.items[service+"/"+user]
	if !ok {
		return "", ErrKeyNotInKeychain
	}
	return v, nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, service+"/"+user)
	return nil
}

func (f *fakeKeyring) only() (key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.items {
		return k, v
	}
	return "", ""
}

func (f *fakeKeyring) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.items) }

func osOpts(kr Keyring) Options { return Options{Mode: ModeOS, Keyring: kr} }

func readKeyFile(t *testing.T, dir string) (keyFile, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatal(err)
	}
	return kf, raw
}

func TestKeychainVaultLifecycle(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	v, err := Open(dir, osOpts(kr))
	if err != nil || v == nil {
		t.Fatalf("create: %v", err)
	}
	sealed := v.Seal([]byte("secret"), "aad")

	// The keychain holds one entry, named for this data directory.
	key, secret := kr.only()
	if kr.count() != 1 || key != keyringService+"/"+keyringAccount(dir) {
		t.Fatalf("keychain entries: %d (%q)", kr.count(), key)
	}
	if raw, err := hex.DecodeString(secret); err != nil || len(raw) != 32 {
		t.Fatalf("the stored wrapping key should be 32 random bytes, hex encoded: %q %v", secret, err)
	}

	// The key file says how it is protected and holds nothing usable on its own.
	kf, raw := readKeyFile(t, dir)
	if kf.Mode != ModeOS || kf.Backend != backendKeyring || kf.Account != keyringAccount(dir) || kf.KDF != nil {
		t.Fatalf("key file: %+v", kf)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the keychain secret leaked into the key file")
	}

	// The same keychain reopens it and reads old data.
	again, err := Open(dir, osOpts(kr))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Open(sealed, "aad"); err != nil || string(got) != "secret" {
		t.Fatalf("reopened vault cannot read old data: %v", err)
	}
	// auto adopts what the file says.
	if _, err := Open(dir, Options{Mode: ModeAuto, Keyring: kr}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFileAloneIsUseless(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	if _, err := Open(dir, osOpts(kr)); err != nil {
		t.Fatal(err)
	}
	before, _ := readKeyFile(t, dir)

	// A stolen copy of the data directory on another machine (empty keychain).
	if _, err := Open(dir, osOpts(newFake())); !errors.Is(err, ErrKeyNotInKeychain) {
		t.Fatalf("got %v", err)
	}
	// The failure must not have replaced the key with a new one.
	if after, _ := readKeyFile(t, dir); string(after.Wrapped) != string(before.Wrapped) {
		t.Fatal("a failed unlock changed the key file")
	}

	// Entry deleted from the keychain: data is unrecoverable, and says so.
	_ = kr.Delete(keyringService, before.Account)
	if _, err := Open(dir, osOpts(kr)); !errors.Is(err, ErrKeyNotInKeychain) {
		t.Fatalf("after deleting the entry: %v", err)
	}
}

func TestTamperedKeychainEntry(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	if _, err := Open(dir, osOpts(kr)); err != nil {
		t.Fatal(err)
	}
	kf, _ := readKeyFile(t, dir)
	for name, value := range map[string]string{
		"another valid key": strings.Repeat("ab", 32),
		"not hex":           "zz-not-hex",
		"wrong length":      "abcd",
		"empty":             "",
	} {
		_ = kr.Set(keyringService, kf.Account, value)
		if _, err := Open(dir, osOpts(kr)); !errors.Is(err, ErrKeychainMismatch) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestDataDirectoriesGetSeparateKeychainEntries(t *testing.T) {
	kr := newFake()
	a, b := t.TempDir(), t.TempDir()
	va, err := Open(a, osOpts(kr))
	if err != nil {
		t.Fatal(err)
	}
	vb, err := Open(b, osOpts(kr))
	if err != nil {
		t.Fatal(err)
	}
	if kr.count() != 2 {
		t.Fatalf("%d entries; two installations must not share or overwrite one", kr.count())
	}
	if _, err := vb.Open(va.Seal([]byte("x"), "aad"), "aad"); err == nil {
		t.Fatal("two installations share a data key")
	}
	// Both still unlock.
	for _, d := range []string{a, b} {
		if _, err := Open(d, osOpts(kr)); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
}

// The key file records the keychain entry, so moving the data directory on the
// same machine keeps working.
func TestMovingTheDataDirectoryKeepsItsKey(t *testing.T) {
	kr := newFake()
	old := t.TempDir()
	v, err := Open(old, osOpts(kr))
	if err != nil {
		t.Fatal(err)
	}
	sealed := v.Seal([]byte("x"), "aad")

	moved := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(moved, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(old, KeyFileName))
	if err := os.WriteFile(filepath.Join(moved, KeyFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Open(moved, osOpts(kr))
	if err != nil {
		t.Fatalf("a moved data directory lost its key: %v", err)
	}
	if _, err := again.Open(sealed, "aad"); err != nil {
		t.Fatal(err)
	}
}

func TestUnavailableKeychain(t *testing.T) {
	broken := newFake()
	broken.failSet = errors.New("Cannot autolaunch D-Bus without X11 $DISPLAY")

	// Explicitly asking for OS protection fails clearly and creates nothing.
	dir := t.TempDir()
	if _, err := Open(dir, osOpts(broken)); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "D-Bus") {
		t.Fatalf("explicit os mode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); err == nil {
		t.Fatal("a key file was created although the keychain is unusable")
	}

	// auto falls back to a passphrase instead of leaving the user stuck.
	v, err := Open(dir, Options{Mode: ModeAuto, Keyring: broken, Passphrase: "fallback passphrase"})
	if err != nil || v == nil {
		t.Fatalf("auto fallback: %v", err)
	}
	if kf, _ := readKeyFile(t, dir); kf.Mode != ModePassphrase {
		t.Fatalf("fell back to %q, want passphrase", kf.Mode)
	}
	// ... and without a passphrase available it says what to do.
	if _, err := Open(t.TempDir(), Options{Mode: ModeAuto, Keyring: broken}); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no keychain and no passphrase: %v", err)
	}
}

func TestAutoPicksTheKeychainWhenItWorks(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	if _, err := Open(dir, Options{Mode: ModeAuto, Keyring: kr}); err != nil {
		t.Fatal(err)
	}
	if kf, _ := readKeyFile(t, dir); kf.Mode != ModeOS || kf.Backend != backendKeyring {
		t.Fatalf("auto chose %+v", kf)
	}
	if kr.count() != 1 {
		t.Fatalf("the probe entry was not cleaned up (%d entries)", kr.count())
	}
}

func TestFailedKeyFileWriteDoesNotLeaveAKeychainEntryBehind(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	// A directory where the key file should go makes the write fail.
	if err := os.Mkdir(filepath.Join(dir, KeyFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, osOpts(kr)); err == nil {
		t.Fatal("expected an error")
	}
	if kr.count() != 0 {
		t.Fatalf("%d orphan keychain entries", kr.count())
	}
}

func TestHungKeychainDoesNotHangTheProgram(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	if _, err := Open(dir, osOpts(kr)); err != nil {
		t.Fatal(err)
	}
	kr.block = make(chan struct{})
	defer close(kr.block)
	old := keyringTimeout
	keyringTimeout = 100 * time.Millisecond
	defer func() { keyringTimeout = old }()

	start := time.Now()
	_, err := Open(dir, osOpts(kr))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("took too long to give up")
	}
}

func TestBackendMismatchesAreRefused(t *testing.T) {
	dir, kr := t.TempDir(), newFake()
	if _, err := Open(dir, osOpts(kr)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, passOpts("some passphrase")); !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("passphrase requested for a keychain vault: %v", err)
	}
	if _, err := Open(dir, Options{Mode: ModeOff}); !errors.Is(err, ErrEncryptedData) {
		t.Fatalf("off on encrypted data: %v", err)
	}

	if runtime.GOOS != "windows" {
		// A DPAPI key file carried over from Windows cannot be used here.
		other := t.TempDir()
		kf := keyFile{Version: fileVersion, Mode: ModeOS, Backend: backendDPAPI, Wrapped: []byte("blob")}
		data, _ := json.Marshal(kf)
		_ = os.WriteFile(filepath.Join(other, KeyFileName), data, 0o600)
		if _, err := Open(other, osOpts(kr)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("DPAPI file on %s: %v", runtime.GOOS, err)
		}
	}
	// Unknown backends are corruption, not a guess.
	bad := t.TempDir()
	data, _ := json.Marshal(keyFile{Version: fileVersion, Mode: ModeOS, Backend: "rot13", Wrapped: []byte("x")})
	_ = os.WriteFile(filepath.Join(bad, KeyFileName), data, 0o600)
	if _, err := Open(bad, osOpts(kr)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown backend: %v", err)
	}
}

func TestKeyringAccountIsStableAndDirectorySpecific(t *testing.T) {
	a := keyringAccount("/some/dir")
	if a != keyringAccount("/some/dir/") || a != keyringAccount("/some/other/../dir") {
		t.Fatal("equivalent paths must map to one account")
	}
	if a == keyringAccount("/some/dir2") || !strings.HasPrefix(a, "vault-") {
		t.Fatalf("account %q", a)
	}
}

// ---- The real operating-system store -----------------------------------------------------

// Runs against the actual secret store: always on Windows (Credential Manager)
// and, elsewhere, when LAZYCHAT_TEST_KEYRING=1 (it needs an unlocked login
// keychain on macOS or a running Secret Service on Linux).
func TestRealSystemKeyring(t *testing.T) {
	if runtime.GOOS != "windows" && os.Getenv("LAZYCHAT_TEST_KEYRING") != "1" {
		t.Skip("set LAZYCHAT_TEST_KEYRING=1 to test the real OS keychain")
	}
	kr := systemKeyring{}
	account := fmt.Sprintf("test-%x", randomBytes(6))
	t.Cleanup(func() { _ = kr.Delete(keyringService, account) })

	if _, err := kr.Get(keyringService, account); !errors.Is(err, ErrKeyNotInKeychain) {
		t.Fatalf("a missing entry must report ErrKeyNotInKeychain, got %v", err)
	}
	if err := probeKeyring(kr, 20*time.Second); err != nil {
		t.Fatalf("the system keyring does not work here: %v", err)
	}

	// Our own wrapping scheme against the real store.
	dataKey := randomBytes(32)
	wrapped, err := keyringProtect(kr, account, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keyringUnprotect(kr, account, wrapped)
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(dataKey) {
		t.Fatalf("round trip through the OS store failed: %v", err)
	}
	if err := kr.Delete(keyringService, account); err != nil {
		t.Fatal(err)
	}
	if _, err := keyringUnprotect(kr, account, wrapped); !errors.Is(err, ErrKeyNotInKeychain) {
		t.Fatalf("after deletion: %v", err)
	}
}
