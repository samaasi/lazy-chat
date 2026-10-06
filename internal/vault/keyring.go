package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/zalando/go-keyring"
)

// Keyring is the part of an operating-system secret store the vault needs:
// the macOS Keychain, the Linux Secret Service (GNOME Keyring, KWallet, ...)
// or the Windows Credential Manager. It is an interface so tests can supply a
// fake and so the vault does not care which one it is talking to.
type Keyring interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// Backends recorded in the key file, so a file is always opened the way it
// was created.
const (
	backendDPAPI   = "dpapi"   // Windows only
	backendKeyring = "keyring" // macOS Keychain / Linux Secret Service
)

const keyringService = "lazy-chat"

// keyringTimeout bounds calls into the secret store. A locked Linux keyring
// can wait indefinitely for the user to answer an unlock dialog. (A variable
// so tests can shorten it.)
var keyringTimeout = 30 * time.Second

// Errors specific to the OS-keychain backend.
var (
	ErrKeyNotInKeychain = errors.New("vault: this data directory's key is not in the OS keychain (it was created on another machine or account, or the keychain entry was deleted)")
	ErrKeychainMismatch = errors.New("vault: the keychain entry does not match this key file")
)

// systemKeyring talks to the real OS secret store through go-keyring. On macOS
// secrets reach the `security` tool over stdin, never as command-line
// arguments (which other users could see in the process list).
type systemKeyring struct{}

func (systemKeyring) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}

func (systemKeyring) Get(service, user string) (string, error) {
	s, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrKeyNotInKeychain
	}
	return s, err
}

func (systemKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

// keyringAccount names this data directory's entry, so several installations
// for one user (the usual testing setup) do not share or overwrite a key.
func keyringAccount(dataDir string) string {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return "vault-" + hex.EncodeToString(sum[:12])
}

// withTimeout runs fn and gives up waiting after d.
func withTimeout(d time.Duration, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		return errors.New("timed out waiting for the OS keychain (is it locked or waiting for a prompt?)")
	}
}

// probeKeyring reports whether the secret store works, by storing and removing
// a throwaway entry.
func probeKeyring(kr Keyring, timeout time.Duration) error {
	user := "probe-" + hex.EncodeToString(randomBytes(6))
	if err := withTimeout(timeout, func() error { return kr.Set(keyringService, user, "probe") }); err != nil {
		return err
	}
	return withTimeout(timeout, func() error { return kr.Delete(keyringService, user) })
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return b
}

// pickBackend decides how OS protection would work here.
//
//   - Windows uses DPAPI, which needs no service to be running, unless a
//     Keyring is injected (tests, embedding).
//   - Otherwise the injected or system keyring is used if it actually works;
//     a headless machine without a Secret Service, or a locked keychain,
//     does not.
func pickBackend(o Options) (backend string, kr Keyring, err error) {
	switch {
	case o.Keyring == nil && runtime.GOOS == "windows":
		return backendDPAPI, nil, nil
	}
	kr = o.Keyring
	if kr == nil {
		kr = systemKeyring{}
	}
	if err := probeKeyring(kr, 10*time.Second); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	return backendKeyring, kr, nil
}

// keyringProtect stores a fresh wrapping key in the OS keychain and returns the
// data key wrapped by it. The key file alone is useless without the keychain.
func keyringProtect(kr Keyring, account string, dataKey []byte) ([]byte, error) {
	kek := randomBytes(32)
	secret := hex.EncodeToString(kek)
	if err := withTimeout(keyringTimeout, func() error { return kr.Set(keyringService, account, secret) }); err != nil {
		return nil, fmt.Errorf("vault: could not store the key in the OS keychain: %w", err)
	}
	return wrapKey(kek, dataKey)
}

// keyringUnprotect reverses keyringProtect.
func keyringUnprotect(kr Keyring, account string, wrapped []byte) ([]byte, error) {
	var secret string
	err := withTimeout(keyringTimeout, func() error {
		var gerr error
		secret, gerr = kr.Get(keyringService, account)
		return gerr
	})
	if err != nil {
		if errors.Is(err, ErrKeyNotInKeychain) {
			return nil, err
		}
		return nil, fmt.Errorf("vault: could not read the key from the OS keychain: %w", err)
	}
	kek, err := hex.DecodeString(secret)
	if err != nil || len(kek) != 32 {
		return nil, ErrKeychainMismatch
	}
	key, err := unwrapKey(kek, wrapped)
	if err != nil {
		return nil, ErrKeychainMismatch
	}
	return key, nil
}
