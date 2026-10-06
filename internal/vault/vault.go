// Package vault provides encryption at rest.
//
// A random 256-bit data key encrypts the sensitive fields of the local
// database and the private identity key file (AES-256-GCM, a fresh random
// nonce per value, and the value's location mixed in as associated data so
// ciphertexts cannot be moved between rows or fields). The data key itself is
// stored wrapped, in <data-dir>/vault.key, in one of two ways:
//
//   - passphrase: wrapped with a key derived from a passphrase using Argon2id.
//     Works everywhere; the passphrase is asked for at start-up (or read from
//     --passphrase-file / P2P_PASSPHRASE for unattended use).
//   - os: wrapped with the operating system's per-user protection (Windows
//     DPAPI). Seamless - nothing to type - and bound to the user account.
//
// "auto" (the default) uses the OS mode where it exists and the passphrase
// mode elsewhere. Losing the passphrase means losing the data: there is no
// recovery path by design.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KeyFileName is the wrapped data key inside the data directory.
const KeyFileName = "vault.key"

// EnvPassphrase names the environment variable that may carry the passphrase.
// It is removed from the process environment as soon as it is read, so child
// processes (such as notification helpers) do not inherit it.
const EnvPassphrase = "P2P_PASSPHRASE"

// MinPassphraseLen is the shortest passphrase accepted when creating a vault.
const MinPassphraseLen = 8

const (
	sealedPrefix = "e1:"
	fileVersion  = 1
	wrapAAD      = "lazy-chat/vault/wrap/v1"
	osEntropy    = "lazy-chat/vault/dpapi/v1"
)

// Mode selects how the data key is protected.
type Mode string

const (
	ModeAuto       Mode = "auto"
	ModePassphrase Mode = "passphrase"
	ModeOS         Mode = "os"
	ModeOff        Mode = "off"
)

// Errors returned by Open.
var (
	ErrWrongPassphrase = errors.New("vault: wrong passphrase")
	ErrEncryptedData   = errors.New("vault: data in this directory is encrypted, but encryption is switched off")
	ErrNoPassphrase    = errors.New("vault: a passphrase is required (type it, or use --passphrase-file or " + EnvPassphrase + ")")
	ErrWeakPassphrase  = errors.New("vault: passphrase is too short")
	ErrUnsupported     = errors.New("vault: OS-protected keys are not available on this platform; use passphrase mode")
	ErrCorrupt         = errors.New("vault: key file is damaged")
	ErrModeMismatch    = errors.New("vault: the existing key file uses a different protection mode")
)

// Vault encrypts and decrypts values with the data key. It is immutable and
// safe for concurrent use.
type Vault struct {
	aead cipher.AEAD
}

// New creates a Vault from a 32-byte data key.
func New(dataKey []byte) (*Vault, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Seal encrypts plaintext. aad names where the value lives (for example
// "messages.content|sender|id"); Open must be given the same string.
func (v *Vault) Seal(plaintext []byte, aad string) string {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err)) // see utils.NewID
	}
	out := v.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(out)
}

// Open decrypts a value produced by Seal.
func (v *Vault) Open(sealed, aad string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return nil, errors.New("vault: value is not encrypted")
	}
	raw, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil || len(raw) < v.aead.NonceSize()+v.aead.Overhead() {
		return nil, errors.New("vault: malformed ciphertext")
	}
	n := v.aead.NonceSize()
	plain, err := v.aead.Open(nil, raw[:n], raw[n:], []byte(aad))
	if err != nil {
		return nil, errors.New("vault: ciphertext failed authentication (wrong key, or data was moved or altered)")
	}
	return plain, nil
}

// ---- Key file ---------------------------------------------------------------

type kdfParams struct {
	Name    string `json:"name"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
}

type keyFile struct {
	Version int        `json:"version"`
	Mode    Mode       `json:"mode"`
	KDF     *kdfParams `json:"kdf,omitempty"`
	Wrapped []byte     `json:"wrapped"` // nonce || AES-GCM(data key)
}

// defaultKDF are the Argon2id parameters used for new vaults (OWASP's
// recommended minimum profile: 64 MiB, 3 passes). Tests lower them.
var defaultKDF = kdfParams{Name: "argon2id", Time: 3, Memory: 64 * 1024, Threads: 4}

const (
	maxKDFMemoryKiB = 1 << 20 // refuse to allocate more than 1 GiB for a key file's parameters
	maxKDFTime      = 20
)

func deriveKEK(passphrase string, p *kdfParams) ([]byte, error) {
	if p.Name != "argon2id" || p.Time == 0 || p.Time > maxKDFTime || p.Memory < 8 ||
		p.Memory > maxKDFMemoryKiB || p.Threads == 0 || len(p.Salt) < 16 {
		return nil, ErrCorrupt
	}
	return argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, 32), nil
}

func wrapKey(kek, dataKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, dataKey, []byte(wrapAAD)), nil
}

func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(wrapped) < n+aead.Overhead() {
		return nil, ErrCorrupt
	}
	key, err := aead.Open(nil, wrapped[:n], wrapped[n:], []byte(wrapAAD))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return key, nil
}

func writeKeyFile(path string, kf keyFile) error {
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// ---- Opening ----------------------------------------------------------------

// Options controls how Open obtains the passphrase and which mode it uses.
type Options struct {
	Mode Mode
	// Passphrase, when set, is used directly.
	Passphrase string
	// PassphraseFile names a file whose first line is the passphrase.
	PassphraseFile string
	// Prompt asks the user interactively; confirm is true when a new
	// passphrase is being chosen. May be nil for unattended use.
	Prompt func(confirm bool) (string, error)
	// Getenv overrides os.Getenv (and skips unsetting) - for tests.
	Getenv func(string) string
}

// Open returns the vault for dataDir, creating the key file on first use.
// It returns (nil, nil) when Mode is off and no encrypted data exists.
func Open(dataDir string, o Options) (*Vault, error) {
	if o.Mode == "" {
		o.Mode = ModeAuto
	}
	path := filepath.Join(dataDir, KeyFileName)

	raw, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	if o.Mode == ModeOff {
		if exists {
			return nil, ErrEncryptedData
		}
		return nil, nil
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if exists {
		return openExisting(raw, o)
	}
	return create(path, o)
}

func openExisting(raw []byte, o Options) (*Vault, error) {
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil || kf.Version != fileVersion {
		return nil, ErrCorrupt
	}
	if (o.Mode == ModePassphrase || o.Mode == ModeOS) && o.Mode != kf.Mode {
		return nil, fmt.Errorf("%w (file: %s, requested: %s)", ErrModeMismatch, kf.Mode, o.Mode)
	}

	var dataKey []byte
	var err error
	switch kf.Mode {
	case ModePassphrase:
		if kf.KDF == nil {
			return nil, ErrCorrupt
		}
		pass, perr := passphrase(o, false)
		if perr != nil {
			return nil, perr
		}
		kek, kerr := deriveKEK(pass, kf.KDF)
		if kerr != nil {
			return nil, kerr
		}
		dataKey, err = unwrapKey(kek, kf.Wrapped)
	case ModeOS:
		dataKey, err = osUnprotect(kf.Wrapped)
	default:
		return nil, ErrCorrupt
	}
	if err != nil {
		return nil, err
	}
	if len(dataKey) != 32 {
		return nil, ErrCorrupt
	}
	return New(dataKey)
}

func create(path string, o Options) (*Vault, error) {
	mode := o.Mode
	if mode == ModeAuto {
		mode = ModePassphrase
		if runtime.GOOS == "windows" {
			mode = ModeOS
		}
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	kf := keyFile{Version: fileVersion, Mode: mode}

	switch mode {
	case ModePassphrase:
		pass, err := passphrase(o, true)
		if err != nil {
			return nil, err
		}
		if len([]rune(pass)) < MinPassphraseLen {
			return nil, fmt.Errorf("%w (minimum %d characters)", ErrWeakPassphrase, MinPassphraseLen)
		}
		p := defaultKDF
		p.Salt = make([]byte, 16)
		if _, err := rand.Read(p.Salt); err != nil {
			return nil, err
		}
		kek, err := deriveKEK(pass, &p)
		if err != nil {
			return nil, err
		}
		if kf.Wrapped, err = wrapKey(kek, dataKey); err != nil {
			return nil, err
		}
		kf.KDF = &p
	case ModeOS:
		blob, err := osProtect(dataKey)
		if err != nil {
			return nil, err
		}
		kf.Wrapped = blob
	default:
		return nil, fmt.Errorf("vault: unknown mode %q", o.Mode)
	}

	if err := writeKeyFile(path, kf); err != nil {
		return nil, err
	}
	return New(dataKey)
}

// passphrase finds the passphrase: explicit value, file, environment, prompt.
func passphrase(o Options, confirm bool) (string, error) {
	if o.Passphrase != "" {
		return o.Passphrase, nil
	}
	if o.PassphraseFile != "" {
		data, err := os.ReadFile(o.PassphraseFile)
		if err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
		line, _, _ := strings.Cut(string(data), "\n")
		if line = strings.TrimRight(line, "\r"); line != "" {
			return line, nil
		}
		return "", fmt.Errorf("passphrase file %s is empty", o.PassphraseFile)
	}
	getenv := o.Getenv
	if getenv == nil {
		getenv = func(k string) string {
			v := os.Getenv(k)
			if v != "" {
				_ = os.Unsetenv(k) // keep it away from child processes
			}
			return v
		}
	}
	if v := getenv(EnvPassphrase); v != "" {
		return v, nil
	}
	if o.Prompt != nil {
		return o.Prompt(confirm)
	}
	return "", ErrNoPassphrase
}
