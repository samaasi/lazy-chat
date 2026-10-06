package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// Real Argon2id parameters cost ~100 ms and 64 MiB each; tests use cheap ones.
	defaultKDF.Time, defaultKDF.Memory, defaultKDF.Threads = 1, 64, 1
	os.Exit(m.Run())
}

func passOpts(pass string) Options { return Options{Mode: ModePassphrase, Passphrase: pass} }

func TestSealOpenRoundTripAndBinding(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s1, s2 := v.Seal([]byte("hello"), "messages.content|a|1"), v.Seal([]byte("hello"), "messages.content|a|1")
	if s1 == s2 {
		t.Fatal("identical plaintexts produced identical ciphertexts (nonce reuse)")
	}
	if !strings.HasPrefix(s1, "e1:") || strings.Contains(s1, "hello") {
		t.Fatalf("unexpected sealed form %q", s1)
	}
	got, err := v.Open(s1, "messages.content|a|1")
	if err != nil || string(got) != "hello" {
		t.Fatalf("Open: %q %v", got, err)
	}

	// A ciphertext cannot be moved to another row or field.
	if _, err := v.Open(s1, "messages.content|a|2"); err == nil {
		t.Fatal("ciphertext opened under a different location")
	}
	// Tampering, truncation, wrong key, and values that were never sealed.
	flipped := s1[:len(s1)-2] + string(rune(s1[len(s1)-2]^1)) + s1[len(s1)-1:]
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	for name, in := range map[string]string{"tampered": flipped, "truncated": s1[:10], "plain": "hello", "empty": "", "bad base64": "e1:!!!"} {
		if _, err := v.Open(in, "messages.content|a|1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := other.Open(s1, "messages.content|a|1"); err == nil {
		t.Fatal("opened with a different key")
	}
	if got, err := v.Open(v.Seal(nil, "x"), "x"); err != nil || len(got) != 0 {
		t.Fatalf("empty value: %q %v", got, err)
	}
}

func TestPassphraseVaultLifecycle(t *testing.T) {
	dir := t.TempDir()
	v1, err := Open(dir, passOpts("correct horse battery"))
	if err != nil || v1 == nil {
		t.Fatalf("create: %v", err)
	}
	sealed := v1.Seal([]byte("secret"), "aad")

	// Same passphrase: same data key.
	v2, err := Open(dir, passOpts("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Open(sealed, "aad"); err != nil || string(got) != "secret" {
		t.Fatalf("reopened vault cannot read old data: %v", err)
	}

	// Wrong passphrase: clear error, no data.
	if _, err := Open(dir, passOpts("not the passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	// The key file itself holds no usable secret.
	raw, _ := os.ReadFile(filepath.Join(dir, KeyFileName))
	if bytes.Contains(raw, []byte("correct horse")) {
		t.Fatal("passphrase leaked into the key file")
	}

	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dir, KeyFileName))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v", st.Mode().Perm())
		}
	}
}

func TestPassphraseSources(t *testing.T) {
	// File: only the first line counts, CRLF tolerated.
	dir := t.TempDir()
	pf := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(pf, []byte("from a file!\r\nignored second line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Open(dir, Options{Mode: ModePassphrase, PassphraseFile: pf})
	if err != nil {
		t.Fatal(err)
	}
	s := v.Seal([]byte("x"), "a")
	if v2, err := Open(dir, passOpts("from a file!")); err != nil {
		t.Fatalf("file passphrase not what was expected: %v", err)
	} else if _, err := v2.Open(s, "a"); err != nil {
		t.Fatal(err)
	}

	// Environment, via an injected lookup.
	dir = t.TempDir()
	env := func(k string) string {
		if k == EnvPassphrase {
			return "from the env!"
		}
		return ""
	}
	if _, err := Open(dir, Options{Mode: ModePassphrase, Getenv: env}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, passOpts("from the env!")); err != nil {
		t.Fatalf("env passphrase not applied: %v", err)
	}

	// Prompt: asked to confirm when creating, not when unlocking.
	dir = t.TempDir()
	var confirms []bool
	prompt := func(confirm bool) (string, error) {
		confirms = append(confirms, confirm)
		return "typed at a prompt", nil
	}
	for range 2 {
		if _, err := Open(dir, Options{Mode: ModePassphrase, Prompt: prompt}); err != nil {
			t.Fatal(err)
		}
	}
	if len(confirms) != 2 || !confirms[0] || confirms[1] {
		t.Fatalf("confirm flags %v, want [true false]", confirms)
	}

	// An empty file and an unreadable file are errors.
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := Open(t.TempDir(), Options{Mode: ModePassphrase, PassphraseFile: empty}); err == nil {
		t.Fatal("empty passphrase file accepted")
	}
	if _, err := Open(t.TempDir(), Options{Mode: ModePassphrase, PassphraseFile: filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("missing passphrase file accepted")
	}
}

func TestEnvPassphraseIsRemovedFromTheEnvironment(t *testing.T) {
	t.Setenv(EnvPassphrase, "a long enough secret")
	if _, err := Open(t.TempDir(), Options{Mode: ModePassphrase}); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv(EnvPassphrase); v != "" {
		t.Fatal("passphrase still in the environment; child processes would inherit it")
	}
}

func TestCreationRequirements(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, passOpts("short")); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("weak passphrase: %v", err)
	}
	if _, err := Open(dir, Options{Mode: ModePassphrase}); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); err == nil {
		t.Fatal("a failed creation left a key file behind")
	}
}

func TestOffMode(t *testing.T) {
	dir := t.TempDir()
	if v, err := Open(dir, Options{Mode: ModeOff}); v != nil || err != nil {
		t.Fatalf("off on a fresh directory: %v %v", v, err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); err == nil {
		t.Fatal("off mode created a key file")
	}
	if _, err := Open(dir, passOpts("some passphrase")); err != nil {
		t.Fatal(err)
	}
	// Switching encryption off must not silently expose or orphan the data.
	if _, err := Open(dir, Options{Mode: ModeOff}); !errors.Is(err, ErrEncryptedData) {
		t.Fatalf("off on encrypted data: %v", err)
	}
}

func TestModeMismatchAndAutoFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, passOpts("some passphrase")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{Mode: ModeOS}); !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("got %v", err)
	}
	// auto adopts whatever the key file says.
	if _, err := Open(dir, Options{Mode: ModeAuto, Passphrase: "some passphrase"}); err != nil {
		t.Fatalf("auto on an existing passphrase vault: %v", err)
	}
}

func TestDamagedKeyFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, passOpts("some passphrase")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, KeyFileName)
	good, _ := os.ReadFile(path)

	mutate := func(fn func(*keyFile)) []byte {
		var kf keyFile
		_ = json.Unmarshal(good, &kf)
		fn(&kf)
		b, _ := json.Marshal(kf)
		return b
	}
	cases := map[string][]byte{
		"not json":        []byte("garbage"),
		"wrong version":   mutate(func(k *keyFile) { k.Version = 99 }),
		"unknown mode":    mutate(func(k *keyFile) { k.Mode = "rot13" }),
		"no kdf":          mutate(func(k *keyFile) { k.KDF = nil }),
		"truncated key":   mutate(func(k *keyFile) { k.Wrapped = k.Wrapped[:5] }),
		"memory bomb":     mutate(func(k *keyFile) { k.KDF.Memory = 1 << 31 }),
		"zero iterations": mutate(func(k *keyFile) { k.KDF.Time = 0 }),
		"time bomb":       mutate(func(k *keyFile) { k.KDF.Time = 1 << 20 }),
		"short salt":      mutate(func(k *keyFile) { k.KDF.Salt = []byte{1} }),
		"altered wrap":    mutate(func(k *keyFile) { k.Wrapped[len(k.Wrapped)-1] ^= 1 }),
	}
	for name, content := range cases {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := Open(dir, passOpts("some passphrase"))
		if err == nil || v != nil {
			t.Errorf("%s: damaged key file accepted", name)
		}
	}
}

func TestVaultsAreIndependent(t *testing.T) {
	a, _ := Open(t.TempDir(), passOpts("passphrase one!"))
	b, _ := Open(t.TempDir(), passOpts("passphrase one!")) // same passphrase, different data key
	if _, err := b.Open(a.Seal([]byte("x"), "aad"), "aad"); err == nil {
		t.Fatal("two vaults share a data key")
	}
}
