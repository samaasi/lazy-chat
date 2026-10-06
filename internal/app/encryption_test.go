package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/storage"
)

const marker = "TOP-SECRET-PAYLOAD-0451"

// passphraseFile writes a passphrase file and returns a config modifier that
// turns on passphrase encryption using it.
func passphraseFile(t *testing.T, pass string) func(*config.Config) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(f, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return func(c *config.Config) {
		c.Encryption = "passphrase"
		c.PassphraseFile = f
	}
}

// onDisk returns every byte an instance has persisted.
func onDisk(t *testing.T, cfg *config.Config) []byte {
	t.Helper()
	var all []byte
	for _, p := range []string{
		cfg.Database.Path, cfg.Database.Path + "-wal", cfg.Database.Path + "-shm",
		filepath.Join(cfg.DataDir, "identity.key"), filepath.Join(cfg.DataDir, "vault.key"),
	} {
		if b, err := os.ReadFile(p); err == nil {
			all = append(all, b...)
		}
	}
	return all
}

func restart(t *testing.T, cfg *config.Config) *App {
	t.Helper()
	a, err := New(cfg, WithIO(strings.NewReader(""), &syncBuf{}))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { a.Stop() })
	return a
}

func historyWith(t *testing.T, a *App, peerID string) []string {
	t.Helper()
	msgs, err := a.history.GetDirectMessageHistory(context.Background(), peerID, storage.Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, m := range msgs {
		texts = append(texts, m.Message)
	}
	return texts
}

func TestEncryptedInstancesWorkAndLeaveNoPlaintextOnDisk(t *testing.T) {
	alice, bob := pair(t, passphraseFile(t, "correct horse battery staple"))

	alice.say("/send bob " + marker)
	bob.waitOut(marker) // still fully functional end to end
	alice.say("/history bob")
	alice.waitOut(marker)

	// Stop everything so SQLite checkpoints, then inspect the files.
	aliceCfg, aliceID := alice.app.config, alice.app.ID()
	alice.app.Stop()
	bob.app.Stop()

	for name, cfg := range map[string]*config.Config{"alice": aliceCfg, "bob": bob.app.config} {
		disk := onDisk(t, cfg)
		if bytes.Contains(disk, []byte(marker)) {
			t.Errorf("%s: message text found in plaintext on disk", name)
		}
		if bytes.Contains(disk, []byte("PRIVATE KEY")) {
			t.Errorf("%s: private key found in plaintext on disk", name)
		}
		if _, err := os.Stat(filepath.Join(cfg.DataDir, "vault.key")); err != nil {
			t.Errorf("%s: no vault key file: %v", name, err)
		}
	}

	// Restarting with the passphrase restores both identity and history.
	again := restart(t, aliceCfg)
	if again.ID() != aliceID {
		t.Fatal("identity changed after an encrypted restart")
	}
	if got := historyWith(t, again, bob.app.ID()); len(got) != 1 || got[0] != marker {
		t.Fatalf("history after restart: %v", got)
	}
}

func TestWrongOrMissingPassphraseRefusesToStart(t *testing.T) {
	alice, _ := pair(t, passphraseFile(t, "the right passphrase"))
	cfg := *alice.app.config // copy
	alice.app.Stop()

	wrong := passphraseFile(t, "a different passphrase")
	wrong(&cfg)
	if _, err := New(&cfg, WithIO(strings.NewReader(""), &syncBuf{})); err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("wrong passphrase: %v", err)
	}

	cfg.PassphraseFile = "" // and nobody to ask
	if _, err := New(&cfg, WithIO(strings.NewReader(""), &syncBuf{})); err == nil {
		t.Fatal("started without any passphrase")
	}

	// Switching encryption off must not expose or orphan the encrypted data.
	cfg.Encryption = "off"
	if _, err := New(&cfg, WithIO(strings.NewReader(""), &syncBuf{})); err == nil {
		t.Fatal("started with encryption off on encrypted data")
	}

	// The correct passphrase still works afterwards.
	good := passphraseFile(t, "the right passphrase")
	good(&cfg)
	restart(t, &cfg)
}

// An existing, unencrypted installation is encrypted in place the first time
// encryption is enabled, keeping its identity and history.
func TestEnablingEncryptionOnAnExistingInstallation(t *testing.T) {
	alice, bob := pair(t) // encryption off
	alice.say("/send bob " + marker)
	bob.waitOut(marker)
	cfg, aliceID, bobID := alice.app.config, alice.app.ID(), bob.app.ID()
	alice.app.Stop()
	bob.app.Stop()

	if !bytes.Contains(onDisk(t, cfg), []byte(marker)) || !bytes.Contains(onDisk(t, cfg), []byte("PRIVATE KEY")) {
		t.Fatal("setup: expected plaintext data before encryption")
	}

	cfgCopy := *cfg
	passphraseFile(t, "now we encrypt it all")(&cfgCopy)
	again := restart(t, &cfgCopy)

	if again.ID() != aliceID {
		t.Fatal("encrypting the installation changed the peer's identity")
	}
	if got := historyWith(t, again, bobID); len(got) != 1 || got[0] != marker {
		t.Fatalf("history lost or unreadable after encryption: %v", got)
	}
	again.Stop() // flush

	disk := onDisk(t, &cfgCopy)
	if bytes.Contains(disk, []byte(marker)) || bytes.Contains(disk, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext survived on disk after enabling encryption")
	}
}

func TestEncryptionOptionIsValidated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Path = "chat.db" // normally derived from the data directory by Load
	cfg.Encryption = "rot13"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown encryption mode accepted")
	}
	for _, mode := range []string{"auto", "passphrase", "os", "off", "OFF"} {
		cfg.Encryption = mode
		if err := cfg.Validate(); err != nil {
			t.Errorf("%q rejected: %v", mode, err)
		}
	}
}

// Timing guard so a slow KDF cannot make the suite hang unnoticed.
func TestEncryptedStartupIsReasonablyFast(t *testing.T) {
	start := time.Now()
	alice, _ := pair(t, passphraseFile(t, "benchmark passphrase"))
	_ = alice
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("starting two encrypted instances took %v", d)
	}
}
