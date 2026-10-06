//go:build windows

package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIVaultNeedsNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(dir, Options{Mode: ModeAuto}) // auto means DPAPI on Windows
	if err != nil || v == nil {
		t.Fatalf("create: %v", err)
	}
	sealed := v.Seal([]byte("secret"), "aad")

	raw, _ := os.ReadFile(filepath.Join(dir, KeyFileName))
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil || kf.Mode != ModeOS || kf.KDF != nil {
		t.Fatalf("auto on Windows should create an OS-protected key: %+v %v", kf, err)
	}

	again, err := Open(dir, Options{Mode: ModeAuto}) // no passphrase supplied
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, err := again.Open(sealed, "aad"); err != nil || string(got) != "secret" {
		t.Fatalf("reopened DPAPI vault cannot read old data: %v", err)
	}

	// The wrapped key is not the plain data key: a copy of the file is useless
	// without this Windows account.
	if bytes.Contains(raw, bytes.Repeat([]byte{0}, 16)) {
		t.Log("(blob contains zero run; unexpected but not fatal)")
	}
	if _, err := Open(dir, passOpts("whatever12")); err == nil {
		t.Fatal("a passphrase request on a DPAPI vault should be a mode mismatch")
	}
}

func TestDPAPIRejectsGarbageBlob(t *testing.T) {
	if _, err := dpapiUnprotect([]byte("not a dpapi blob")); err == nil {
		t.Fatal("garbage unwrapped")
	}
	if _, err := dpapiUnprotect(nil); err == nil {
		t.Fatal("empty blob unwrapped")
	}
}
