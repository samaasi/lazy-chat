package identity

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("identity changed between runs: %s vs %s", first.ID(), second.ID())
	}
	if !ValidID(first.ID()) {
		t.Fatalf("malformed ID %q", first.ID())
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}
}

func TestCorruptKeyIsAnErrorNotRegenerated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFileName), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("a corrupt key must not be silently replaced (that would change the peer's identity)")
	}
}

func TestSignVerify(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	msg := []byte("hello")
	sig := a.Sign(msg)
	if !Verify(a.PublicKey(), msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(b.PublicKey(), msg, sig) || Verify(a.PublicKey(), []byte("other"), sig) {
		t.Fatal("invalid signature accepted")
	}
	if Verify(nil, msg, sig) {
		t.Fatal("nil key accepted")
	}
}

func TestValidID(t *testing.T) {
	for _, bad := range []string{"", "abc", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "0123456789abcdef0123456789abcdef0", "0123456789ABCDEF0123456789ABCDEF"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
	if !ValidID("0123456789abcdef0123456789abcdef") {
		t.Error("good ID rejected")
	}
}

// Two identities complete a mutual TLS 1.3 handshake and each learns the
// other's authentic ID from the certificate.
func TestMutualTLSYieldsPeerIDs(t *testing.T) {
	server, _ := Generate()
	client, _ := Generate()
	sCert, err := server.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	cCert, err := client.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{sCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			seen <- "accept error"
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			seen <- "handshake error: " + err.Error()
			return
		}
		id, err := PeerIDFromCertificate(tc.ConnectionState().PeerCertificates[0].Raw)
		if err != nil {
			seen <- err.Error()
			return
		}
		seen <- id
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cCert},
		InsecureSkipVerify: true, // identity is pinned below, not chain-verified
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	gotServerID, err := PeerIDFromCertificate(conn.ConnectionState().PeerCertificates[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if gotServerID != server.ID() {
		t.Fatalf("client saw server ID %s, want %s", gotServerID, server.ID())
	}
	if got := <-seen; got != client.ID() {
		t.Fatalf("server saw client ID %q, want %s", got, client.ID())
	}
}

func TestSafetyNumber(t *testing.T) {
	a, b, c := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
	ab, ba := SafetyNumber(a, b), SafetyNumber(b, a)
	if ab != ba {
		t.Fatalf("both peers must compute the same number: %q vs %q", ab, ba)
	}
	if got := strings.Fields(ab); len(got) != 12 {
		t.Fatalf("want 12 groups, got %q", ab)
	}
	for _, g := range strings.Fields(ab) {
		if len(g) != 5 {
			t.Fatalf("group %q is not 5 digits", g)
		}
	}
	if ab == SafetyNumber(a, c) || ab == SafetyNumber(b, c) {
		t.Fatal("different peer pairs must give different numbers")
	}
	if SafetyNumber(a, b) != ab {
		t.Fatal("not deterministic")
	}
}

func TestDHKeyIsStableAndDistinctPerIdentity(t *testing.T) {
	dir := t.TempDir()
	first, _ := LoadOrCreate(dir)
	again, _ := LoadOrCreate(dir)
	other, _ := Generate()
	if !first.DHKey().PublicKey().Equal(again.DHKey().PublicKey()) {
		t.Fatal("DH key changed across restarts; offline messages to us would stop decrypting")
	}
	if first.DHKey().PublicKey().Equal(other.DHKey().PublicKey()) {
		t.Fatal("two identities share a DH key")
	}
}
