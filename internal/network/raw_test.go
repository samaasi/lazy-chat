package network

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/ratchet"
)

// rawPeer is a hand-driven protocol client, for sending things a well-behaved
// Manager never would. After setup it speaks the real ratchet protocol.
type rawPeer struct {
	conn *tls.Conn
	br   *bufio.Reader
	sess *ratchet.Session
}

// dialRaw connects, and when hello is non-nil also completes the Hello and
// ratchet handshakes as an honest client holding identity id.
func dialRaw(t *testing.T, target *node, id *identity.Identity, alpn string, hello []byte) *rawPeer {
	t.Helper()
	return dialRawWith(t, target, id, alpn, hello, id)
}

// dialRawWith is dialRaw with control over who signs the ratchet handshake.
func dialRawWith(t *testing.T, target *node, id *identity.Identity, alpn string, hello []byte, ratchetSigner ratchet.Signer) *rawPeer {
	t.Helper()
	cert, err := id.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(target.m.Port())), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() { tc.Close() })
	rp := &rawPeer{conn: tc, br: bufio.NewReader(tc)}
	if hello == nil {
		return rp
	}
	rp.writeRaw(t, protocol.KindHello, hello)
	rp.expectKind(t, protocol.KindHello)

	state := tc.ConnectionState()
	binding, err := state.ExportKeyingMaterial("lazy-chat ratchet v1", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	hs, initMsg, err := ratchet.Start(id.ID(), target.id.ID(), ratchetSigner, binding)
	if err != nil {
		t.Fatal(err)
	}
	rp.writeRaw(t, protocol.KindRatchetInit, initMsg)
	serverInit := rp.expectKind(t, protocol.KindRatchetInit)
	if rp.sess, err = hs.Finish(serverInit, target.id.PublicKey()); err != nil {
		t.Fatalf("server's ratchet handshake did not verify: %v", err)
	}
	return rp
}

func goodHello(name string) []byte {
	b, _ := protocol.Marshal(protocol.Hello{Version: protocol.Version, Username: name})
	return b
}

// write sends a frame the way an honest client would: application frames are
// sealed by the ratchet, plumbing frames go in the clear.
func (r *rawPeer) write(t *testing.T, k protocol.Kind, body []byte) {
	t.Helper()
	if k.Application() && r.sess != nil {
		r.writeRaw(t, protocol.KindSecure, r.seal(t, k, body))
		return
	}
	r.writeRaw(t, k, body)
}

func (r *rawPeer) seal(t *testing.T, k protocol.Kind, body []byte) []byte {
	t.Helper()
	sealed, err := r.sess.Seal(append([]byte{byte(k)}, body...))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// sealAndSend is write without a testing.T, for helper goroutines.
func (r *rawPeer) sealAndSend(k protocol.Kind, body []byte) (int, error) {
	sealed, err := r.sess.Seal(append([]byte{byte(k)}, body...))
	if err != nil {
		return 0, err
	}
	frame, err := protocol.EncodeFrame(protocol.KindSecure, sealed)
	if err != nil {
		return 0, err
	}
	return r.conn.Write(frame)
}

// writeRaw sends a frame exactly as given.
func (r *rawPeer) writeRaw(t *testing.T, k protocol.Kind, body []byte) {
	t.Helper()
	frame, err := protocol.EncodeFrame(k, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func (r *rawPeer) expectKind(t *testing.T, want protocol.Kind) []byte {
	t.Helper()
	_ = r.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	k, body, err := protocol.ReadFrame(r.br)
	if err != nil || k != want {
		t.Fatalf("expected frame kind %d from the server, got kind=%d err=%v", want, k, err)
	}
	return body
}

// closedBy reports whether the server closes the connection within d.
func (r *rawPeer) closedBy(d time.Duration) bool {
	_ = r.conn.SetReadDeadline(time.Now().Add(d))
	for {
		if _, _, err := protocol.ReadFrame(r.br); err != nil {
			var ne net.Error
			return !(errors.As(err, &ne) && ne.Timeout())
		}
	}
}

// ---- The ratchet layer -------------------------------------------------------

func TestPlaintextApplicationFramesAreRejected(t *testing.T) {
	bob := newNode(t, "bob")
	id, _ := identity.Generate()
	rp := dialRaw(t, bob, id, protocol.ALPN, goodHello("eve"))
	waitFor(t, "registration", func() bool { return bob.m.IsConnected(id.ID()) })

	rp.writeRaw(t, protocol.KindMessage, []byte("not encrypted"))
	if !rp.closedBy(2 * time.Second) {
		t.Fatal("a plaintext application frame was tolerated")
	}
	expectNone(t, bob.got, 100*time.Millisecond)
}

func TestTamperedAndReplayedSealedFramesDropTheConnection(t *testing.T) {
	bob := newNode(t, "bob")

	// Tampering with a sealed frame.
	id1, _ := identity.Generate()
	rp := dialRaw(t, bob, id1, protocol.ALPN, goodHello("eve"))
	sealed := rp.seal(t, protocol.KindMessage, []byte("original"))
	sealed[len(sealed)-1] ^= 0x01
	rp.writeRaw(t, protocol.KindSecure, sealed)
	if !rp.closedBy(2 * time.Second) {
		t.Fatal("a tampered frame did not end the connection")
	}
	expectNone(t, bob.got, 100*time.Millisecond)

	// Replaying a genuine sealed frame.
	id2, _ := identity.Generate()
	rp2 := dialRaw(t, bob, id2, protocol.ALPN, goodHello("eve2"))
	genuine := rp2.seal(t, protocol.KindMessage, []byte("once"))
	rp2.writeRaw(t, protocol.KindSecure, genuine)
	if r := recv(t, bob.got); string(r.body) != "once" || r.from != id2.ID() {
		t.Fatalf("genuine frame not delivered: %+v", r)
	}
	rp2.writeRaw(t, protocol.KindSecure, genuine)
	if !rp2.closedBy(2 * time.Second) {
		t.Fatal("a replayed frame did not end the connection")
	}
	expectNone(t, bob.got, 100*time.Millisecond)
}

func TestRatchetHandshakeMustBeSignedByTheConnectionsIdentity(t *testing.T) {
	bob := newNode(t, "bob")
	victim, _ := identity.Generate()
	attacker, _ := identity.Generate()

	// The TLS certificate is the attacker's, but the ratchet handshake is
	// signed with someone else's key.
	rp := dialRaw(t, bob, attacker, protocol.ALPN, nil)
	rp.writeRaw(t, protocol.KindHello, goodHello("eve"))
	rp.expectKind(t, protocol.KindHello)
	state := rp.conn.ConnectionState()
	binding, _ := state.ExportKeyingMaterial("lazy-chat ratchet v1", nil, 32)
	_, initMsg, err := ratchet.Start(attacker.ID(), bob.id.ID(), victim, binding)
	if err != nil {
		t.Fatal(err)
	}
	rp.writeRaw(t, protocol.KindRatchetInit, initMsg)

	if !rp.closedBy(2 * time.Second) {
		t.Fatal("a ratchet handshake signed with a different identity was accepted")
	}
	if bob.m.IsConnected(attacker.ID()) || bob.m.IsConnected(victim.ID()) {
		t.Fatal("the connection was registered")
	}
}

func TestSealedFramesWithInvalidContentsDropTheConnection(t *testing.T) {
	bob := newNode(t, "bob")
	cases := map[string]func(rp *rawPeer) []byte{
		"inner kind is Hello": func(rp *rawPeer) []byte { return rp.seal(t, protocol.KindHello, goodHello("x")) },
		"inner kind is Ping":  func(rp *rawPeer) []byte { return rp.seal(t, protocol.KindPing, nil) },
		"nested Secure":       func(rp *rawPeer) []byte { return rp.seal(t, protocol.KindSecure, []byte("x")) },
		"unknown inner kind":  func(rp *rawPeer) []byte { return rp.seal(t, protocol.Kind(99), []byte("x")) },
		"empty plaintext": func(rp *rawPeer) []byte {
			s, _ := rp.sess.Seal(nil)
			return s
		},
		"inner body over its limit": func(rp *rawPeer) []byte {
			// Bigger than a Message may be, yet small enough to fit the envelope.
			return rp.seal(t, protocol.KindMessage, make([]byte, protocol.MaxBody(protocol.KindMessage)+10))
		},
	}
	for name, build := range cases {
		id, _ := identity.Generate()
		rp := dialRaw(t, bob, id, protocol.ALPN, goodHello("eve"))
		rp.writeRaw(t, protocol.KindSecure, build(rp))
		if !rp.closedBy(2 * time.Second) {
			t.Errorf("%s: connection survived", name)
		}
	}
	expectNone(t, bob.got, 100*time.Millisecond)
}

// Two real managers exchange many messages in both directions; the DH
// ratchet turns over repeatedly and nothing is lost or reordered.
func TestLongConversationSurvivesManyRatchetTurns(t *testing.T) {
	unlimited := func(o *Options) { o.FrameRate, o.FrameBurst = 100000, 100000 } // the test sends far faster than a person types
	alice, bob := newNode(t, "alice", unlimited), newNode(t, "bob", unlimited)
	alice.know(bob)
	for i := range 300 {
		send(t, alice, bob, fmt.Sprintf("a%d", i))
		if r := recv(t, bob.got); string(r.body) != fmt.Sprintf("a%d", i) {
			t.Fatalf("bob got %q at %d", r.body, i)
		}
		send(t, bob, alice, fmt.Sprintf("b%d", i))
		if r := recv(t, alice.got); string(r.body) != fmt.Sprintf("b%d", i) {
			t.Fatalf("alice got %q at %d", r.body, i)
		}
	}
}

// An eavesdropper on the TCP stream between two honest peers sees no
// plaintext. (TLS alone would also hide it; the point is that the whole stack
// is working, not just one layer.)
func TestOnTheWireBytesDoNotContainPlaintext(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	tap := &tapBuffer{}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go tap.proxy(proxyLn, net.JoinHostPort("127.0.0.1", strconv.Itoa(bob.m.Port())))
	alice.peers.AddPeer(&models.Peer{ID: bob.id.ID(), Username: "bob", Address: "127.0.0.1",
		Port: proxyLn.Addr().(*net.TCPAddr).Port, LastSeen: time.Now()})

	const secret = "the-launch-code-is-0451"
	send(t, alice, bob, secret)
	if r := recv(t, bob.got); string(r.body) != secret {
		t.Fatalf("got %q", r.body)
	}
	got := tap.snapshot()
	if len(got) == 0 || bytes.Contains(got, []byte(secret)) {
		t.Fatalf("captured %d bytes; plaintext visible=%v", len(got), bytes.Contains(got, []byte(secret)))
	}
}

// tapBuffer is a recording TCP proxy.
type tapBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (tb *tapBuffer) snapshot() []byte {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return bytes.Clone(tb.buf.Bytes())
}

func (tb *tapBuffer) Write(p []byte) (int, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.buf.Write(p)
}

func (tb *tapBuffer) proxy(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", target)
		if err != nil {
			c.Close()
			continue
		}
		go func() { _, _ = io.Copy(io.MultiWriter(up, tb), c); up.Close() }()
		go func() { _, _ = io.Copy(io.MultiWriter(c, tb), up); c.Close() }()
	}
}
