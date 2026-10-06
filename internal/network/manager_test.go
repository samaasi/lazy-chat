package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/peer"
	"github.com/samaasi/lazy-chat/internal/protocol"
)

var bg = context.Background()

type received struct {
	from string
	kind protocol.Kind
	body []byte
}

type node struct {
	name   string
	id     *identity.Identity
	peers  *peer.Manager
	m      *Manager
	got    chan received
	events chan string
}

func (n *node) PeerConnected(id, name string) { n.events <- "connected:" + id }
func (n *node) PeerDisconnected(id string)    { n.events <- "disconnected:" + id }

func newNode(t *testing.T, name string, mod ...func(*Options)) *node {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	log := logger.Discard()
	pm := peer.NewManager(log)
	opts := Options{ListenAddr: "127.0.0.1", Username: name, HandshakeTimeout: 3 * time.Second}
	for _, f := range mod {
		f(&opts)
	}
	m, err := NewManager(opts, id, log, pm)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{name: name, id: id, peers: pm, m: m, got: make(chan received, 4096), events: make(chan string, 64)}
	for _, k := range []protocol.Kind{protocol.KindMessage, protocol.KindAck, protocol.KindFileChunk} {
		m.Handle(k, func(from string, body []byte) { n.got <- received{from: from, kind: k, body: body} })
	}
	m.AddListener(n)
	if err := m.Start(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop() })
	return n
}

// know teaches n where to find other (as discovery would).
func (n *node) know(other *node) {
	n.peers.AddPeer(&models.Peer{ID: other.id.ID(), Username: other.name, Address: "127.0.0.1", Port: other.m.Port(), LastSeen: time.Now()})
}

func recv(t *testing.T, ch <-chan received) received {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return received{}
	}
}

func expectNone(t *testing.T, ch <-chan received, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("unexpected frame from %s: %q", r.from[:8], r.body)
	case <-time.After(d):
	}
}

func event(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an event")
		return ""
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func send(t *testing.T, from *node, to *node, text string) {
	t.Helper()
	if err := from.m.Send(bg, to.id.ID(), protocol.KindMessage, []byte(text)); err != nil {
		t.Fatal(err)
	}
}

func TestMessagesAreDeliveredWithTheAuthenticatedSender(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)

	send(t, alice, bob, "hi bob") // dials on demand
	r := recv(t, bob.got)
	if r.from != alice.id.ID() || string(r.body) != "hi bob" {
		t.Fatalf("bob got %+v", r)
	}
	if name, ok := bob.m.PeerName(alice.id.ID()); !ok || name != "alice" {
		t.Fatalf("hello name: %q %v", name, ok)
	}

	// Bob never discovered alice; the inbound connection is enough to reply.
	send(t, bob, alice, "hi alice")
	if r := recv(t, alice.got); r.from != bob.id.ID() || string(r.body) != "hi alice" {
		t.Fatalf("alice got %+v", r)
	}
	if !alice.m.IsConnected(bob.id.ID()) || !bob.m.IsConnected(alice.id.ID()) {
		t.Fatal("both sides should report a connection")
	}
}

func TestImpostorAtDiscoveredAddressIsRejected(t *testing.T) {
	alice, bob, mallory := newNode(t, "alice"), newNode(t, "bob"), newNode(t, "mallory")

	// A forged announcement points Bob's ID at Mallory's port.
	alice.peers.AddPeer(&models.Peer{ID: bob.id.ID(), Username: "bob", Address: "127.0.0.1", Port: mallory.m.Port(), LastSeen: time.Now()})

	err := alice.m.Send(bg, bob.id.ID(), protocol.KindMessage, []byte("for bob's eyes only"))
	if err == nil {
		t.Fatal("message was sent to an impostor")
	}
	expectNone(t, mallory.got, 200*time.Millisecond)
	if alice.m.IsConnected(bob.id.ID()) || alice.m.IsConnected(mallory.id.ID()) {
		t.Fatal("a connection was registered")
	}
}

func TestSendToUnknownPeer(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	if err := alice.m.Send(bg, bob.id.ID(), protocol.KindMessage, []byte("x")); !errors.Is(err, apperrors.ErrPeerNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); !errors.Is(err, apperrors.ErrPeerNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestAlreadyConnected(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); err != nil {
		t.Fatal(err)
	}
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); !errors.Is(err, apperrors.ErrPeerAlreadyConnected) {
		t.Fatalf("got %v", err)
	}
	if got := alice.m.ConnectedPeers(); len(got) != 1 || got[0] != bob.id.ID() {
		t.Fatalf("ConnectedPeers = %v", got)
	}
}

// Both peers dial each other at the same moment. Both must end up keeping the
// same single connection, and it must work in both directions.
func TestSimultaneousDialsConvergeOnOneConnection(t *testing.T) {
	for i := range 15 {
		alice, bob := newNode(t, "alice"), newNode(t, "bob")
		alice.know(bob)
		bob.know(alice)

		var wg sync.WaitGroup
		for _, pair := range [][2]*node{{alice, bob}, {bob, alice}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = pair[0].m.ConnectToPeer(bg, pair[1].id.ID())
			}()
		}
		wg.Wait()

		// Let the loser connection be torn down on both ends.
		time.Sleep(50 * time.Millisecond)
		send(t, alice, bob, "a->b")
		send(t, bob, alice, "b->a")
		if r := recv(t, bob.got); string(r.body) != "a->b" {
			t.Fatalf("iteration %d: bob got %q", i, r.body)
		}
		if r := recv(t, alice.got); string(r.body) != "b->a" {
			t.Fatalf("iteration %d: alice got %q", i, r.body)
		}
		if n := len(alice.m.ConnectedPeers()); n != 1 {
			t.Fatalf("iteration %d: alice has %d connections", i, n)
		}
		if n := len(bob.m.ConnectedPeers()); n != 1 {
			t.Fatalf("iteration %d: bob has %d connections", i, n)
		}
		alice.m.Stop()
		bob.m.Stop()
	}
}

func TestConcurrentSendsShareOneDial(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send(t, alice, bob, fmt.Sprintf("m%d", i))
		}()
	}
	wg.Wait()
	for range 20 {
		recv(t, bob.got)
	}
	if n := len(bob.m.ConnectedPeers()); n != 1 {
		t.Fatalf("bob has %d connections to alice", n)
	}
}

func TestListenerEvents(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); err != nil {
		t.Fatal(err)
	}
	if e := event(t, alice.events); e != "connected:"+bob.id.ID() {
		t.Fatalf("alice event %q", e)
	}
	if e := event(t, bob.events); e != "connected:"+alice.id.ID() {
		t.Fatalf("bob event %q", e)
	}

	alice.m.Disconnect(bob.id.ID())
	if e := event(t, alice.events); e != "disconnected:"+bob.id.ID() {
		t.Fatalf("alice event %q", e)
	}
	if e := event(t, bob.events); e != "disconnected:"+alice.id.ID() {
		t.Fatalf("bob event %q", e)
	}
	waitFor(t, "connections to drop", func() bool { return !alice.m.IsConnected(bob.id.ID()) && !bob.m.IsConnected(alice.id.ID()) })

	// And they can reconnect afterwards.
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
}

func TestInboundLimitAndSlotRelease(t *testing.T) {
	srv := newNode(t, "srv", func(o *Options) { o.MaxInbound = 2; o.MaxPerIP = 10 })
	dial := func() net.Conn {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.m.Port())))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	isClosed := func(c net.Conn, d time.Duration) bool {
		_ = c.SetReadDeadline(time.Now().Add(d))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && !(errors.As(err, &ne) && ne.Timeout())
	}

	c1, c2 := dial(), dial()
	waitFor(t, "slots to fill", func() bool { srv.m.mu.Lock(); defer srv.m.mu.Unlock(); return srv.m.inbound == 2 })
	c3 := dial()
	if !isClosed(c3, 2*time.Second) {
		t.Fatal("third connection should be refused when the limit is 2")
	}
	if isClosed(c1, 100*time.Millisecond) || isClosed(c2, 100*time.Millisecond) {
		t.Fatal("existing connections were disturbed")
	}

	c1.Close()
	waitFor(t, "slot to be released", func() bool { srv.m.mu.Lock(); defer srv.m.mu.Unlock(); return srv.m.inbound == 1 })
	c4 := dial()
	if isClosed(c4, 300*time.Millisecond) {
		t.Fatal("a freed slot was not reusable")
	}
}

func TestPerIPLimit(t *testing.T) {
	srv := newNode(t, "srv", func(o *Options) { o.MaxInbound = 50; o.MaxPerIP = 2 })
	var conns []net.Conn
	for range 4 {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.m.Port())))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		conns = append(conns, c)
	}
	waitFor(t, "accept loop", func() bool { srv.m.mu.Lock(); defer srv.m.mu.Unlock(); return srv.m.perIP["127.0.0.1"] == 2 })
	closed := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			closed++
		}
	}
	if closed != 2 {
		t.Fatalf("%d of 4 connections refused, want 2", closed)
	}
}

func TestSilentConnectionTimesOutAndFreesItsSlot(t *testing.T) {
	srv := newNode(t, "srv", func(o *Options) { o.MaxInbound = 1; o.MaxPerIP = 1; o.HandshakeTimeout = 300 * time.Millisecond })
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.m.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// A slow-loris client sends nothing; the slot must come back on its own.
	waitFor(t, "handshake timeout to free the slot", func() bool {
		srv.m.mu.Lock()
		defer srv.m.mu.Unlock()
		return srv.m.inbound == 0
	})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent connection still open")
	}
}

func TestNonTLSTrafficIsDroppedAndServerSurvives(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(bob.m.Port())))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n{\"from\":\"x\"}\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, c) // the server hangs up
	c.Close()

	alice.know(bob)
	send(t, alice, bob, "still alive")
	if r := recv(t, bob.got); string(r.body) != "still alive" {
		t.Fatalf("got %q", r.body)
	}
}

func TestWrongALPNIsRejected(t *testing.T) {
	bob := newNode(t, "bob")
	id, _ := identity.Generate()
	cert, _ := id.TLSCertificate()
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(bob.m.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	if err := tc.Handshake(); err == nil {
		// TLS 1.3 may complete client-side before the server's verdict arrives;
		// the server must still drop the connection.
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := tc.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection with a foreign ALPN stayed open")
		}
	}
}

func TestClientWithoutCertificateIsRejected(t *testing.T) {
	bob := newNode(t, "bob")
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(bob.m.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}})
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err == nil {
		if _, err := tc.Read(make([]byte, 1)); err == nil {
			t.Fatal("anonymous client was accepted")
		}
	}
}

func TestTLS12IsRefused(t *testing.T) {
	bob := newNode(t, "bob")
	id, _ := identity.Generate()
	cert, _ := id.TLSCertificate()
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(bob.m.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: []string{protocol.ALPN}})
	if err := tc.Handshake(); err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
}

func TestHelloValidation(t *testing.T) {
	bob := newNode(t, "bob")
	bad := map[string][]byte{
		"control chars in name": mustJSON(protocol.Hello{Version: protocol.Version, Username: "evil\x1b[2J"}),
		"empty name":            mustJSON(protocol.Hello{Version: protocol.Version, Username: "  "}),
		"long name":             mustJSON(protocol.Hello{Version: protocol.Version, Username: strings.Repeat("a", 33)}),
		"future version":        mustJSON(protocol.Hello{Version: 99, Username: "x"}),
		"not json":              []byte("hello"),
	}
	for name, hello := range bad {
		id, _ := identity.Generate()
		rp := dialRaw(t, bob, id, protocol.ALPN, nil)
		rp.write(t, protocol.KindHello, hello)
		if !rp.closedBy(2 * time.Second) {
			t.Errorf("%s: connection not closed", name)
		}
		if bob.m.IsConnected(id.ID()) {
			t.Errorf("%s: peer was registered", name)
		}
	}

	// A first frame that is not Hello is also a violation.
	id, _ := identity.Generate()
	rp := dialRaw(t, bob, id, protocol.ALPN, nil)
	rp.write(t, protocol.KindMessage, []byte("sneaky"))
	if !rp.closedBy(2 * time.Second) {
		t.Error("frame before Hello accepted")
	}
	expectNone(t, bob.got, 50*time.Millisecond)
}

func mustJSON(v any) []byte { b, _ := protocol.Marshal(v); return b }

func TestSecondHelloDisconnects(t *testing.T) {
	bob := newNode(t, "bob")
	id, _ := identity.Generate()
	rp := dialRaw(t, bob, id, protocol.ALPN, goodHello("eve"))
	waitFor(t, "registration", func() bool { return bob.m.IsConnected(id.ID()) })
	rp.write(t, protocol.KindHello, goodHello("eve2"))
	if !rp.closedBy(2 * time.Second) {
		t.Fatal("a repeated Hello must end the connection")
	}
}

func TestOversizedFrameDropsOnlyThatConnection(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); err != nil {
		t.Fatal(err)
	}

	id, _ := identity.Generate()
	rp := dialRaw(t, bob, id, protocol.ALPN, goodHello("eve"))
	// Header: kind=Message, length=1 GiB. Never followed by a body.
	if _, err := rp.conn.Write([]byte{byte(protocol.KindMessage), 0x40, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if !rp.closedBy(2 * time.Second) {
		t.Fatal("oversized frame header did not close the connection")
	}
	if !bob.m.IsConnected(alice.id.ID()) {
		t.Fatal("an unrelated peer lost its connection")
	}
	send(t, alice, bob, "fine")
	if r := recv(t, bob.got); string(r.body) != "fine" {
		t.Fatalf("got %q", r.body)
	}
}

func TestUnknownFrameKindDropsConnection(t *testing.T) {
	bob := newNode(t, "bob")
	id, _ := identity.Generate()
	rp := dialRaw(t, bob, id, protocol.ALPN, goodHello("eve"))
	if _, err := rp.conn.Write([]byte{200, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if !rp.closedBy(2 * time.Second) {
		t.Fatal("unknown kind accepted")
	}
}

func TestFloodIsDisconnectedButFileChunksAreNot(t *testing.T) {
	bob := newNode(t, "bob", func(o *Options) { o.FrameRate = 5; o.FrameBurst = 10 })

	id, _ := identity.Generate()
	flooder := dialRaw(t, bob, id, protocol.ALPN, goodHello("flooder"))
	for range 200 {
		if _, err := flooder.sealAndSend(protocol.KindMessage, []byte("spam")); err != nil {
			break
		}
	}
	if !flooder.closedBy(2 * time.Second) {
		t.Fatal("flooding peer was not disconnected")
	}

	// The same volume of file chunks passes: they are paced by TCP instead.
	id2, _ := identity.Generate()
	sender := dialRaw(t, bob, id2, protocol.ALPN, goodHello("sender"))
	chunk, _ := protocol.EncodeChunk("00112233445566778899aabbccddeeff", make([]byte, protocol.MaxChunkSize))
	go func() {
		for range 300 {
			if _, err := sender.sealAndSend(protocol.KindFileChunk, chunk); err != nil {
				return
			}
		}
	}()
	spam, chunksSeen := 0, 0
	for chunksSeen < 300 {
		r := recv(t, bob.got)
		switch {
		case r.kind == protocol.KindMessage && r.from == id.ID():
			spam++ // what the flooder got through before being cut off
		case r.kind == protocol.KindFileChunk && r.from == id2.ID():
			chunksSeen++
		default:
			t.Fatalf("unexpected frame %+v", r)
		}
	}
	if spam > 20 { // burst of 10 plus a little refill while the loop ran
		t.Fatalf("%d spam frames got through a burst limit of 10", spam)
	}
}

func TestPanickingHandlerDoesNotKillTheConnection(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	var calls atomic.Int32
	bob.m.Handle(protocol.KindAck, func(string, []byte) {
		if calls.Add(1) == 1 {
			panic("handler bug")
		}
	})
	alice.know(bob)
	if err := alice.m.Send(bg, bob.id.ID(), protocol.KindAck, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := alice.m.Send(bg, bob.id.ID(), protocol.KindAck, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second frame after the panic", func() bool { return calls.Load() == 2 })
}

func TestLargeTransferPreservesOrderAndData(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	const chunks = 200
	go func() {
		for i := range chunks {
			data := make([]byte, protocol.MaxChunkSize)
			data[0], data[1] = byte(i), byte(i>>8)
			body, _ := protocol.EncodeChunk("00112233445566778899aabbccddeeff", data)
			if err := alice.m.Send(bg, bob.id.ID(), protocol.KindFileChunk, body); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := range chunks {
		r := recv(t, bob.got)
		_, data, err := protocol.DecodeChunk(r.body)
		if err != nil || len(data) != protocol.MaxChunkSize || int(data[0])|int(data[1])<<8 != i {
			t.Fatalf("chunk %d corrupted or out of order (err=%v)", i, err)
		}
	}
}

func TestStopWithLiveConnectionsReturnsPromptly(t *testing.T) {
	alice, bob, carol := newNode(t, "alice"), newNode(t, "bob"), newNode(t, "carol")
	alice.know(bob)
	carol.know(alice)
	send(t, alice, bob, "x")
	send(t, carol, alice, "y")
	recv(t, bob.got)
	recv(t, alice.got)

	// A half-open handshake is also in flight.
	c, _ := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(alice.m.Port())))
	defer c.Close()

	done := make(chan struct{})
	go func() { alice.m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return: shutdown deadlock")
	}
	if err := alice.m.ConnectToPeer(bg, bob.id.ID()); err == nil {
		t.Fatal("ConnectToPeer after Stop should fail")
	}
	// Peers notice the loss.
	waitFor(t, "peers to notice the shutdown", func() bool { return !bob.m.IsConnected(alice.id.ID()) && !carol.m.IsConnected(alice.id.ID()) })
}

func TestConnectingToSelfIsRefused(t *testing.T) {
	alice := newNode(t, "alice")
	alice.peers.AddPeer(&models.Peer{ID: alice.id.ID(), Username: "me", Address: "127.0.0.1", Port: alice.m.Port(), LastSeen: time.Now()})
	if err := alice.m.ConnectToPeer(bg, alice.id.ID()); err == nil {
		t.Fatal("connected to ourselves")
	}
}

func TestStartTwiceAndStopTwice(t *testing.T) {
	alice := newNode(t, "alice")
	if err := alice.m.Start(bg); !errors.Is(err, apperrors.ErrAppAlreadyRunning) {
		t.Fatalf("second Start: %v", err)
	}
	if err := alice.m.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := alice.m.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestFrameTooBigForKindIsRejectedBeforeSending(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	err := alice.m.Send(bg, bob.id.ID(), protocol.KindMessage, make([]byte, protocol.MaxBody(protocol.KindMessage)+1))
	if err == nil {
		t.Fatal("oversized frame accepted by Send")
	}
}

func TestSendRespectsContext(t *testing.T) {
	alice, bob := newNode(t, "alice"), newNode(t, "bob")
	alice.know(bob)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if err := alice.m.Send(ctx, bob.id.ID(), protocol.KindMessage, []byte("x")); err == nil {
		t.Fatal("cancelled context ignored")
	}
}
