package network

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/samaasi/lazy-chat/internal/address"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/protocol"
)

func TestConnectToAddressWithoutDiscovery(t *testing.T) {
	a, b := newNode(t, "alice"), newNode(t, "bob")
	// Neither knows the other: there is no discovery, only an address.
	addr := "127.0.0.1:" + strconv.Itoa(b.m.Port())

	id, name, err := a.m.ConnectToAddress(bg, address.Target{Host: "127.0.0.1", Port: b.m.Port()})
	if err != nil {
		t.Fatal(err)
	}
	if id != b.id.ID() || name != "bob" {
		t.Fatalf("connected to %s %q, want %s bob (%s)", id, name, b.id.ID(), addr)
	}
	waitFor(t, "both ends to see the connection", func() bool { return a.m.IsConnected(id) && b.m.IsConnected(a.id.ID()) })

	// Remembered, so it appears in /list and can be reached by name.
	if p, ok := a.peers.GetPeer(id); !ok || p.Username != "bob" || p.Port != b.m.Port() {
		t.Fatalf("peer not remembered: %+v %v", p, ok)
	}

	// Traffic flows exactly as on any other connection.
	if err := a.m.Send(bg, id, protocol.KindMessage, []byte("hello over a direct address")); err != nil {
		t.Fatal(err)
	}
	if r := recv(t, b.got); string(r.body) != "hello over a direct address" || r.from != a.id.ID() {
		t.Fatalf("got %+v", r)
	}
}

func TestConnectToAddressPinsTheExpectedIdentity(t *testing.T) {
	a, b, impostor := newNode(t, "alice"), newNode(t, "bob"), newNode(t, "mallory")

	// Someone else answering at the address Alice believes is Bob's is refused,
	// and nothing is connected or remembered.
	_, _, err := a.m.ConnectToAddress(bg, address.Target{ID: b.id.ID(), Host: "127.0.0.1", Port: impostor.m.Port()})
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") && !strings.Contains(strings.ToLower(err.Error()), "secure connection") {
		t.Fatalf("an impostor was accepted: %v", err)
	}
	if a.m.IsConnected(impostor.id.ID()) {
		t.Fatal("connected to the impostor")
	}
	if _, ok := a.peers.GetPeer(impostor.id.ID()); ok {
		t.Fatal("the impostor was remembered")
	}
	// The right ID at the right address works.
	if _, _, err := a.m.ConnectToAddress(bg, address.Target{ID: b.id.ID(), Host: "127.0.0.1", Port: b.m.Port()}); err != nil {
		t.Fatal(err)
	}
	// Already connected is reported as such.
	if _, _, err := a.m.ConnectToAddress(bg, address.Target{ID: b.id.ID(), Host: "127.0.0.1", Port: b.m.Port()}); !errors.Is(err, apperrors.ErrPeerAlreadyConnected) {
		t.Fatalf("got %v", err)
	}
}

func TestConnectToAddressFailuresAreClean(t *testing.T) {
	a := newNode(t, "alice")
	// Nothing listens there.
	if _, _, err := a.m.ConnectToAddress(bg, address.Target{Host: "127.0.0.1", Port: freePort(t)}); err == nil {
		t.Fatal("connected to nothing")
	}
	// Ourselves.
	if _, _, err := a.m.ConnectToAddress(bg, address.Target{Host: "127.0.0.1", Port: a.m.Port()}); err == nil {
		t.Fatal("connected to ourselves")
	}
	// Not a lazy-chat peer: a plain TCP server that says nothing useful.
	junk := newJunkServer(t)
	if _, _, err := a.m.ConnectToAddress(bg, address.Target{Host: "127.0.0.1", Port: junk}); err == nil {
		t.Fatal("connected to something that is not a peer")
	}
	if len(a.m.ConnectedPeers()) != 0 {
		t.Fatalf("connections left behind: %v", a.m.ConnectedPeers())
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newJunkServer accepts TCP connections and answers with plain text, like a
// web server that is not a lazy-chat peer.
func newJunkServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}
