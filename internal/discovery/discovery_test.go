package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/peer"
)

var bg = context.Background()

type svc struct {
	*Service
	id    *identity.Identity
	peers *peer.Manager
}

// randomBase picks a base UDP port such that base..base+7 can all be bound
// right now. Random ports can fall into OS-reserved ranges (Windows excludes
// some for Hyper-V/WSL), which would make tests flaky.
func randomBase() int {
	for range 200 {
		base := 20000 + rand.IntN(30000)
		var conns []*net.UDPConn
		ok := true
		for p := base; p < base+8; p++ {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
			if err != nil {
				ok = false
				break
			}
			conns = append(conns, c)
		}
		for _, c := range conns {
			c.Close()
		}
		if ok {
			return base
		}
	}
	panic("no usable UDP port range found")
}

func newSvc(t *testing.T, name string, base int, mod ...func(*Options)) *svc {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pm := peer.NewManager(logger.Discard())
	opts := Options{BasePort: base, PortRange: 4, BroadcastAddr: "127.0.0.1", Interval: 50 * time.Millisecond, Username: name, TCPPort: 4000 + rand.IntN(1000)}
	for _, f := range mod {
		f(&opts)
	}
	s := NewService(opts, id, logger.Discard(), pm)
	if err := s.Start(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	return &svc{Service: s, id: id, peers: pm}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPeersDiscoverEachOther(t *testing.T) {
	base := randomBase()
	a, b := newSvc(t, "alice", base), newSvc(t, "bob", base)
	if a.Port() == b.Port() {
		t.Fatal("instances must take different ports")
	}
	eventually(t, "alice to find bob", func() bool { _, ok := a.peers.GetPeer(b.id.ID()); return ok })
	eventually(t, "bob to find alice", func() bool { _, ok := b.peers.GetPeer(a.id.ID()); return ok })

	got, _ := a.peers.GetPeer(b.id.ID())
	if got.Username != "bob" || got.Address != "127.0.0.1" || got.Port != b.opts.TCPPort {
		t.Fatalf("discovered %+v", got)
	}
	if _, ok := a.peers.GetPeer(a.id.ID()); ok {
		t.Fatal("a peer discovered itself")
	}
}

func TestStopIsPromptAndIdempotent(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	done := make(chan struct{})
	go func() { s.Stop(); s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked")
	}
	if err := s.Start(bg); err == nil {
		// A stopped service must not silently restart with a dead socket.
		s.Stop()
	}
}

func TestStartErrors(t *testing.T) {
	base := randomBase()
	a := newSvc(t, "alice", base)
	if err := a.Start(bg); !errors.Is(err, apperrors.ErrAppAlreadyRunning) {
		t.Fatalf("double start: %v", err)
	}

	// Every port in the range taken.
	hogs := make([]*net.UDPConn, 0, 3)
	for p := base + 1; p < base+4; p++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
		if err != nil {
			t.Skip("port unavailable")
		}
		hogs = append(hogs, c)
		defer c.Close()
	}
	pm := peer.NewManager(logger.Discard())
	id, _ := identity.Generate()
	full := NewService(Options{BasePort: base, PortRange: 4, BroadcastAddr: "127.0.0.1", Interval: time.Second, Username: "x", TCPPort: 1}, id, logger.Discard(), pm)
	if err := full.Start(bg); !errors.Is(err, apperrors.ErrDiscoveryStartFailed) {
		t.Fatalf("expected a bind failure, got %v", err)
	}

	bad := NewService(Options{BasePort: base + 100, PortRange: 1, BroadcastAddr: "not-an-ip", Interval: time.Second, Username: "x", TCPPort: 1}, id, logger.Discard(), pm)
	if err := bad.Start(bg); err == nil {
		t.Fatal("bad broadcast address accepted")
	}
}

// ---- Forged and malformed packets ---------------------------------------

func sign(id *identity.Identity, mod func(*announcement)) []byte {
	a := announcement{
		Type: announceType, Version: announceVersion, PeerID: id.ID(), PublicKey: id.PublicKey(),
		Username: "mallory", Port: 9999, Timestamp: time.Now().UnixMilli(),
	}
	if mod != nil {
		mod(&a)
	}
	a.Signature = id.Sign(a.signedBytes())
	data, _ := json.Marshal(a)
	return data
}

// inject feeds a datagram straight to the packet handler, as if from addr.
func inject(s *svc, data []byte, ip string) {
	s.handlePacket(data, &net.UDPAddr{IP: net.ParseIP(ip), Port: 5555})
}

func TestValidAnnouncementIsAccepted(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	id, _ := identity.Generate()
	inject(s, sign(id, nil), "10.0.0.7")
	p, ok := s.peers.GetPeer(id.ID())
	if !ok || p.Address != "10.0.0.7" || p.Port != 9999 || p.Username != "mallory" {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
}

func TestForgedAnnouncementsAreRejected(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	victim, _ := identity.Generate()
	attacker, _ := identity.Generate()

	cases := map[string][]byte{
		"victim's ID, attacker's key": sign(attacker, func(a *announcement) { a.PeerID = victim.ID() }),
		"victim's ID and key, attacker's signature": func() []byte {
			a := announcement{Type: announceType, Version: announceVersion, PeerID: victim.ID(), PublicKey: victim.PublicKey(),
				Username: "victim", Port: 1234, Timestamp: time.Now().UnixMilli()}
			a.Signature = attacker.Sign(a.signedBytes())
			d, _ := json.Marshal(a)
			return d
		}(),
		"tampered port after signing": func() []byte {
			var a announcement
			_ = json.Unmarshal(sign(attacker, nil), &a)
			a.Port = 22
			d, _ := json.Marshal(a)
			return d
		}(),
		"tampered username after signing": func() []byte {
			var a announcement
			_ = json.Unmarshal(sign(attacker, nil), &a)
			a.Username = "root"
			d, _ := json.Marshal(a)
			return d
		}(),
		"stale (replayed old packet)": sign(attacker, func(a *announcement) { a.Timestamp = time.Now().Add(-10 * time.Minute).UnixMilli() }),
		"from the future":             sign(attacker, func(a *announcement) { a.Timestamp = time.Now().Add(10 * time.Minute).UnixMilli() }),
		"port zero":                   sign(attacker, func(a *announcement) { a.Port = 0 }),
		"port too large":              sign(attacker, func(a *announcement) { a.Port = 70000 }),
		"escape sequence in name":     sign(attacker, func(a *announcement) { a.Username = "\x1b[2Jhacked" }),
		"empty name":                  sign(attacker, func(a *announcement) { a.Username = "" }),
		"wrong version":               sign(attacker, func(a *announcement) { a.Version = 2 }),
		"wrong type":                  sign(attacker, func(a *announcement) { a.Type = "goodbye" }),
		"short key":                   sign(attacker, func(a *announcement) { a.PublicKey = a.PublicKey[:10] }),
		"not json":                    []byte("hello"),
		"empty":                       {},
		"oversize":                    []byte(strings.Repeat("x", maxPacket+1)),
		"json null":                   []byte("null"),
	}
	for _, data := range cases {
		inject(s, data, "10.9.9.9")
	}
	if n := s.peers.Count(); n != 0 {
		for _, p := range s.peers.Peers() {
			t.Logf("accepted: %+v", p)
		}
		t.Fatalf("%d forged announcements were accepted", n)
	}
}

func TestReplayedAnnouncementDoesNotMoveAPeer(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	id, _ := identity.Generate()

	first := sign(id, nil)
	inject(s, first, "10.0.0.1")
	// Later, the real peer moves; newer announcement from the new address.
	time.Sleep(5 * time.Millisecond)
	inject(s, sign(id, nil), "10.0.0.2")
	// An attacker replays the captured first packet from elsewhere.
	inject(s, first, "10.6.6.6")

	p, _ := s.peers.GetPeer(id.ID())
	if p.Address != "10.0.0.2" {
		t.Fatalf("replay moved the peer to %s", p.Address)
	}
	// The identical packet twice is also dropped. (Timestamps have
	// millisecond resolution, so let the clock move first.)
	time.Sleep(5 * time.Millisecond)
	same := sign(id, nil)
	inject(s, same, "10.0.0.3")
	inject(s, same, "10.0.0.4")
	if p, _ := s.peers.GetPeer(id.ID()); p.Address != "10.0.0.3" {
		t.Fatalf("duplicate packet accepted: %s", p.Address)
	}
}

func TestSourceRateLimit(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	// One source address hammering with many valid identities (Sybil flood).
	for i := range 200 {
		id, _ := identity.Generate()
		_ = i
		inject(s, sign(id, nil), "10.5.5.5")
	}
	if n := s.peers.Count(); n > sourceBurst+2 {
		t.Fatalf("one source registered %d peers; rate limit burst is %d", n, sourceBurst)
	}
	// A different source is unaffected.
	id, _ := identity.Generate()
	inject(s, sign(id, nil), "10.7.7.7")
	if _, ok := s.peers.GetPeer(id.ID()); !ok {
		t.Fatal("legitimate source was throttled by someone else's flood")
	}
}

func TestOwnAnnouncementsIgnored(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	data, err := s.buildAnnouncement()
	if err != nil {
		t.Fatal(err)
	}
	inject(s, data, "127.0.0.1")
	if s.peers.Count() != 0 {
		t.Fatal("registered ourselves")
	}
}

func TestClockSkewToleranceBoundary(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	for name, skew := range map[string]time.Duration{"30s ahead": 30 * time.Second, "30s behind": -30 * time.Second} {
		id, _ := identity.Generate()
		inject(s, sign(id, func(a *announcement) { a.Timestamp = time.Now().Add(skew).UnixMilli() }), "10.0.0.1")
		if _, ok := s.peers.GetPeer(id.ID()); !ok {
			t.Errorf("%s: modest clock skew should be tolerated", name)
		}
	}
}

func TestReplayTableIsBounded(t *testing.T) {
	s := newSvc(t, "alice", randomBase(), func(o *Options) { o.Interval = time.Hour })
	for i := range maxTracked + 10 {
		s.acceptTimestamp(strings.Repeat("a", 31)+string(rune('a'+i%26))+string(rune(i)), int64(i))
	}
	s.mu.Lock()
	n := len(s.lastSeen)
	s.mu.Unlock()
	if n > maxTracked {
		t.Fatalf("replay table grew to %d", n)
	}
}

// Real sockets: a datagram that is not an announcement must not disturb the
// listener.
func TestGarbageOverTheWire(t *testing.T) {
	a := newSvc(t, "alice", randomBase())
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: a.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, junk := range []string{"", "{", "\x00\x01\x02", strings.Repeat("A", 5000)} {
		_, _ = c.Write([]byte(junk))
	}
	b := newSvc(t, "bob", a.opts.BasePort)
	eventually(t, "discovery after garbage", func() bool { _, ok := a.peers.GetPeer(b.id.ID()); return ok })
}
