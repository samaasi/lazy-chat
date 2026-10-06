package peer

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/models"
)

func id(n int) string { return fmt.Sprintf("%032x", n) }

func newMgr() *Manager { return NewManager(logger.Discard()) }

func add(m *Manager, n int, name, addr string) bool {
	return m.AddPeer(&models.Peer{ID: id(n), Username: name, Address: addr, Port: 8080, LastSeen: time.Now()})
}

func TestAddReportsNewAndUpdates(t *testing.T) {
	m := newMgr()
	if !add(m, 1, "alice", "10.0.0.1") {
		t.Fatal("first add should report new")
	}
	if add(m, 1, "alice2", "10.0.0.9") {
		t.Fatal("second add of the same ID is an update")
	}
	p, ok := m.GetPeer(id(1))
	if !ok || p.Username != "alice2" || p.Address != "10.0.0.9" {
		t.Fatalf("update lost: %+v", p)
	}
}

func TestCopiesAreIsolated(t *testing.T) {
	m := newMgr()
	in := &models.Peer{ID: id(1), Username: "alice", Address: "10.0.0.1", Port: 1, LastSeen: time.Now()}
	m.AddPeer(in)
	in.Username = "changed-by-caller"
	got, _ := m.GetPeer(id(1))
	if got.Username != "alice" {
		t.Fatal("stored peer aliases the caller's pointer")
	}
	got.Username = "changed-by-reader"
	if again, _ := m.GetPeer(id(1)); again.Username != "alice" {
		t.Fatal("returned peer aliases internal state")
	}
}

func TestLimitsStopTableFlooding(t *testing.T) {
	m := newMgr()
	for i := range MaxPeersPerAddress + 5 {
		add(m, i+1, fmt.Sprintf("p%d", i), "6.6.6.6")
	}
	if n := m.Count(); n != MaxPeersPerAddress {
		t.Fatalf("one address registered %d identities, limit is %d", n, MaxPeersPerAddress)
	}
	// An existing identity from a saturated address can still refresh.
	if add(m, 1, "p0", "6.6.6.6") {
		t.Fatal("refresh reported as new")
	}
	// A legitimate peer from elsewhere is unaffected.
	if !add(m, 5000, "real", "10.0.0.2") {
		t.Fatal("legitimate peer locked out")
	}

	big := newMgr()
	for i := range MaxPeers + 50 {
		big.AddPeer(&models.Peer{ID: id(i + 1), Username: "x", Address: fmt.Sprintf("10.%d.%d.1", i/250, i%250), Port: 1, LastSeen: time.Now()})
	}
	if n := big.Count(); n != MaxPeers {
		t.Fatalf("table grew to %d, limit %d", n, MaxPeers)
	}
}

func TestResolvePeer(t *testing.T) {
	m := newMgr()
	m.AddPeer(&models.Peer{ID: "aaaa" + id(1)[4:], Username: "Alice", Address: "10.0.0.1", Port: 1, LastSeen: time.Now()})
	m.AddPeer(&models.Peer{ID: "aaab" + id(2)[4:], Username: "Bob", Address: "10.0.0.2", Port: 1, LastSeen: time.Now()})
	m.AddPeer(&models.Peer{ID: "cccc" + id(3)[4:], Username: "bob", Address: "10.0.0.3", Port: 1, LastSeen: time.Now()})

	ok := map[string]string{
		"aaaa" + id(1)[4:]: "Alice", // full ID
		"AAAA" + id(1)[4:]: "Alice", // case-insensitive ID
		"aaaa":             "Alice", // unique prefix
		"alice":            "Alice", // username
		"  ALICE ":         "Alice",
		"cccc":             "bob",
	}
	for q, want := range ok {
		p, err := m.ResolvePeer(q)
		if err != nil || p.Username != want {
			t.Errorf("ResolvePeer(%q) = %v, %v; want %s", q, p, err, want)
		}
	}

	if _, err := m.ResolvePeer("aaa"); !errors.Is(err, apperrors.ErrPeerNotFound) {
		t.Errorf("prefix below the minimum length matched: %v", err)
	}
	if _, err := m.ResolvePeer("bob"); !errors.Is(err, apperrors.ErrPeerInvalidID) {
		t.Errorf("ambiguous username must be an error, got %v", err)
	}
	if _, err := m.ResolvePeer("zzzzzz"); !errors.Is(err, apperrors.ErrPeerNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := m.ResolvePeer(""); err == nil {
		t.Error("empty query accepted")
	}
}

func TestPeersSortedAndCleanup(t *testing.T) {
	m := newMgr()
	add(m, 1, "zed", "10.0.0.1")
	add(m, 2, "Amy", "10.0.0.2")
	add(m, 3, "bob", "10.0.0.3")
	var names []string
	for _, p := range m.Peers() {
		names = append(names, p.Username)
	}
	if fmt.Sprint(names) != "[Amy bob zed]" {
		t.Fatalf("order: %v", names)
	}

	m.AddPeer(&models.Peer{ID: id(9), Username: "old", Address: "10.0.0.9", Port: 1, LastSeen: time.Now().Add(-time.Hour)})
	m.CleanupStalePeers(time.Minute)
	if _, ok := m.GetPeer(id(9)); ok {
		t.Fatal("stale peer kept")
	}
	if m.Count() != 3 {
		t.Fatalf("fresh peers removed: %d", m.Count())
	}
	m.RemovePeer(id(1))
	if m.Count() != 2 {
		t.Fatal("RemovePeer failed")
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := newMgr()
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				add(m, w*1000+i+1, "p", fmt.Sprintf("10.%d.0.1", w))
				m.Peers()
				m.GetPeer(id(i))
				_, _ = m.ResolvePeer("p")
			}
		}()
	}
	wg.Wait()
}

func TestIPv6AddressFormatting(t *testing.T) {
	p := &models.Peer{Address: "fe80::1", Port: 8080}
	if got := p.NetworkAddress(); got != "[fe80::1]:8080" {
		t.Fatalf("got %q", got)
	}
}
