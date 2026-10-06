package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
)

// islands starts two instances whose discovery ports differ, so they cannot
// find each other, as on a network where broadcasts are blocked.
func islands(t *testing.T, mods ...func(*config.Config)) (alice, bob *instance) {
	t.Helper()
	bob = newInstance(t, "bob", randomBase())
	alice = newInstance(t, "alice", randomBase(), mods...)
	return alice, bob
}

func (i *instance) addr() string { return fmt.Sprintf("127.0.0.1:%d", i.app.config.TCPPort) }

func TestConnectByAddressWhenDiscoveryCannotWork(t *testing.T) {
	alice, bob := islands(t)
	time.Sleep(1500 * time.Millisecond) // long enough for an announcement, had one been heard
	if len(alice.app.Peers().Peers()) != 0 {
		t.Fatal("setup: the two instances discovered each other")
	}

	// By ID alone there is nothing to go on, and the error says what to do.
	alice.say("/send %s hi", bob.app.ID())
	alice.waitOut("not been discovered", "/connect <ip>")

	alice.say("/connect %s", bob.addr())
	alice.waitOut("Connecting to "+bob.addr(), "bob", "connected")
	alice.waitOut("/safety") // connected without an ID to check: confirm who it is
	connected := func() bool { return bob.app.Network().IsConnected(alice.app.ID()) }
	deadline := time.Now().Add(5 * time.Second)
	for !connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !connected() {
		t.Fatal("bob does not see the connection")
	}

	// The peer is now known, so it can be addressed by name, and messages flow.
	alice.say("/send bob hello across the island")
	bob.waitOut("hello across the island")
	alice.say("/list")
	alice.waitOut("bob")
}

func TestConnectByAddressPinsTheIDGiven(t *testing.T) {
	alice, bob := islands(t)
	other := newInstance(t, "mallory", randomBase())

	// Mallory answers at an address Alice believes is Bob's: refused.
	alice.say("/connect %s@%s", bob.app.ID(), other.addr())
	alice.waitOut("could not connect")
	if alice.app.Network().IsConnected(other.app.ID()) {
		t.Fatal("connected to the wrong peer")
	}

	// The right pair works, and with an ID to check there is no "confirm who" nag.
	alice.say("/connect %s@%s", bob.app.ID(), bob.addr())
	alice.waitOut("bob", "connected")
	if strings.Contains(alice.out.String(), "/safety") {
		t.Fatalf("asked to confirm identity although the ID was pinned:\n%s", alice.out.String())
	}
}

func TestBadAddressesAreExplained(t *testing.T) {
	alice, _ := islands(t)
	for line, want := range map[string]string{
		"/connect 10.0.0.1:99999":      "invalid port",
		"/connect nothex@10.0.0.1":     "not a valid peer ID",
		"/connect 127.0.0.1:1":         "could not connect",
		"/connect bad_host!.example.x": "invalid host",
	} {
		alice.say("%s", line)
		alice.waitOut(want)
	}
}

func TestConfiguredPeersAreConnectedAtStartUp(t *testing.T) {
	bob := newInstance(t, "bob", randomBase())
	alice := newInstance(t, "alice", randomBase(), func(c *config.Config) {
		c.Peers = []string{bob.app.ID() + "@" + bob.addr()}
	})
	alice.waitOut("bob", "connected")
	if !alice.app.Network().IsConnected(bob.app.ID()) {
		t.Fatal("not connected")
	}
}

func TestConfiguredPeersAreRetriedUntilTheyAppear(t *testing.T) {
	port := freeTCPPort(t)
	alice := newInstance(t, "alice", randomBase(), func(c *config.Config) {
		c.Peers = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	})
	time.Sleep(500 * time.Millisecond) // the first attempt finds nobody
	bob := newInstance(t, "bob", randomBase(), func(c *config.Config) { c.TCPPort = port })
	alice.waitOut("bob", "connected")
	_ = bob
}

func TestPeersConfigIsValidated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Path = "chat.db"
	cfg.Peers = []string{"10.0.0.5:8080", "nothex@10.0.0.6"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a malformed peer address was accepted")
	}
	cfg.Peers = []string{"10.0.0.5:8080", "0123456789abcdef0123456789abcdef@bob.local"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPeerFlagAndEnvironment(t *testing.T) {
	cfg, err := config.Load([]string{"--peer", "10.0.0.5", "--peer", "10.0.0.6:9000"}, func(string) string { return "" })
	if err != nil || len(cfg.Peers) != 2 || cfg.Peers[1] != "10.0.0.6:9000" {
		t.Fatalf("flags: %+v %v", cfg.Peers, err)
	}
	cfg, err = config.Load(nil, func(k string) string {
		if k == "P2P_PEERS" {
			return " 10.0.0.5 , ,10.0.0.6:9000"
		}
		return ""
	})
	if err != nil || len(cfg.Peers) != 2 || cfg.Peers[0] != "10.0.0.5" {
		t.Fatalf("env: %+v %v", cfg.Peers, err)
	}
	if _, err := config.Load([]string{"--peer", "host:99999"}, func(string) string { return "" }); err == nil {
		t.Fatal("a bad --peer was accepted")
	}
}
