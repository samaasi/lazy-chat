package app

import (
	"context"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
)

func waitConnected(t *testing.T, from, to *instance, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !from.app.Network().IsConnected(to.app.ID()) {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not connect to %s\n%s", from.name, to.name, from.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func remembered(t *testing.T, in *instance) map[string]string {
	t.Helper()
	known, err := in.app.db.KnownPeers(context.Background(), time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, p := range known {
		out[p.ID] = p.Username
	}
	return out
}

// After meeting once, peers find each other again by themselves, even where
// discovery never works (the two instances here cannot hear each other).
func TestRememberedPeersAreReconnectedAfterARestart(t *testing.T) {
	alice, bob := islands(t)
	alice.say("/connect %s", bob.addr())
	waitConnected(t, alice, bob, 10*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for remembered(t, alice)[bob.app.ID()] != "bob" {
		if time.Now().After(deadline) {
			t.Fatalf("bob was not remembered: %v", remembered(t, alice))
		}
		time.Sleep(20 * time.Millisecond)
	}

	alice = reopen(t, alice) // no --peer, no /connect
	waitConnected(t, alice, bob, 15*time.Second)
	alice.say("/send bob found you again")
	bob.waitOut("found you again")
}

// A remembered address is tied to the remembered identity: if another machine
// takes it over, it is not connected to.
func TestARememberedAddressIsNotTrustedForSomeoneElse(t *testing.T) {
	alice, bob := islands(t)
	bobPort := bob.app.config.TCPPort
	alice.say("/connect %s", bob.addr())
	waitConnected(t, alice, bob, 10*time.Second)
	time.Sleep(300 * time.Millisecond) // let it be written
	bob.app.Stop()

	mallory := newInstance(t, "mallory", randomBase(), func(c *config.Config) { c.TCPPort = bobPort })
	alice = reopen(t, alice)
	time.Sleep(3 * time.Second) // the start-up reconnection has run
	if alice.app.Network().IsConnected(mallory.app.ID()) {
		t.Fatal("connected to a different peer at a remembered address")
	}
}

func TestForgetAndOptingOut(t *testing.T) {
	alice, bob := islands(t)
	alice.say("/connect %s", bob.addr())
	waitConnected(t, alice, bob, 10*time.Second)
	time.Sleep(300 * time.Millisecond)

	alice.say("/forget bob")
	alice.waitOut("Forgot bob")
	if _, ok := remembered(t, alice)[bob.app.ID()]; ok {
		t.Fatal("still remembered after /forget")
	}
	alice.say("/forget nobody")
	alice.waitOut("no remembered peer matches")

	// Remember again, then turn the feature off: everything is forgotten and
	// nothing is reconnected.
	alice.say("/connect %s", bob.addr())
	time.Sleep(500 * time.Millisecond)
	alice = reopen(t, alice, func(c *config.Config) { c.RememberPeers = false })
	time.Sleep(2 * time.Second)
	if alice.app.Network().IsConnected(bob.app.ID()) {
		t.Fatal("reconnected although remembering is off")
	}
	if n := len(remembered(t, alice)); n != 0 {
		t.Fatalf("%d peers still remembered", n)
	}
}
