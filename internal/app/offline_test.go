package app

import (
	"context"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
)

// trio starts alice, bob and carol, all discovering each other.
func trio(t *testing.T, mods ...func(*config.Config)) (alice, bob, carol *instance) {
	t.Helper()
	base := randomBase()
	alice = newInstance(t, "alice", base, mods...)
	bob = newInstance(t, "bob", base, mods...)
	carol = newInstance(t, "carol", base, mods...)
	for _, pair := range [][2]*instance{{alice, bob}, {alice, carol}, {bob, alice}, {bob, carol}, {carol, alice}, {carol, bob}} {
		waitDiscovered(t, pair[0], pair[1])
	}
	return
}

func waitDiscovered(t *testing.T, me, other *instance) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, ok := me.app.Peers().GetPeer(other.app.ID()); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never discovered %s", me.name, other.name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func connected(t *testing.T, from, to *instance) {
	t.Helper()
	from.say("/connect %s", to.name)
	deadline := time.Now().Add(10 * time.Second)
	for !from.app.Network().IsConnected(to.app.ID()) {
		if time.Now().After(deadline) {
			t.Fatalf("%s could not connect to %s\n%s", from.name, to.name, from.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitBundle waits until `from` can encrypt to `to`, which happens when they
// connect and exchange prekey bundles.
func waitBundle(t *testing.T, from, to *instance) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !from.app.relay.Offline.HasBundle(context.Background(), to.app.ID()) {
		if time.Now().After(deadline) {
			t.Fatalf("%s never received %s's prekey bundle", from.name, to.name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// relayHolds polls /relay until the instance reports holding n messages.
func relayHolds(t *testing.T, in *instance, n int) {
	t.Helper()
	want := "holding " + itoa(n) + " encrypted message(s)"
	deadline := time.Now().Add(10 * time.Second)
	for {
		mark := len(in.out.String())
		in.say("/relay")
		time.Sleep(150 * time.Millisecond)
		if strings.Contains(in.out.String()[mark:], want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never reported %q:\n%s", in.name, want, in.out.String())
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// reopen stops an instance and starts a new one with the same keys, database
// and ports: a laptop being closed and opened again.
func reopen(t *testing.T, old *instance) *instance {
	t.Helper()
	cfg := *old.app.config
	old.app.Stop()

	pr, pw := io.Pipe()
	out := &syncBuf{}
	a, err := New(&cfg, WithIO(pr, out))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go a.CLI().Start(ctx)
	t.Cleanup(func() { cancel(); pw.Close(); a.Stop() })
	if a.ID() != old.app.ID() {
		t.Fatal("identity changed across the restart")
	}
	return &instance{t: t, name: old.name, app: a, in: pw, out: out, dir: old.dir}
}

// The headline scenario: Alice and Bob are never online together.
func TestMessageIsDeliveredToAPeerWhoWasOffline(t *testing.T) {
	alice, bob, carol := trio(t)

	// Alice and Bob talk once, which also exchanges their prekey bundles.
	alice.say("/send bob hello")
	bob.waitOut("hello")
	waitBundle(t, alice, bob)

	// Bob closes his laptop. Alice writes to him anyway; Carol is the only one
	// she can reach, and holds the message.
	bobID := bob.app.ID()
	bob.app.Stop()
	connected(t, alice, carol)
	alice.say("/send bob while you were away")
	alice.waitOut("queued with relays")
	alice.say("/history bob")
	alice.waitOut("while you were away", "(not delivered)") // not delivered *yet*

	relayHolds(t, carol, 1)

	// Now Alice goes offline too. Nobody who sent or will receive it is online.
	aliceAway := reopenLater(t, alice)

	// Bob comes back and meets Carol only.
	bob = reopen(t, bob)
	if bob.app.ID() != bobID {
		t.Fatal("bob's identity changed")
	}
	waitDiscovered(t, bob, carol)
	connected(t, bob, carol)
	bob.waitOut("alice", "while you were away")
	relayHolds(t, carol, 0)

	// Alice returns and learns it arrived, through a receipt only Bob could sign.
	aliceAway.start(t)
	alice = aliceAway.inst
	waitDiscovered(t, alice, carol)
	connected(t, alice, carol)
	deadline := time.Now().Add(10 * time.Second)
	for {
		alice.say("/history bob")
		time.Sleep(300 * time.Millisecond)
		out := alice.out.String()
		if i := strings.LastIndex(out, "while you were away"); i >= 0 && !strings.Contains(out[i:], "(not delivered)") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Alice was never told the message arrived:\n%s", out)
		}
	}
}

// laterInstance lets a test stop an instance now and bring it back later.
type laterInstance struct {
	inst *instance
	cfg  config.Config
}

func reopenLater(t *testing.T, old *instance) *laterInstance {
	t.Helper()
	li := &laterInstance{cfg: *old.app.config, inst: old}
	old.app.Stop()
	return li
}

func (l *laterInstance) start(t *testing.T) {
	t.Helper()
	pr, pw := io.Pipe()
	out := &syncBuf{}
	cfg := l.cfg
	a, err := New(&cfg, WithIO(pr, out))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go a.CLI().Start(ctx)
	t.Cleanup(func() { cancel(); pw.Close(); a.Stop() })
	l.inst = &instance{t: t, name: l.inst.name, app: a, in: pw, out: out, dir: l.inst.dir}
}

// If no relay is reachable at send time, the message is queued later, as soon
// as the sender meets one - even though the recipient is still away.
func TestMessageIsQueuedWithARelayFoundLater(t *testing.T) {
	alice, bob, carol := trio(t)
	alice.say("/send bob hello")
	bob.waitOut("hello")
	waitBundle(t, alice, bob)
	bob.app.Stop()

	// Alone with nobody to hold it: saved, but not yet queued anywhere.
	alice.say("/send bob nobody can carry this yet")
	alice.waitOut("saved but not delivered")

	connected(t, alice, carol)
	alice.app.Handler().RetryAll(context.Background()) // the periodic retry
	alice.waitOut("queued with relays")

	bob = reopen(t, bob)
	waitDiscovered(t, bob, carol)
	connected(t, bob, carol)
	bob.waitOut("nobody can carry this yet")
}

func TestRelayingCanBeSwitchedOff(t *testing.T) {
	var carolOff func(*config.Config)
	base := randomBase()
	alice := newInstance(t, "alice", base)
	bob := newInstance(t, "bob", base)
	carolOff = func(c *config.Config) { c.Relay = false }
	carol := newInstance(t, "carol", base, carolOff)
	for _, p := range [][2]*instance{{alice, bob}, {alice, carol}} {
		waitDiscovered(t, p[0], p[1])
	}
	alice.say("/send bob hello")
	bob.waitOut("hello")
	waitBundle(t, alice, bob)
	bob.app.Stop()
	connected(t, alice, carol)

	alice.say("/send bob is anyone holding this?")
	alice.waitOut("saved but not delivered")
	carol.say("/relay")
	carol.waitOut("Relaying is OFF")
}

func TestRelayCommandShowsStatus(t *testing.T) {
	alice, _ := pair(t)
	alice.say("/relay")
	alice.waitOut("Relaying is ON", "holding 0 encrypted message(s)")
}

func TestRelayConfigIsValidated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Path = "chat.db"
	cfg.RelayMaxStorage = 10
	if err := cfg.Validate(); err == nil {
		t.Fatal("an absurdly small relay storage limit was accepted")
	}
	cfg.RelayMaxStorage = 8 << 20
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

// With a third peer to forward for her, Alice's offline message is queued
// without any relay seeing who sent it, and she is not warned.
func TestOfflineMessageIsQueuedAnonymouslyWhenAForwarderExists(t *testing.T) {
	base := randomBase()
	alice, bob := newInstance(t, "alice", base), newInstance(t, "bob", base)
	carol, yan := newInstance(t, "carol", base), newInstance(t, "yan", base)
	for _, p := range [][2]*instance{{alice, bob}, {alice, carol}, {alice, yan}, {yan, carol}} {
		waitDiscovered(t, p[0], p[1])
	}
	alice.say("/send bob hello")
	bob.waitOut("hello")
	waitBundle(t, alice, bob)
	bob.app.Stop()
	connected(t, alice, carol)
	connected(t, alice, yan)
	connected(t, yan, carol)

	alice.say("/send bob in a sealed envelope")
	alice.waitOut("queued with relays")
	if strings.Contains(alice.out.String(), "could see that this is from you") {
		t.Fatalf("Alice was warned although forwarders were available:\n%s", alice.out.String())
	}
	relayHolds(t, carol, 1)
	relayHolds(t, yan, 1)
}

// Alone with a single relay the sender is visible to it, and the app says so;
// with sealed_sender=required it refuses to queue at all.
func TestSealedSenderPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy string
		queued bool
	}{{"auto", true}, {"required", false}} {
		t.Run(tc.policy, func(t *testing.T) {
			alice, bob, carol := trio(t, func(c *config.Config) { c.SealedSender = tc.policy })
			alice.say("/send bob hello")
			bob.waitOut("hello")
			waitBundle(t, alice, bob)
			bob.app.Stop()
			connected(t, alice, carol)

			alice.say("/send bob only one relay is reachable")
			if tc.queued {
				alice.waitOut("queued with relays", "could see that this is from you")
				relayHolds(t, carol, 1)
			} else {
				alice.waitOut("saved but not delivered")
				relayHolds(t, carol, 0)
			}
		})
	}
}

func TestSealedSenderConfigIsValidated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Path = "chat.db"
	cfg.SealedSender = "sometimes"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an unknown sealed_sender mode was accepted")
	}
}
