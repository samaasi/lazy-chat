package offline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/storage"
)

var ctx = context.Background()

type peerEnv struct {
	id  *identity.Identity
	svc *Service
	db  *storage.SQLiteDB
}

// clock is a shared, adjustable time source for all peers in a test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newPeer(t *testing.T, clk *clock) *peerEnv {
	t.Helper()
	db := storage.NewSQLiteDB(filepath.Join(t.TempDir(), "p.db"))
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate()
	svc := NewService(id, db)
	svc.now = clk.now
	return &peerEnv{id: id, svc: svc, db: db}
}

// introduce makes `to` learn `from`'s bundle, as happens when they connect.
func introduce(t *testing.T, from, to *peerEnv) {
	t.Helper()
	b, err := from.svc.OurBundleFor(ctx, to.id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := to.svc.RememberBundle(ctx, from.id.ID(), b); err != nil {
		t.Fatal(err)
	}
}

func TestOurBundleIsValidStableAndReservesPerPeer(t *testing.T) {
	clk := &clock{t: time.Now()}
	bob := newPeer(t, clk)

	forAlice, err := bob.svc.OurBundleFor(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if id, err := forAlice.Verify(); err != nil || id != bob.id.ID() {
		t.Fatalf("our own bundle does not verify: %q %v", id, err)
	}
	if len(forAlice.OPKs) != opkBatch {
		t.Fatalf("%d one-time prekeys", len(forAlice.OPKs))
	}

	again, _ := bob.svc.OurBundleFor(ctx, "alice")
	if again.SPK.ID != forAlice.SPK.ID || len(again.OPKs) != opkBatch || again.OPKs[0].ID != forAlice.OPKs[0].ID {
		t.Fatal("asking again must return the same prekeys, not mint new ones")
	}

	forCarol, _ := bob.svc.OurBundleFor(ctx, "carol")
	seen := map[uint32]bool{}
	for _, o := range forAlice.OPKs {
		seen[o.ID] = true
	}
	for _, o := range forCarol.OPKs {
		if seen[o.ID] {
			t.Fatalf("one-time prekey %d was given to two different peers", o.ID)
		}
	}
	if forCarol.SPK.ID != forAlice.SPK.ID {
		t.Fatal("the signed prekey is shared; only one-time prekeys are per peer")
	}
}

func TestSwarmOfIdentitiesCannotMakeUsMintUnlimitedPrekeys(t *testing.T) {
	clk := &clock{t: time.Now()}
	bob := newPeer(t, clk)
	for i := range maxOPKTotal/opkBatch + 20 {
		if _, err := bob.svc.OurBundleFor(ctx, fmt.Sprintf("peer-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := bob.db.CountOPKs(ctx); n > maxOPKTotal {
		t.Fatalf("%d one-time prekeys; the cap is %d", n, maxOPKTotal)
	}
	// Beyond the cap a bundle still works, just without one-time prekeys.
	b, err := bob.svc.OurBundleFor(ctx, "one-more-stranger")
	if err != nil || len(b.OPKs) != 0 {
		t.Fatalf("over the cap: %d prekeys, %v", len(b.OPKs), err)
	}
	if _, err := b.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndOfflineMessage(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice) // they met once; Bob gave Alice his bundle

	blob, err := alice.svc.Seal(ctx, bob.id.ID(), []byte("see you tomorrow"))
	if err != nil {
		t.Fatal(err)
	}
	// ... Bob is offline for a while; a relay holds `blob` ...
	plain, from, err := bob.svc.Open(ctx, blob)
	if err != nil || string(plain) != "see you tomorrow" || from != alice.id.ID() {
		t.Fatalf("open: %q %s %v", plain, from, err)
	}

	// The one-time prekey was destroyed: a replayed copy cannot be opened.
	if _, _, err := bob.svc.Open(ctx, blob); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("replay: %v", err)
	}
}

func TestEachMessageUsesAFreshOneTimePrekeyThenDegradesGracefully(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)

	var blobs [][]byte
	for range opkBatch + 3 { // more messages than one-time prekeys
		b, err := alice.svc.Seal(ctx, bob.id.ID(), []byte("m"))
		if err != nil {
			t.Fatal(err)
		}
		blobs = append(blobs, b)
	}
	for i, b := range blobs {
		if _, _, err := bob.svc.Open(ctx, b); err != nil {
			t.Fatalf("message %d (the last 3 had no one-time prekey): %v", i, err)
		}
	}
}

func TestUsedPrekeysAreNeverOfferedAgain(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)

	// Bob announces his bundle (with prekeys reserved for Alice) twice, with
	// Alice sending a message in between and Bob not having opened it yet.
	b1, _ := bob.svc.OurBundleFor(ctx, alice.id.ID())
	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), b1); err != nil {
		t.Fatal(err)
	}
	first, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("one"))
	b2, _ := bob.svc.OurBundleFor(ctx, alice.id.ID()) // still lists the prekey Alice just used
	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), b2); err != nil {
		t.Fatal(err)
	}
	second, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("two"))

	for name, blob := range map[string][]byte{"first": first, "second": second} {
		if _, _, err := bob.svc.Open(ctx, blob); err != nil {
			t.Fatalf("%s message could not be opened (a one-time prekey was reused): %v", name, err)
		}
	}
}

func TestBundleHandling(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob, mallory := newPeer(t, clk), newPeer(t, clk), newPeer(t, clk)
	good, _ := bob.svc.OurBundleFor(ctx, alice.id.ID())

	// A relay cannot pass off its own bundle as Bob's, nor alter Bob's.
	mb, _ := mallory.svc.OurBundleFor(ctx, alice.id.ID())
	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), mb); !errors.Is(err, ErrBadBundle) {
		t.Fatalf("bundle of another peer accepted under Bob's ID: %v", err)
	}
	tampered := *good
	tampered.IKDH = mb.IKDH
	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), &tampered); err == nil {
		t.Fatal("tampered bundle accepted")
	}
	if alice.svc.HasBundle(ctx, bob.id.ID()) {
		t.Fatal("rejected bundles must leave no trace")
	}
	if _, err := alice.svc.Seal(ctx, bob.id.ID(), []byte("x")); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("seal without a bundle: %v", err)
	}

	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), good); err != nil {
		t.Fatal(err)
	}
	if !alice.svc.HasBundle(ctx, bob.id.ID()) {
		t.Fatal("bundle not stored")
	}

	// Gossip form: no one-time prekeys, and it does not wipe the ones we hold.
	gossip, err := alice.svc.BundleForGossip(ctx, bob.id.ID())
	if err != nil || len(gossip.OPKs) != 0 {
		t.Fatalf("gossip: %+v %v", gossip, err)
	}
	carol := newPeer(t, clk)
	if err := carol.svc.RememberBundle(ctx, bob.id.ID(), gossip); err != nil {
		t.Fatalf("a gossiped bundle must verify for the receiver: %v", err)
	}
	if err := alice.svc.RememberBundle(ctx, bob.id.ID(), gossip); err != nil {
		t.Fatal(err)
	}
	st, _ := alice.svc.load(ctx, bob.id.ID())
	if len(st.Bundle.OPKs) != opkBatch {
		t.Fatalf("gossip erased our one-time prekeys (%d left)", len(st.Bundle.OPKs))
	}
	if _, err := carol.svc.BundleForGossip(ctx, mallory.id.ID()); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("unknown peer: %v", err)
	}
	if own, err := bob.svc.BundleForGossip(ctx, bob.id.ID()); err != nil || len(own.OPKs) != 0 {
		t.Fatalf("own bundle for gossip: %v", err)
	}
}

func TestNewerSignedPrekeyWinsAndAnOlderOneCannotReplaceIt(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	oldBundle, _ := bob.svc.OurBundleFor(ctx, alice.id.ID())
	clk.advance(SPKRotate + time.Hour) // Bob rotates
	newBundle, _ := bob.svc.OurBundleFor(ctx, alice.id.ID())
	if newBundle.SPK.ID == oldBundle.SPK.ID {
		t.Fatal("no rotation happened")
	}

	_ = alice.svc.RememberBundle(ctx, bob.id.ID(), newBundle)
	_ = alice.svc.RememberBundle(ctx, bob.id.ID(), oldBundle) // a stale copy arrives later
	st, _ := alice.svc.load(ctx, bob.id.ID())
	if st.Bundle.SPK.ID != newBundle.SPK.ID {
		t.Fatal("a stale bundle replaced the newer signed prekey")
	}
}

func TestStaleBundlesAreNotUsed(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)
	clk.advance(senderMaxAge + 24*time.Hour) // Bob has long since rotated and may have deleted that key
	if _, err := alice.svc.Seal(ctx, bob.id.ID(), []byte("x")); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("sealed to an old signed prekey: %v", err)
	}
	if alice.svc.HasBundle(ctx, bob.id.ID()) {
		t.Fatal("stale bundle reported as usable")
	}
	if _, err := alice.svc.BundleForGossip(ctx, bob.id.ID()); !errors.Is(err, ErrNoBundle) {
		t.Fatal("stale bundles must not be gossiped")
	}
}

// Messages sealed to an older signed prekey still open during the grace
// period, and stop opening once that key has been deleted (forward secrecy).
func TestSignedPrekeyRotationAndForwardSecrecy(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	b, _ := bob.svc.OurBundleFor(ctx, alice.id.ID())
	b.OPKs = nil // isolate the signed prekey
	_ = alice.svc.RememberBundle(ctx, bob.id.ID(), b)

	early, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("sealed to the first signed prekey"))
	late, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("also the first signed prekey"))

	clk.advance(SPKRotate + time.Hour)
	if _, err := bob.svc.OurBundleFor(ctx, alice.id.ID()); err != nil { // Bob rotates
		t.Fatal(err)
	}
	if _, _, err := bob.svc.Open(ctx, early); err != nil {
		t.Fatalf("an in-flight message must still open after rotation: %v", err)
	}

	clk.advance(SPKRetain)
	if err := bob.svc.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bob.svc.Open(ctx, late); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("after the old key was deleted the message must be unreadable: %v", err)
	}
	// The newest signed prekey always survives maintenance.
	if _, err := bob.svc.OurBundleFor(ctx, "someone"); err != nil {
		t.Fatal(err)
	}
}

func TestMaintainDropsExpiredOneTimePrekeys(t *testing.T) {
	clk := &clock{t: time.Now()}
	bob := newPeer(t, clk)
	_, _ = bob.svc.OurBundleFor(ctx, "alice")
	clk.advance(opkTTL + time.Hour)
	if err := bob.svc.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := bob.db.CountOPKs(ctx); n != 0 {
		t.Fatalf("%d one-time prekeys survived their TTL", n)
	}
}

func TestPrekeyIsDestroyedOnlyAfterTheMessageIsAccepted(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)
	blob, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("do not lose me"))

	// Storing the message fails (disk full, crash...): the message must stay openable.
	if _, _, err := bob.svc.OpenThen(ctx, blob, func([]byte, string) error { return errors.New("disk full") }); err == nil {
		t.Fatal("the failure was swallowed")
	}
	var got string
	if _, _, err := bob.svc.OpenThen(ctx, blob, func(p []byte, _ string) error { got = string(p); return nil }); err != nil || got != "do not lose me" {
		t.Fatalf("a message whose storage failed must be retryable: %q %v", got, err)
	}
	// And once accepted, it is gone for good.
	if _, _, err := bob.svc.Open(ctx, blob); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("after acceptance: %v", err)
	}
}

func TestOpenRejectsGarbageWithoutHarm(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)
	good, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("real"))

	for _, junk := range [][]byte{nil, []byte("junk"), []byte(`{"v":1}`), good[:len(good)/2]} {
		if _, _, err := bob.svc.Open(ctx, junk); err == nil {
			t.Errorf("garbage accepted: %q", junk)
		}
	}
	// None of that burned the real message's one-time prekey.
	if _, _, err := bob.svc.Open(ctx, good); err != nil {
		t.Fatalf("garbage consumed a one-time prekey: %v", err)
	}
}
