package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/network"
	"github.com/samaasi/lazy-chat/internal/offline"
	"github.com/samaasi/lazy-chat/internal/peer"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/storage"
)

var bg = context.Background()

type delivered struct {
	from string
	id   string
	text string
}

type receipt struct{ msgID, signer string }

// node is a complete peer: identity, database, network and relay manager. It
// can be stopped and restarted with the same keys, like a laptop going offline.
type node struct {
	t     *testing.T
	name  string
	id    *identity.Identity
	db    *storage.SQLiteDB
	peers *peer.Manager
	svc   *offline.Service
	opts  Options

	net *network.Manager
	mgr *Manager

	mu       sync.Mutex
	msgs     []delivered
	receipts []receipt
}

func newNode(t *testing.T, name string, opts Options) *node {
	t.Helper()
	db := storage.NewSQLiteDB(filepath.Join(t.TempDir(), name+".db"))
	if err := db.Connect(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(bg); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate()
	n := &node{t: t, name: name, id: id, db: db, peers: peer.NewManager(logger.Discard()), svc: offline.NewService(id, db), opts: opts}
	n.start()
	t.Cleanup(n.stop)
	return n
}

func (n *node) start() {
	n.t.Helper()
	nm, err := network.NewManager(network.Options{
		ListenAddr: "127.0.0.1", Username: n.name, HandshakeTimeout: 3 * time.Second,
		FrameRate: 100000, FrameBurst: 100000,
	}, n.id, logger.Discard(), n.peers)
	if err != nil {
		n.t.Fatal(err)
	}
	n.net = nm
	n.mgr = NewManager(n.opts, Deps{Logger: logger.Discard(), Self: n.id, Net: nm, Offline: n.svc, Store: n.db})
	n.mgr.SetHandlers(func(_ context.Context, sender string, plain []byte) (string, bool) {
		var m struct{ ID, Text string }
		if json.Unmarshal(plain, &m) != nil || m.ID == "" {
			return "", false
		}
		n.mu.Lock()
		n.msgs = append(n.msgs, delivered{from: sender, id: m.ID, text: m.Text})
		n.mu.Unlock()
		return m.ID, true
	}, func(_ context.Context, msgID, signer string) {
		n.mu.Lock()
		n.receipts = append(n.receipts, receipt{msgID, signer})
		n.mu.Unlock()
	})
	n.mgr.Register()
	if err := nm.Start(bg); err != nil {
		n.t.Fatal(err)
	}
}

// stop takes the peer off the network (its database and keys remain).
func (n *node) stop() {
	if n.net != nil {
		n.net.Stop()
		n.mgr.Close()
		n.net = nil
	}
}

func (n *node) restart() { n.stop(); n.start() }

func (n *node) know(o *node) {
	n.peers.AddPeer(&models.Peer{ID: o.id.ID(), Username: o.name, Address: "127.0.0.1", Port: o.net.Port(), LastSeen: time.Now()})
}

func (n *node) connect(o *node) {
	n.t.Helper()
	n.know(o)
	if err := n.net.ConnectToPeer(bg, o.id.ID()); err != nil {
		n.t.Fatalf("%s -> %s: %v", n.name, o.name, err)
	}
	eventually(n.t, n.name+" and "+o.name+" to exchange prekeys", func() bool {
		return n.svc.HasBundle(bg, o.id.ID()) && o.svc.HasBundle(bg, n.id.ID())
	})
}

func (n *node) got() []delivered {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]delivered(nil), n.msgs...)
}

func (n *node) gotReceipts() []receipt {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]receipt(nil), n.receipts...)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func never(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			t.Fatalf("unexpectedly: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func plain(id, text string) []byte {
	b, _ := json.Marshal(map[string]string{"ID": id, "Text": text})
	return b
}

// send queues a message through whichever relays n can reach, returning how
// many agreed to hold it.
func send(n *node, to, id, text string) (int, error) {
	res, err := n.mgr.Dispatch(bg, to, id, plain(id, text))
	return res.Relays, err
}

func held(n *node) int { c, _, _ := n.db.RelayUsage(bg); return c }

var relayOn = Options{Enabled: true, StoreTimeout: 3 * time.Second, BundleTimeout: 2 * time.Second}

// ---- The main journey ----------------------------------------------------------

// Alice and Bob never overlap online. Carol, who is online with each of them
// at different times, carries the message and the receipt.
func TestMessageReachesAnOfflineRecipientThroughARelay(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)

	// Alice and Bob meet once (exchanging prekey bundles), then Bob goes away.
	alice.connect(bob)
	bob.stop()

	// Alice sends to Bob while he is offline; Carol is the only peer she can reach.
	alice.connect(carol)
	n, err := send(alice, bob.id.ID(), "m1", "see you tomorrow")
	if err != nil || n != 1 {
		t.Fatalf("dispatch: %d %v", n, err)
	}
	if held(carol) != 1 {
		t.Fatalf("carol holds %d messages", held(carol))
	}

	// Alice goes offline too: nobody who sent or will receive the message is online.
	alice.stop()
	bob.start()
	bob.connect(carol)

	eventually(t, "Bob to receive the message", func() bool { return len(bob.got()) == 1 })
	if g := bob.got()[0]; g.from != alice.id.ID() || g.text != "see you tomorrow" || g.id != "m1" {
		t.Fatalf("bob got %+v", g)
	}
	eventually(t, "Carol to drop the delivered message", func() bool { return held(carol) == 0 })

	// Later Alice returns, and the signed receipt is waiting for her.
	alice.start()
	alice.connect(carol)
	eventually(t, "Alice's receipt", func() bool { return len(alice.gotReceipts()) == 1 })
	if r := alice.gotReceipts()[0]; r.msgID != "m1" || r.signer != bob.id.ID() {
		t.Fatalf("receipt: %+v", r)
	}
	// ... and it is delivered only once.
	before := len(alice.gotReceipts())
	alice.restart()
	alice.connect(carol)
	never(t, "the receipt being delivered again", 300*time.Millisecond, func() bool { return len(alice.gotReceipts()) > before })
}

func TestRelayHoldsOnlyCiphertext(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)
	const secret = "the-launch-code-is-0451"
	if _, err := send(alice, bob.id.ID(), "m1", secret); err != nil {
		t.Fatal(err)
	}
	envs, _ := carol.db.EnvelopesFor(bg, bob.id.ID(), time.Now(), 10)
	if len(envs) != 1 || envs[0].Submitter != alice.id.ID() {
		t.Fatalf("envelopes: %+v", envs)
	}
	if containsBytes(envs[0].Blob, secret) {
		t.Fatal("the relay stores readable plaintext")
	}
	// Carol, a legitimate peer with her own keys, cannot open it.
	if _, _, err := carol.svc.Open(bg, envs[0].Blob); err == nil {
		t.Fatal("the relay could decrypt a message that is not for it")
	}
}

func containsBytes(b []byte, s string) bool { return len(s) > 0 && stringsContains(string(b), s) }
func stringsContains(a, b string) bool {
	for i := 0; i+len(b) <= len(a); i++ {
		if a[i:i+len(b)] == b {
			return true
		}
	}
	return false
}

func TestRecipientConnectedToTheRelayReceivesImmediately(t *testing.T) {
	// Alice and Bob cannot reach each other directly, but both are connected to
	// Carol: the relay forwards at once, acting as a router.
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	alice.net.Disconnect(bob.id.ID())
	bob.connect(carol)
	alice.connect(carol)

	if _, err := send(alice, bob.id.ID(), "m1", "via carol"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "immediate forwarding", func() bool { return len(bob.got()) == 1 })
	eventually(t, "the receipt to come back", func() bool { alice.mgr.FetchReceipts(bg); return len(alice.gotReceipts()) == 1 })
}

func TestSeveralRelaysDeliverOnceAndAllClearTheirCopy(t *testing.T) {
	alice, bob := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn)
	c1, c2 := newNode(t, "c1", relayOn), newNode(t, "c2", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(c1)
	alice.connect(c2)

	n, err := send(alice, bob.id.ID(), "m1", "twice relayed")
	if err != nil || n != 2 {
		t.Fatalf("dispatch: %d %v", n, err)
	}
	bob.start()
	bob.connect(c1)
	bob.connect(c2)
	eventually(t, "delivery", func() bool { return len(bob.got()) >= 1 })
	eventually(t, "both relays to clear their copy", func() bool { return held(c1) == 0 && held(c2) == 0 })
	time.Sleep(200 * time.Millisecond)
	if n := len(bob.got()); n != 1 {
		t.Fatalf("the message was delivered %d times", n)
	}
}

func TestBundleGossipLetsAStrangerEncryptViaAMutualPeer(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	carol.connect(bob) // Carol knows Bob's bundle; Alice has never met Bob
	bob.stop()
	alice.connect(carol)
	if alice.svc.HasBundle(bg, bob.id.ID()) {
		t.Fatal("setup: Alice must not know Bob yet")
	}

	if n, err := send(alice, bob.id.ID(), "m1", "hello stranger"); err != nil || n != 1 {
		t.Fatalf("dispatch: %d %v", n, err)
	}
	bob.start()
	bob.connect(carol)
	eventually(t, "delivery", func() bool { return len(bob.got()) == 1 })
	if bob.got()[0].from != alice.id.ID() {
		t.Fatal("wrong sender")
	}
}

func TestDispatchFailureModes(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", Options{Enabled: false, StoreTimeout: 2 * time.Second})

	// Never met Bob and nobody to ask.
	if _, err := send(alice, bob.id.ID(), "m", "x"); err == nil {
		t.Fatal("dispatched without a bundle and without peers")
	}
	alice.connect(bob)
	bob.stop()
	// Knows Bob's bundle, but is connected to nobody.
	if _, err := send(alice, bob.id.ID(), "m", "x"); !errors.Is(err, ErrNoPeers) {
		t.Fatalf("no peers: %v", err)
	}
	// The only connected peer refuses to relay.
	alice.connect(carol)
	if _, err := send(alice, bob.id.ID(), "m", "x"); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("relay disabled: %v", err)
	}
	if held(carol) != 0 {
		t.Fatal("a peer with relaying switched off stored a message")
	}
	if _, err := send(alice, "not-an-id", "m", "x"); err == nil {
		t.Fatal("bad recipient accepted")
	}
	if _, err := send(alice, alice.id.ID(), "m", "x"); err == nil {
		t.Fatal("dispatch to ourselves accepted")
	}
}

// ---- Abuse ----------------------------------------------------------------------

func TestRelayEnforcesQuotasPerSender(t *testing.T) {
	tight := relayOn
	tight.Limits = &storage.RelayLimits{MaxTotalBytes: 1 << 20, MaxPerSender: 3, MaxBytesPerSender: 1 << 20, MaxPerRecipient: 100, MaxReceipts: 10}
	alice, mallory, bob, carol := newNode(t, "alice", relayOn), newNode(t, "mallory", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", tight)
	alice.connect(bob)
	mallory.connect(bob)
	bob.stop()
	mallory.connect(carol)
	alice.connect(carol)

	accepted := 0
	for i := range 6 {
		if n, err := send(mallory, bob.id.ID(), fmt.Sprintf("s%d", i), "spam"); err == nil && n > 0 {
			accepted++
		}
	}
	if accepted != 3 {
		t.Fatalf("the relay accepted %d of Mallory's 6 messages; the per-sender limit is 3", accepted)
	}
	// Mallory's spam does not stop Alice using the same relay.
	if n, err := send(alice, bob.id.ID(), "a1", "legit"); err != nil || n != 1 {
		t.Fatalf("an unrelated sender was blocked: %d %v", n, err)
	}
	if held(carol) != 4 {
		t.Fatalf("carol holds %d", held(carol))
	}
}

func TestOnlyTheRecipientCanAcknowledgeAnEnvelope(t *testing.T) {
	alice, bob, carol, dave := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn), newNode(t, "dave", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)
	if _, err := send(alice, bob.id.ID(), "m1", "for Bob"); err != nil {
		t.Fatal(err)
	}
	envs, _ := carol.db.EnvelopesFor(bg, bob.id.ID(), time.Now(), 5)

	// Dave (connected to the relay) tries to delete Bob's envelope and plant a receipt.
	dave.connect(carol)
	forged := protocol.RelayAck{ID: envs[0].ID, Delivered: true, MsgID: "m1", Tag: "tag1", EdPub: dave.id.PublicKey(), Sig: offline.SignReceipt(dave.id, "m1", alice.id.ID())}
	if err := dave.net.SendJSON(bg, carol.id.ID(), protocol.KindRelayAck, forged); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if held(carol) != 1 {
		t.Fatal("someone other than the recipient deleted the envelope")
	}
	if r, _ := carol.db.ReceiptsForTags(bg, []string{"tag1"}, time.Now(), 5); len(r) != 0 {
		t.Fatal("a receipt from a non-recipient was stored")
	}
}

func TestARelayCannotForgeADeliveryReceipt(t *testing.T) {
	alice, bob, mallory, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "mallory", relayOn), newNode(t, "carol", relayOn)
	alice.connect(carol)
	// Alice queued a message to Bob under a tag only she and Bob know.
	const tag = "tag-for-m1"
	_ = alice.db.AddOutbox(bg, storage.OutboxEntry{MsgID: "m1", RelayID: carol.id.ID(), To: bob.id.ID(), Tag: tag, Created: time.Now()})

	put := func(r storage.RelayReceipt) {
		r.Tag, r.Expires = tag, time.Now().Add(time.Hour)
		if err := carol.db.PutReceipt(bg, r, storage.RelayLimits{}); err != nil {
			t.Fatal(err)
		}
	}
	// A made-up signature "from Bob".
	put(storage.RelayReceipt{MsgID: "m1", Signer: bob.id.ID(), EdPub: bob.id.PublicKey(), Sig: make([]byte, 64)})
	// Bob's genuine signature, but made for a different sender (replayed from another conversation).
	put(storage.RelayReceipt{MsgID: "m1", Signer: bob.id.ID(), EdPub: bob.id.PublicKey(), Sig: offline.SignReceipt(bob.id, "m1", mallory.id.ID())})
	// Mallory's own genuine receipt, claiming to be Bob's.
	put(storage.RelayReceipt{MsgID: "m1", Signer: bob.id.ID(), EdPub: mallory.id.PublicKey(), Sig: offline.SignReceipt(mallory.id, "m1", alice.id.ID())})
	// Mallory's genuine receipt under her own name: valid, but she is not who Alice wrote to.
	put(storage.RelayReceipt{MsgID: "m1", Signer: mallory.id.ID(), EdPub: mallory.id.PublicKey(), Sig: offline.SignReceipt(mallory.id, "m1", alice.id.ID())})
	// Bob's genuine receipt for another message of Alice's.
	put(storage.RelayReceipt{MsgID: "other", Signer: bob.id.ID(), EdPub: bob.id.PublicKey(), Sig: offline.SignReceipt(bob.id, "other", alice.id.ID())})

	alice.mgr.FetchReceipts(bg)
	if got := alice.gotReceipts(); len(got) != 0 {
		t.Fatalf("a forged or misattributed receipt reached the application: %+v", got)
	}
	if o, _ := alice.db.Outbox(bg, time.Time{}); len(o) != 1 {
		t.Fatal("the outbox entry was cleared by a bad receipt")
	}

	// Bob's genuine receipt for a message she did queue is accepted, once.
	_ = alice.db.AddOutbox(bg, storage.OutboxEntry{MsgID: "m2", RelayID: carol.id.ID(), To: bob.id.ID(), Tag: tag, Created: time.Now()})
	put(storage.RelayReceipt{MsgID: "m2", Signer: bob.id.ID(), EdPub: bob.id.PublicKey(), Sig: offline.SignReceipt(bob.id, "m2", alice.id.ID())})
	alice.mgr.FetchReceipts(bg)
	if got := alice.gotReceipts(); len(got) != 1 || got[0].signer != bob.id.ID() || got[0].msgID != "m2" {
		t.Fatalf("receipts: %+v", got)
	}
	alice.mgr.FetchReceipts(bg)
	if len(alice.gotReceipts()) != 1 {
		t.Fatal("a receipt was applied twice")
	}
}

func TestMalformedRelayTrafficIsIgnored(t *testing.T) {
	alice, carol := newNode(t, "alice", relayOn), newNode(t, "carol", relayOn)
	alice.connect(carol)
	bobID := "0123456789abcdef0123456789abcdef"

	bad := []request{
		{ID: "../x", To: bobID, Blob: []byte("x")},
		{ID: "ok1", To: "nope", Blob: []byte("x")},
		{ID: "ok2", To: alice.id.ID(), Blob: []byte("x")}, // to the sender
		{ID: "ok3", To: carol.id.ID(), Blob: []byte("x")}, // to the relay itself
		{ID: "ok4", To: bobID, Blob: nil},
		{ID: "ok5", To: bobID, Blob: make([]byte, offline.MaxSealed+1)},
	}
	for _, r := range bad {
		r.Op = "store"
		if resp, _, err := alice.mgr.call(bg, carol.id.ID(), "", r); err == nil && resp.OK {
			t.Errorf("accepted %q", r.ID)
		}
	}
	// Frames that are not even requests.
	_ = alice.net.SendJSON(bg, carol.id.ID(), protocol.KindRelayRequest, protocol.RelayRequest{ID: "g1", Sealed: []byte("garbage")})
	_ = alice.net.SendJSON(bg, carol.id.ID(), protocol.KindRelayRequest, protocol.RelayRequest{ID: "../bad", Sealed: []byte("x")})
	_ = alice.net.SendJSON(bg, carol.id.ID(), protocol.KindRelayDeliver, protocol.RelayDeliver{ID: "d1", Blob: []byte("x")}) // not a relay's job
	time.Sleep(400 * time.Millisecond)
	if held(carol) != 0 {
		t.Fatalf("carol stored %d malformed messages", held(carol))
	}

	// A delivery that is not decryptable is acknowledged as undeliverable, so
	// the relay does not keep it forever.
	bob := newNode(t, "bob", relayOn)
	carol.connect(bob)
	junk := storage.RelayEnvelope{ID: "junk1", Submitter: alice.id.ID(), To: bob.id.ID(), Blob: []byte(`{"v":1}`), Created: time.Now(), Expires: time.Now().Add(time.Hour)}
	_ = carol.db.PutEnvelope(bg, junk, storage.RelayLimits{})
	carol.mgr.deliverHeld(bg, bob.id.ID())
	eventually(t, "the relay to drop an undecryptable envelope", func() bool { return held(carol) == 0 })
	if len(bob.got()) != 0 {
		t.Fatal("junk reached the application")
	}
}

func TestExpiredEnvelopesAreNotDeliveredAndArePurged(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)
	if _, err := send(alice, bob.id.ID(), "m1", "too late"); err != nil {
		t.Fatal(err)
	}
	carol.mgr.now = func() time.Time { return time.Now().Add(MaxTTL + time.Hour) }
	if envs, _ := carol.db.EnvelopesFor(bg, bob.id.ID(), carol.mgr.now(), 5); len(envs) != 0 {
		t.Fatal("an expired envelope is still offered for delivery")
	}
	if err := carol.mgr.Maintain(bg); err != nil {
		t.Fatal(err)
	}
	if held(carol) != 0 {
		t.Fatal("expired envelope not purged")
	}
}

func TestUsageReporting(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)
	_, _ = send(alice, bob.id.ID(), "m1", "x")
	n, bytes, capacity, err := carol.mgr.Usage(bg)
	if err != nil || n != 1 || bytes == 0 || capacity != DefaultMaxStorage {
		t.Fatalf("usage: %d %d %d %v", n, bytes, capacity, err)
	}
	if !carol.mgr.Enabled() {
		t.Fatal("Enabled() wrong")
	}
}
