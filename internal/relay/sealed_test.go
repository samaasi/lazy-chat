package relay

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/storage"
)

// spy records the frames of one kind that a node receives, then lets the node
// handle them as usual.
type spy struct {
	mu     sync.Mutex
	froms  []string
	bodies [][]byte
}

func watch(n *node, kind protocol.Kind, handle func(string, []byte)) *spy {
	s := &spy{}
	n.net.Handle(kind, func(from string, body []byte) {
		s.mu.Lock()
		s.froms = append(s.froms, from)
		s.bodies = append(s.bodies, append([]byte(nil), body...))
		s.mu.Unlock()
		handle(from, body)
	})
	return s
}

func (s *spy) seen() (froms []string, bodies [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.froms...), append([][]byte(nil), s.bodies...)
}

// Alice queues a message for Bob, who is away, with Yan and Carol, who both
// relay. Neither may learn that it is from Alice, and she still gets Bob's receipt.
func TestRelaysNeverLearnWhoTheSenderIs(t *testing.T) {
	alice, bob := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn)
	yan, carol := newNode(t, "yan", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(yan)
	alice.connect(carol)
	yan.connect(carol)

	reqYan := watch(yan, protocol.KindRelayRequest, yan.mgr.onRequest)
	reqCarol := watch(carol, protocol.KindRelayRequest, carol.mgr.onRequest)
	fwdYan := watch(yan, protocol.KindRelayForward, yan.mgr.onForward)
	fwdCarol := watch(carol, protocol.KindRelayForward, carol.mgr.onForward)

	const secret = "meet at the old bridge"
	res, err := alice.mgr.Dispatch(bg, bob.id.ID(), "m1", plain("m1", secret))
	if err != nil || res.Relays != 2 {
		t.Fatalf("dispatch: %+v %v", res, err)
	}
	if res.Exposed != 0 {
		t.Fatalf("the sender was exposed to %d relays although forwarders were available", res.Exposed)
	}

	traces := map[string][]byte{
		"peer ID":               []byte(alice.id.ID()),
		"identity key":          alice.id.PublicKey(),
		"identity key (base64)": []byte(base64.StdEncoding.EncodeToString(alice.id.PublicKey())),
		"the plaintext":         []byte(secret),
		"the recipient":         []byte(bob.id.ID()), // not visible to a forwarder
	}
	for _, relay := range []*node{yan, carol} {
		envs, _ := relay.db.EnvelopesFor(bg, bob.id.ID(), time.Now(), 10)
		if len(envs) != 1 {
			t.Fatalf("%s holds %d envelopes", relay.name, len(envs))
		}
		e := envs[0]
		if e.Submitter == alice.id.ID() {
			t.Errorf("%s recorded Alice as the one who submitted the message", relay.name)
		}
		for what, needle := range traces {
			if what == "the recipient" {
				continue // a relay does know who a message is for
			}
			if bytes.Contains(e.Blob, needle) || bytes.Contains([]byte(e.Submitter+e.ID), needle) {
				t.Errorf("%s: the stored envelope contains %s", relay.name, what)
			}
		}
	}

	// On the wire, every relay was asked by the other relay, never by Alice.
	for name, s := range map[string]*spy{"yan": reqYan, "carol": reqCarol} {
		froms, _ := s.seen()
		if len(froms) == 0 {
			t.Errorf("%s was never asked", name)
		}
		for _, f := range froms {
			if f == alice.id.ID() {
				t.Errorf("%s received a request directly from Alice", name)
			}
		}
	}
	// A forwarder sees a sealed blob: neither the recipient, the text, nor the sender's key.
	for name, s := range map[string]*spy{"yan": fwdYan, "carol": fwdCarol} {
		froms, bodies := s.seen()
		if len(froms) == 0 {
			t.Errorf("%s was never asked to forward", name)
		}
		for _, b := range bodies {
			for what, needle := range traces {
				if bytes.Contains(b, needle) {
					t.Errorf("%s, forwarding: the request reveals %s", name, what)
				}
			}
		}
	}

	// Bob returns and gets the message once, from either relay.
	bob.start()
	bob.connect(yan)
	bob.connect(carol)
	eventually(t, "Bob to receive the message", func() bool { return len(bob.got()) >= 1 })
	time.Sleep(200 * time.Millisecond)
	if got := bob.got(); len(got) != 1 || got[0].from != alice.id.ID() || got[0].text != secret {
		t.Fatalf("bob got %+v", got)
	}
	eventually(t, "the relays to clear their copies", func() bool { return held(yan) == 0 && held(carol) == 0 })

	// The receipts are filed under a tag, not under Alice.
	o, _ := alice.db.Outbox(bg, time.Time{})
	if len(o) != 2 {
		t.Fatalf("outbox: %+v", o)
	}
	// (Bob opens the first copy; the duplicate at the other relay is dropped
	// without a receipt, so one relay is enough.)
	filed := 0
	eventually(t, "a relay to file the receipt", func() bool {
		filed = 0
		for _, relay := range []*node{yan, carol} {
			recs, _ := relay.db.ReceiptsForTags(bg, []string{o[0].Tag}, time.Now(), 10)
			for _, r := range recs {
				if r.Signer != bob.id.ID() || r.Tag == alice.id.ID() || bytes.Contains(r.Sig, []byte(alice.id.ID())) {
					t.Errorf("%s: unexpected receipt %+v", relay.name, r)
				}
				filed++
			}
		}
		return filed > 0
	})

	// Alice collects it, again through forwarders, and only once.
	eventually(t, "Alice's receipt", func() bool { alice.mgr.FetchReceipts(bg); return len(alice.gotReceipts()) >= 1 })
	if r := alice.gotReceipts(); len(r) != 1 || r[0].msgID != "m1" || r[0].signer != bob.id.ID() {
		t.Fatalf("receipts: %+v", r)
	}
	alice.mgr.FetchReceipts(bg)
	if len(alice.gotReceipts()) != 1 {
		t.Fatal("the receipt was applied twice")
	}
	for _, f := range func() []string { f, _ := reqCarol.seen(); return f }() {
		if f == alice.id.ID() {
			t.Fatal("Alice contacted a relay directly to collect the receipt")
		}
	}
}

func TestWithoutAForwarderTheSenderIsExposedAndToldSo(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)

	res, err := alice.mgr.Dispatch(bg, bob.id.ID(), "m1", plain("m1", "hi"))
	if err != nil || res.Relays != 1 || res.Exposed != 1 {
		t.Fatalf("with only one possible relay the sender is visible to it: %+v %v", res, err)
	}
	envs, _ := carol.db.EnvelopesFor(bg, bob.id.ID(), time.Now(), 10)
	if len(envs) != 1 || envs[0].Submitter != alice.id.ID() {
		t.Fatalf("envelopes: %+v", envs)
	}
}

func TestRequiredPolicyRefusesToExposeTheSender(t *testing.T) {
	strict := relayOn
	strict.RequireAnonymous = true
	alice, bob, carol := newNode(t, "alice", strict), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)

	if _, err := alice.mgr.Dispatch(bg, bob.id.ID(), "m1", plain("m1", "hi")); !errors.Is(err, ErrNoAnonymousPath) {
		t.Fatalf("got %v, want ErrNoAnonymousPath", err)
	}
	if held(carol) != 0 {
		t.Fatal("a message was stored although the policy forbids exposing the sender")
	}
	if o, _ := alice.db.Outbox(bg, time.Time{}); len(o) != 0 {
		t.Fatalf("the failed message was recorded as queued: %+v", o)
	}

	// With a forwarder available it goes through, anonymously.
	yan := newNode(t, "yan", relayOn)
	alice.connect(yan)
	yan.connect(carol)
	res, err := alice.mgr.Dispatch(bg, bob.id.ID(), "m2", plain("m2", "hi again"))
	if err != nil || res.Relays == 0 || res.Exposed != 0 {
		t.Fatalf("dispatch: %+v %v", res, err)
	}
}

func TestForwardingIsRefusedWhenRelayingIsOffAndIsRateLimited(t *testing.T) {
	off := Options{Enabled: false, StoreTimeout: time.Second}
	alice, carol, yan := newNode(t, "alice", relayOn), newNode(t, "carol", relayOn), newNode(t, "yan", off)
	alice.connect(carol)
	alice.connect(yan)
	yan.connect(carol)

	// Yan will not forward, so Alice falls back to Carol directly (and is told).
	bob := newNode(t, "bob", relayOn)
	alice.connect(bob)
	bob.stop()
	res, err := alice.mgr.Dispatch(bg, bob.id.ID(), "m1", plain("m1", "x"))
	if err != nil || res.Relays != 1 || res.Exposed != 1 {
		t.Fatalf("dispatch: %+v %v", res, err)
	}
	if held(yan) != 0 {
		t.Fatal("a peer with relaying off held a message")
	}

	// A flood of forward requests is cut off, and each is answered or ignored cheaply.
	for i := range 60 {
		_ = alice.net.SendJSON(bg, carol.id.ID(), protocol.KindRelayForward,
			protocol.RelayForward{ID: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Relay: yan.id.ID(), Sealed: []byte("x")})
	}
	time.Sleep(300 * time.Millisecond)
	carol.mgr.mu.Lock()
	pending := len(carol.mgr.forwards)
	carol.mgr.mu.Unlock()
	if pending > 30 {
		t.Fatalf("a single peer queued %d forwards", pending)
	}
}

// A forwarder that tampers with the answer, or drops it, cannot make the
// sender believe something false, and the sender moves on to another.
func TestAMaliciousForwarderCannotForgeOrBlock(t *testing.T) {
	quick := relayOn
	quick.StoreTimeout = 700 * time.Millisecond
	alice, bob := newNode(t, "alice", quick), newNode(t, "bob", relayOn)
	mallory, good, carol := newNode(t, "mallory", relayOn), newNode(t, "good", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	for _, n := range []*node{mallory, good, carol} {
		alice.connect(n)
		if n != carol {
			n.connect(carol)
		}
	}
	mallory.connect(good)

	// Mallory answers every forward request with a made-up "ok".
	mallory.net.Handle(protocol.KindRelayForward, func(from string, body []byte) {
		var f protocol.RelayForward
		if protocol.Unmarshal(body, &f) == nil {
			_ = mallory.net.SendJSON(bg, from, protocol.KindRelayForwardReply, protocol.RelayForwardReply{ID: f.ID, OK: true, Sealed: bytes.Repeat([]byte{7}, 90)})
		}
	})

	for i := range 3 {
		id := string(rune('a'+i)) + "msg"
		res, err := alice.mgr.Dispatch(bg, bob.id.ID(), id, plain(id, "hi"))
		if err != nil {
			continue // every relay she tried was reached through Mallory
		}
		// Whatever was recorded as queued really is held somewhere.
		if res.Relays == 0 {
			t.Fatal("success with no relay")
		}
	}
	// What Alice believes is queued must match what the relays hold.
	queued, _ := alice.db.Outbox(bg, time.Time{})
	holders := map[string]int{}
	for _, n := range []*node{mallory, good, carol} {
		for range func() []storage.RelayEnvelope { e, _ := n.db.EnvelopesFor(bg, bob.id.ID(), time.Now(), 50); return e }() {
			holders[n.id.ID()]++
		}
	}
	for _, q := range queued {
		if holders[q.RelayID] == 0 {
			t.Fatalf("Alice believes %s holds %s, but it does not", q.RelayID[:8], q.MsgID)
		}
	}
}

func TestRequestsAreIdempotentAndGarbageIsIgnored(t *testing.T) {
	alice, bob, carol := newNode(t, "alice", relayOn), newNode(t, "bob", relayOn), newNode(t, "carol", relayOn)
	alice.connect(bob)
	bob.stop()
	alice.connect(carol)

	// The same sealed request delivered twice (a replay) stores one envelope.
	req := request{Op: "store", ID: "env-1", To: bob.id.ID(), Blob: bytes.Repeat([]byte{9}, 200)}
	for range 2 {
		resp, _, err := alice.mgr.call(bg, carol.id.ID(), "", req)
		if err != nil || !resp.OK {
			t.Fatalf("store: %+v %v", resp, err)
		}
	}
	if held(carol) != 1 {
		t.Fatalf("a replayed request stored %d envelopes", held(carol))
	}

	// An unknown operation and an oversized tag list are handled safely.
	if resp, _, err := alice.mgr.call(bg, carol.id.ID(), "", request{Op: "wipe"}); err != nil || resp.OK {
		t.Fatalf("unknown op: %+v %v", resp, err)
	}
	many := request{Op: "fetch"}
	for range 500 {
		many.Tags = append(many.Tags, "tagtagtag")
	}
	if resp, _, err := alice.mgr.call(bg, carol.id.ID(), "", many); err != nil || !resp.OK {
		t.Fatalf("fetch: %+v %v", resp, err)
	}
}
