package ratchet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
)

type signer struct{ priv ed25519.PrivateKey }

func (s signer) Sign(m []byte) []byte { return ed25519.Sign(s.priv, m) }

type party struct {
	id   string
	pub  ed25519.PublicKey
	sign signer
}

func newParty(id string) party {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return party{id: id, pub: pub, sign: signer{priv}}
}

// sessions establishes a pair; "a..." sorts before "b...", so A is the lower ID.
func sessions(t *testing.T) (a, b *Session, pa, pb party) {
	t.Helper()
	pa, pb = newParty("aaaa"), newParty("bbbb")
	binding := make([]byte, 32)
	_, _ = rand.Read(binding)

	ha, ia, err := Start(pa.id, pb.id, pa.sign, binding)
	if err != nil {
		t.Fatal(err)
	}
	hb, ib, err := Start(pb.id, pa.id, pb.sign, binding)
	if err != nil {
		t.Fatal(err)
	}
	if a, err = ha.Finish(ib, pb.pub); err != nil {
		t.Fatal(err)
	}
	if b, err = hb.Finish(ia, pa.pub); err != nil {
		t.Fatal(err)
	}
	return
}

func mustSeal(t *testing.T, s *Session, msg string) []byte {
	t.Helper()
	ct, err := s.Seal([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func mustOpen(t *testing.T, s *Session, ct []byte, want string) {
	t.Helper()
	got, err := s.Open(ct)
	if err != nil || string(got) != want {
		t.Fatalf("Open = %q, %v; want %q", got, err, want)
	}
}

func TestRoundTripInBothDirectionsAndPatterns(t *testing.T) {
	a, b, _, _ := sessions(t)

	// B speaks first (before receiving anything), then bursts, then ping-pong.
	mustOpen(t, a, mustSeal(t, b, "b first"), "b first")
	for i := range 5 {
		mustOpen(t, b, mustSeal(t, a, fmt.Sprintf("a burst %d", i)), fmt.Sprintf("a burst %d", i))
	}
	for i := range 20 {
		mustOpen(t, a, mustSeal(t, b, fmt.Sprintf("b %d", i)), fmt.Sprintf("b %d", i))
		mustOpen(t, b, mustSeal(t, a, fmt.Sprintf("a %d", i)), fmt.Sprintf("a %d", i))
	}
	mustOpen(t, b, mustSeal(t, a, ""), "") // empty messages are fine
}

func TestEveryMessageHasItsOwnKeyAndOverheadIsConstant(t *testing.T) {
	a, b, _, _ := sessions(t)
	c1, c2 := mustSeal(t, a, "same text"), mustSeal(t, a, "same text")
	if bytes.Equal(c1[headerLen:], c2[headerLen:]) {
		t.Fatal("identical plaintexts produced identical ciphertexts: keys are being reused")
	}
	if len(c1) != len("same text")+Overhead {
		t.Fatalf("overhead %d, constant says %d", len(c1)-len("same text"), Overhead)
	}
	mustOpen(t, b, c1, "same text")
	mustOpen(t, b, c2, "same text")

	big := bytes.Repeat([]byte("x"), 70_000)
	ct, _ := a.Seal(big)
	got, err := b.Open(ct)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("large message: %v", err)
	}
}

func TestDHKeyChangesEachTurn(t *testing.T) {
	a, b, _, _ := sessions(t)
	dh := func(ct []byte) string { return string(ct[1 : 1+pubLen]) }

	m1 := mustSeal(t, a, "1")
	mustOpen(t, b, m1, "1")
	r1 := mustSeal(t, b, "r1")
	mustOpen(t, a, r1, "r1")
	m2 := mustSeal(t, a, "2")
	mustOpen(t, b, m2, "2")
	r2 := mustSeal(t, b, "r2")
	mustOpen(t, a, r2, "r2")
	m3 := mustSeal(t, a, "3")

	if dh(m1) == dh(m2) || dh(m2) == dh(m3) || dh(r1) == dh(r2) {
		t.Fatal("DH keys were not renewed on each turn")
	}
	// Within one turn the DH key stays and only the chain advances.
	m3b := mustSeal(t, a, "3b")
	if dh(m3) != dh(m3b) {
		t.Fatal("DH key changed without a reply")
	}
}

func TestReplayLossAndReorderingAreRejected(t *testing.T) {
	a, b, _, _ := sessions(t)
	m1, m2, m3 := mustSeal(t, a, "1"), mustSeal(t, a, "2"), mustSeal(t, a, "3")

	mustOpen(t, b, m1, "1")
	if _, err := b.Open(m1); !errors.Is(err, ErrOrder) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := b.Open(m3); !errors.Is(err, ErrOrder) {
		t.Fatalf("skipped message: %v", err)
	}
	// A rejected message must not damage the session.
	mustOpen(t, b, m2, "2")
	mustOpen(t, b, m3, "3")
}

func TestTamperingIsDetectedAndLeavesStateIntact(t *testing.T) {
	a, b, _, _ := sessions(t)
	good := mustSeal(t, a, "authentic")

	flip := func(i int) []byte { c := bytes.Clone(good); c[i] ^= 0x01; return c }
	cases := map[string][]byte{
		"version":          flip(0),
		"dh public key":    flip(5),
		"message number":   flip(1 + pubLen + 3),
		"ciphertext":       flip(headerLen + 2),
		"tag":              flip(len(good) - 1),
		"truncated":        good[:len(good)-1],
		"header only":      good[:headerLen],
		"too short":        good[:10],
		"empty":            nil,
		"appended garbage": append(bytes.Clone(good), 0),
	}
	for name, msg := range cases {
		if _, err := b.Open(msg); err == nil {
			t.Errorf("%s: tampered message accepted", name)
		}
	}
	// None of that advanced or corrupted the state.
	mustOpen(t, b, good, "authentic")
}

func TestForgedDHKeyDoesNotCorruptTheSession(t *testing.T) {
	a, b, _, _ := sessions(t)
	mustOpen(t, b, mustSeal(t, a, "hello"), "hello")
	reply := mustSeal(t, b, "reply")

	forged := mustSeal(t, a, "next")
	_, rnd, _ := ed25519.GenerateKey(rand.Reader)
	copy(forged[1:1+pubLen], rnd[:pubLen]) // a different (valid-looking) DH key
	if _, err := b.Open(forged); err == nil {
		t.Fatal("forged DH key accepted")
	}
	zero := bytes.Clone(forged)
	copy(zero[1:1+pubLen], make([]byte, pubLen)) // low-order point
	if _, err := b.Open(zero); err == nil {
		t.Fatal("low-order DH key accepted")
	}
	mustOpen(t, a, reply, "reply") // the session still works
}

func TestHandshakeRejectsImpostorsAndRelays(t *testing.T) {
	pa, pb, eve := newParty("aaaa"), newParty("bbbb"), newParty("eeee")
	binding := bytes.Repeat([]byte{7}, 32)
	other := bytes.Repeat([]byte{8}, 32)

	ha, _, _ := Start(pa.id, pb.id, pa.sign, binding)
	_, good, _ := Start(pb.id, pa.id, pb.sign, binding)

	// Signed by someone else.
	_, forged, _ := Start(pb.id, pa.id, eve.sign, binding)
	if _, err := ha.Finish(forged, pb.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("impostor: %v", err)
	}
	// Valid handshake from a different TLS session (relay).
	_, relayed, _ := Start(pb.id, pa.id, pb.sign, other)
	if _, err := ha.Finish(relayed, pb.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("relay: %v", err)
	}
	// Valid handshake addressed to someone else.
	_, misaddressed, _ := Start(pb.id, "cccc", pb.sign, binding)
	if _, err := ha.Finish(misaddressed, pb.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("misaddressed: %v", err)
	}
	// Right message, wrong expected key.
	if _, err := ha.Finish(good, eve.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("wrong key: %v", err)
	}
	// Garbage and degenerate keys.
	for name, msg := range map[string][]byte{"garbage": []byte("nope"), "short key": []byte(`{"pub":"AAAA","sig":"AAAA"}`)} {
		if _, err := ha.Finish(msg, pb.pub); !errors.Is(err, ErrBadInit) {
			t.Errorf("%s: %v", name, err)
		}
	}
	zeroPub := make([]byte, pubLen)
	sig := pb.sign.Sign(transcript(binding, pb.id, pa.id, zeroPub))
	lowOrder, _ := json.Marshal(InitMessage{Pub: zeroPub, Sig: sig})
	if _, err := ha.Finish(lowOrder, pb.pub); !errors.Is(err, ErrBadInit) {
		t.Fatalf("validly signed low-order key: %v", err)
	}
	if _, err := ha.Finish(good, pb.pub); err != nil {
		t.Fatalf("the genuine handshake was refused: %v", err)
	}
}

func TestSessionsFromDifferentConnectionsAreIndependent(t *testing.T) {
	a1, _, _, _ := sessions(t)
	_, b2, _, _ := sessions(t)
	ct := mustSeal(t, a1, "for connection 1")
	if _, err := b2.Open(ct); err == nil {
		t.Fatal("a message decrypted under a different session")
	}
}

// ---- Security properties ---------------------------------------------------

// clone copies the secret state, as an attacker dumping process memory would.
func (s *Session) clone() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Session{
		rk: bytes.Clone(s.rk), dhs: s.dhs, dhr: s.dhr,
		cks: bytes.Clone(s.cks), ckr: bytes.Clone(s.ckr),
		ns: s.ns, nr: s.nr, pending: s.pending,
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}

// Forward secrecy: the key material that protected earlier messages is
// destroyed as soon as it has been used, so a later compromise of the state
// cannot decrypt them.
func TestUsedKeyMaterialIsErased(t *testing.T) {
	a, b, _, _ := sessions(t)

	// Sending side: the chain key that produced a message key is wiped.
	oldCKS := a.cks
	ct := mustSeal(t, a, "secret one")
	if !allZero(oldCKS) {
		t.Fatal("sending chain key survived the message it protected")
	}

	// Receiving side, including across a DH ratchet step.
	oldCKR, oldRK := b.ckr, b.rk
	mustOpen(t, b, ct, "secret one")
	if !allZero(oldCKR) {
		t.Fatal("receiving chain key survived")
	}
	if !allZero(oldRK) {
		t.Fatal("old root key survived a DH ratchet step")
	}

	// A state captured after the fact holds nothing that opens the old message
	// (it is past that message number and its chains have moved on).
	late := b.clone()
	if _, err := late.Open(ct); err == nil {
		t.Fatal("captured later state could decrypt an earlier message")
	}
}

// Post-compromise security: an attacker who copies the full state at one
// moment reads what follows only until the parties have exchanged new DH
// keys; after a round trip the session is closed to them again.
func TestSessionHealsAfterStateCompromise(t *testing.T) {
	a, b, _, _ := sessions(t)
	mustOpen(t, b, mustSeal(t, a, "warm-up"), "warm-up")
	mustOpen(t, a, mustSeal(t, b, "warm-up reply"), "warm-up reply")

	attacker := b.clone() // memory dump of Bob at this instant

	// Right after the dump the attacker can follow along.
	m1 := mustSeal(t, a, "m1 (same chain, still readable)")
	mustOpen(t, attacker, m1, "m1 (same chain, still readable)")
	mustOpen(t, b, m1, "m1 (same chain, still readable)")

	// Bob replies with a fresh DH key the attacker never saw; Alice answers
	// using it.
	r1 := mustSeal(t, b, "r1")
	mustOpen(t, a, r1, "r1")
	m2 := mustSeal(t, a, "m2 - after healing")
	mustOpen(t, b, m2, "m2 - after healing")

	if _, err := attacker.Open(m2); err == nil {
		t.Fatal("attacker holding the old state could read a message after the DH ratchet")
	}
	// And every later message stays closed to them.
	for range 3 {
		mustOpen(t, a, mustSeal(t, b, "more"), "more")
		next := mustSeal(t, a, "later")
		mustOpen(t, b, next, "later")
		if _, err := attacker.Open(next); err == nil {
			t.Fatal("attacker regained access")
		}
	}
}

func TestConcurrentSealAndOpen(t *testing.T) {
	a, b, _, _ := sessions(t)
	const n = 400

	aToB, bToA := make(chan []byte, 16), make(chan []byte, 16)
	var wg sync.WaitGroup
	errs := make(chan error, 8)

	sender := func(s *Session, out chan<- []byte, tag string) {
		defer wg.Done()
		defer close(out)
		for i := range n {
			ct, err := s.Seal([]byte(fmt.Sprintf("%s-%d", tag, i)))
			if err != nil {
				errs <- err
				return
			}
			out <- ct
		}
	}
	receiver := func(s *Session, in <-chan []byte, tag string) {
		defer wg.Done()
		for i := 0; ; i++ {
			ct, ok := <-in
			if !ok {
				return
			}
			got, err := s.Open(ct)
			if err != nil || string(got) != fmt.Sprintf("%s-%d", tag, i) {
				errs <- fmt.Errorf("%s message %d: %q %v", tag, i, got, err)
				return
			}
		}
	}
	wg.Add(4)
	go sender(a, aToB, "a")
	go sender(b, bToA, "b")
	go receiver(b, aToB, "a")
	go receiver(a, bToA, "b")
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestCounterExhaustion(t *testing.T) {
	a, _, _, _ := sessions(t)
	a.ns = math.MaxUint32
	if _, err := a.Seal([]byte("x")); !errors.Is(err, ErrExhausted) {
		t.Fatalf("got %v", err)
	}
}
