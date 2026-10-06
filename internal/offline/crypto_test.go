package offline

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samaasi/lazy-chat/internal/identity"
)

// memKeys is a minimal Keys implementation that also records consumption.
type memKeys struct {
	spk  map[uint32]*ecdh.PrivateKey
	opk  map[uint32]*ecdh.PrivateKey
	for_ map[uint32]string
}

func (m *memKeys) SPK(id uint32) (*ecdh.PrivateKey, bool) { k, ok := m.spk[id]; return k, ok }
func (m *memKeys) OPK(id uint32, by string) (*ecdh.PrivateKey, bool) {
	k, ok := m.opk[id]
	return k, ok && m.for_[id] == by
}

// recipient builds an identity, its keys and a published bundle that reserves
// one-time prekeys 1..n for `reservedFor`.
func recipient(t *testing.T, reservedFor string, n int) (*identity.Identity, *memKeys, *Bundle) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keys := &memKeys{spk: map[uint32]*ecdh.PrivateKey{}, opk: map[uint32]*ecdh.PrivateKey{}, for_: map[uint32]string{}}
	spk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	keys.spk[7] = spk
	b := NewBundle(id, SignPrekey(id, 7, spk.PublicKey().Bytes(), 1_700_000_000))
	for i := 1; i <= n; i++ {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		keys.opk[uint32(i)], keys.for_[uint32(i)] = k, reservedFor
		b.OPKs = append(b.OPKs, OneTimePrekey{ID: uint32(i), Pub: k.PublicKey().Bytes()})
	}
	return id, keys, b
}

func mustSender(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSealOpenRoundTripWithAndWithoutOneTimePrekey(t *testing.T) {
	alice := mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 3)
	if id, err := bundle.Verify(); err != nil || id != bob.ID() {
		t.Fatalf("bundle verify: %q %v", id, err)
	}

	for name, opk := range map[string]*OneTimePrekey{"with one-time prekey": &bundle.OPKs[0], "without": nil} {
		blob, err := Seal(alice, bob.ID(), bundle, opk, []byte("hello while you were away"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, from, used, err := Open(bob, keys, blob)
		if err != nil || string(got) != "hello while you were away" || from != alice.ID() {
			t.Fatalf("%s: got %q from %s err=%v", name, got, from, err)
		}
		if (opk == nil) != (used == 0) {
			t.Fatalf("%s: reported one-time prekey %d", name, used)
		}
	}
}

func TestCiphertextHidesTheMessageAndIsFreshEachTime(t *testing.T) {
	alice := mustSender(t)
	bob, _, bundle := recipient(t, alice.ID(), 0)
	a, _ := Seal(alice, bob.ID(), bundle, nil, []byte("the launch code is 0451"))
	b, _ := Seal(alice, bob.ID(), bundle, nil, []byte("the launch code is 0451"))
	if bytes.Contains(a, []byte("launch")) || bytes.Equal(a, b) {
		t.Fatal("ciphertext leaks the text or repeats")
	}
}

// A relay (or anyone else) holding the blob cannot read it, even with every
// public key and even if it is itself a legitimate peer.
func TestOnlyTheRecipientCanOpen(t *testing.T) {
	alice := mustSender(t)
	bob, _, bundle := recipient(t, alice.ID(), 1)
	relay, relayKeys, _ := recipient(t, alice.ID(), 1) // has its own prekeys, with the same IDs
	blob, _ := Seal(alice, bob.ID(), bundle, &bundle.OPKs[0], []byte("for Bob only"))
	if _, _, _, err := Open(relay, relayKeys, blob); err == nil {
		t.Fatal("a third party opened the message")
	}
	// Alice herself cannot reopen it either: the ephemeral key is gone.
	if _, _, _, err := Open(alice, relayKeys, blob); err == nil {
		t.Fatal("the sender could reopen her own ciphertext")
	}
}

func TestMessageIsBoundToItsRecipient(t *testing.T) {
	alice := mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 0)
	blob, _ := Seal(alice, "someone-else", bundle, nil, []byte("x"))
	if _, _, _, err := Open(bob, keys, blob); err == nil {
		t.Fatal("a message sealed for another recipient ID was accepted")
	}
}

func TestSenderCannotBeForged(t *testing.T) {
	alice, mallory := mustSender(t), mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 0)

	// Mallory claims to be Alice by putting Alice's public identity in the header.
	blob, _ := Seal(mallory, bob.ID(), bundle, nil, []byte("pay Mallory"))
	var h map[string]any
	_ = json.Unmarshal(blob, &h)
	aliceIK := alice.DHKey().PublicKey().Bytes()
	h["ed"], h["ik"], h["ik_sig"] = alice.PublicKey(), aliceIK, alice.Sign(signedIK(aliceIK)) // all public, all genuine
	forged, _ := json.Marshal(h)
	if _, _, _, err := Open(bob, keys, forged); err == nil {
		t.Fatal("a message was accepted as coming from Alice without her private key")
	}

	// And an unbound DH key (signature from the wrong identity) is rejected outright.
	_ = json.Unmarshal(blob, &h)
	h["ed"] = alice.PublicKey() // Mallory's ik_sig no longer verifies under Alice's key
	swapped, _ := json.Marshal(h)
	if _, _, _, err := Open(bob, keys, swapped); err == nil {
		t.Fatal("DH key not bound to the claimed identity was accepted")
	}
}

func TestTamperingAndMalformedBlobs(t *testing.T) {
	alice := mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 1)
	good, _ := Seal(alice, bob.ID(), bundle, &bundle.OPKs[0], []byte("authentic"))

	mutate := func(field string, v any) []byte {
		var h map[string]any
		_ = json.Unmarshal(good, &h)
		h[field] = v
		b, _ := json.Marshal(h)
		return b
	}
	cases := map[string][]byte{
		"not json":         []byte("garbage"),
		"empty":            nil,
		"wrong version":    mutate("v", 2),
		"short ed key":     mutate("ed", []byte{1, 2}),
		"short ephemeral":  mutate("ek", []byte{1, 2}),
		"other ciphertext": mutate("ct", []byte("not the ciphertext, but long enough to be plausible....")),
		"other spk id":     mutate("spk", 99),
		"other opk id":     mutate("opk", 2),
		"oversize":         bytes.Repeat([]byte("x"), MaxBlob+1),
	}
	for name, blob := range cases {
		if _, _, _, err := Open(bob, keys, blob); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Flipping any ciphertext bit fails authentication.
	var h blob
	_ = json.Unmarshal(good, &h)
	h.CT[0] ^= 1
	flipped, _ := json.Marshal(h)
	if _, _, _, err := Open(bob, keys, flipped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("bit flip: %v", err)
	}
	if _, _, _, err := Open(bob, keys, good); err != nil {
		t.Fatalf("the genuine message must still open: %v", err)
	}
}

func TestOneTimePrekeyRules(t *testing.T) {
	alice, carol := mustSender(t), mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 2) // prekeys reserved for Alice only
	blob, _ := Seal(alice, bob.ID(), bundle, &bundle.OPKs[0], []byte("x"))

	// Carol cannot use a prekey reserved for Alice: not even to learn it exists.
	// (Simulated by presenting Alice's blob under a header that names Carol.)
	if _, _, _, err := Open(bob, keys, mustSwapSender(t, blob, carol)); err == nil {
		t.Fatal("a one-time prekey reserved for one peer opened another peer's message")
	}

	// Once the caller consumes the prekey, a replay of the same blob fails.
	_, _, used, err := Open(bob, keys, blob)
	if err != nil || used != 1 {
		t.Fatalf("first open: used=%d err=%v", used, err)
	}
	delete(keys.opk, used)
	if _, _, _, err := Open(bob, keys, blob); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("replay after the prekey was destroyed: %v", err)
	}
}

func mustSwapSender(t *testing.T, raw []byte, as *identity.Identity) []byte {
	t.Helper()
	var h map[string]any
	_ = json.Unmarshal(raw, &h)
	ik := as.DHKey().PublicKey().Bytes()
	h["ed"], h["ik"], h["ik_sig"] = as.PublicKey(), ik, as.Sign(signedIK(ik))
	out, _ := json.Marshal(h)
	return out
}

// Forward secrecy for stored ciphertext: once the private prekeys are
// destroyed, nothing the recipient still holds can open the message.
func TestMessageIsUnreadableAfterPrekeysAreDestroyed(t *testing.T) {
	alice := mustSender(t)
	bob, keys, bundle := recipient(t, alice.ID(), 1)
	blob, _ := Seal(alice, bob.ID(), bundle, &bundle.OPKs[0], []byte("burn after reading"))

	// Bob's whole identity (including his long-term DH key) is later stolen,
	// but the prekeys were deleted along the way.
	keys.opk, keys.spk = map[uint32]*ecdh.PrivateKey{}, map[uint32]*ecdh.PrivateKey{}
	if _, _, _, err := Open(bob, keys, blob); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("got %v", err)
	}
}

func TestBundleVerification(t *testing.T) {
	bob, _, good := recipient(t, "x", 2)
	other := mustSender(t)

	clone := func() *Bundle { b := *good; b.OPKs = append([]OneTimePrekey(nil), good.OPKs...); return &b }
	bad := map[string]func(*Bundle){
		"ik not signed by the identity": func(b *Bundle) { b.IKDH = other.DHKey().PublicKey().Bytes() },
		"spk swapped":                   func(b *Bundle) { b.SPK.Pub = other.DHKey().PublicKey().Bytes() },
		"spk id changed":                func(b *Bundle) { b.SPK.ID++ },
		"spk date changed":              func(b *Bundle) { b.SPK.Created++ },
		"identity replaced":             func(b *Bundle) { b.EdPub = other.PublicKey() },
		"short key":                     func(b *Bundle) { b.IKDH = b.IKDH[:5] },
		"zero opk id":                   func(b *Bundle) { b.OPKs[0].ID = 0 },
		"short opk":                     func(b *Bundle) { b.OPKs[0].Pub = []byte{1} },
		"too many opks": func(b *Bundle) {
			for len(b.OPKs) <= MaxOPKs {
				b.OPKs = append(b.OPKs, OneTimePrekey{ID: uint32(len(b.OPKs) + 10), Pub: good.OPKs[0].Pub})
			}
		},
	}
	for name, mutate := range bad {
		b := clone()
		mutate(b)
		if _, err := b.Verify(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if id, err := clone().Verify(); err != nil || id != bob.ID() {
		t.Fatalf("good bundle: %q %v", id, err)
	}
}

func TestReceipts(t *testing.T) {
	alice, bob, mallory := mustSender(t), mustSender(t), mustSender(t)
	sig := SignReceipt(bob, "msg-1", alice.ID())

	if who, err := VerifyReceipt(bob.PublicKey(), sig, "msg-1", alice.ID()); err != nil || who != bob.ID() {
		t.Fatalf("valid receipt: %q %v", who, err)
	}
	for name, fn := range map[string]func() error{
		"other message":   func() error { _, e := VerifyReceipt(bob.PublicKey(), sig, "msg-2", alice.ID()); return e },
		"other sender":    func() error { _, e := VerifyReceipt(bob.PublicKey(), sig, "msg-1", mallory.ID()); return e },
		"forged by relay": func() error { _, e := VerifyReceipt(mallory.PublicKey(), sig, "msg-1", alice.ID()); return e },
		"signed by relay": func() error {
			_, e := VerifyReceipt(mallory.PublicKey(), SignReceipt(mallory, "msg-1", alice.ID()), "msg-1", bob.ID())
			return e
		},
		"short public key": func() error { _, e := VerifyReceipt([]byte{1}, sig, "msg-1", alice.ID()); return e },
	} {
		// "signed by relay" is a *valid* receipt, but from Mallory: the caller
		// must compare the returned signer with the message's recipient.
		if name == "signed by relay" {
			if who, err := VerifyReceipt(mallory.PublicKey(), SignReceipt(mallory, "msg-1", alice.ID()), "msg-1", alice.ID()); err != nil || who == bob.ID() {
				t.Fatalf("signer must be reported truthfully: %q %v", who, err)
			}
			continue
		}
		if fn() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOversizedPlaintextRefused(t *testing.T) {
	alice := mustSender(t)
	bob, _, bundle := recipient(t, alice.ID(), 0)
	if _, err := Seal(alice, bob.ID(), bundle, nil, make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}
