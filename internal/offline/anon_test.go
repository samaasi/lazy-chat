package offline

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestSealToKeyRoundTripAndBinding(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)

	box, err := SealToKey(priv.PublicKey().Bytes(), "relay-reply|abc", []byte("the reply"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenWithKey(priv, "relay-reply|abc", box); err != nil || string(got) != "the reply" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := OpenWithKey(other, "relay-reply|abc", box); err == nil {
		t.Fatal("opened with the wrong key")
	}
	if _, err := OpenWithKey(priv, "relay-reply|other", box); err == nil {
		t.Fatal("a box made for one purpose opened for another")
	}
	for name, mut := range map[string][]byte{
		"flipped ciphertext": append(bytes.Clone(box[:len(box)-1]), box[len(box)-1]^1),
		"flipped ephemeral":  append([]byte{box[0] ^ 1}, box[1:]...),
		"truncated":          box[:len(box)-3],
		"short":              box[:10],
		"empty":              nil,
	} {
		if _, err := OpenWithKey(priv, "relay-reply|abc", mut); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Nothing identifies the sender, and two boxes of the same text look unrelated.
	again, _ := SealToKey(priv.PublicKey().Bytes(), "relay-reply|abc", []byte("the reply"))
	if bytes.Equal(box[:32], again[:32]) || bytes.Equal(box, again) {
		t.Fatal("boxes are linkable: the ephemeral key repeated")
	}
	if _, err := SealToKey([]byte{1, 2, 3}, "x", nil); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}

func TestSealedMessageNamesNoSender(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)

	blob, err := alice.svc.Seal(ctx, bob.id.ID(), []byte("who sent this?"))
	if err != nil {
		t.Fatal(err)
	}

	// Everything that identifies Alice - in any encoding a relay might look for.
	for name, needle := range map[string][]byte{
		"peer ID":                             []byte(alice.id.ID()),
		"identity key":                        alice.id.PublicKey(),
		"identity key (base64)":               []byte(base64.StdEncoding.EncodeToString(alice.id.PublicKey())),
		"DH identity key":                     alice.id.DHKey().PublicKey().Bytes(),
		"DH identity (base64)":                []byte(base64.StdEncoding.EncodeToString(alice.id.DHKey().PublicKey().Bytes())),
		"the plaintext":                       []byte("who sent this"),
		"JSON field names (the inner format)": []byte(`"ik_sig"`),
	} {
		if bytes.Contains(blob, needle) {
			t.Errorf("the stored message reveals the sender: contains her %s", name)
		}
	}
	// A relay sees a fixed-size header, a one-off key and noise.
	if len(blob) < AnonOverhead {
		t.Fatal("too short")
	}

	// The recipient still learns who it is from, authenticated.
	plain, from, err := bob.svc.Open(ctx, blob)
	if err != nil || string(plain) != "who sent this?" || from != alice.id.ID() {
		t.Fatalf("recipient: %q %s %v", plain, from, err)
	}
}

func TestSealedSenderMessagesAreUnlinkable(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob := newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)
	a, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("one"))
	b, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("one"))
	// Only the 4-byte signed-prekey ID is shared; everything else differs, so
	// two messages from the same sender cannot be matched up.
	if !bytes.Equal(a[:4], b[:4]) {
		t.Fatal("setup: same recipient should name the same signed prekey")
	}
	same := 0
	for i := 4; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			same++
		}
	}
	if same > len(a)/8 {
		t.Fatalf("%d of %d bytes coincide: messages look linkable", same, len(a))
	}
}

func TestOuterLayerCannotBeSkippedOrForged(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, bob, mallory := newPeer(t, clk), newPeer(t, clk), newPeer(t, clk)
	introduce(t, bob, alice)
	introduce(t, bob, mallory)
	blob, _ := alice.svc.Seal(ctx, bob.id.ID(), []byte("hi"))

	// Tampering with the outer header (the signed-prekey ID) or body fails.
	hdr := bytes.Clone(blob)
	hdr[3] ^= 1
	body := bytes.Clone(blob)
	body[len(body)-1] ^= 1
	for name, m := range map[string][]byte{"header": hdr, "body": body, "truncated": blob[:len(blob)/2], "empty": nil} {
		if _, _, err := bob.svc.Open(ctx, m); err == nil {
			t.Errorf("%s: tampered message accepted", name)
		}
	}
	// A box meant for something else (a relay request to Bob) is not a message.
	req, err := mallory.svc.SealFor(ctx, bob.id.ID(), "relay-request", []byte(`{"op":"fetch"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bob.svc.Open(ctx, req); err == nil {
		t.Fatal("a relay request was accepted as a chat message")
	}
	if _, err := bob.svc.OpenFor(ctx, "relay-request", blob); err == nil {
		t.Fatal("a chat message was accepted as a relay request")
	}
	if _, _, err := bob.svc.Open(ctx, blob); err != nil {
		t.Fatalf("the genuine message must still open: %v", err)
	}
}

func TestSealForAndOpenFor(t *testing.T) {
	clk := &clock{t: time.Now()}
	alice, relay, bystander := newPeer(t, clk), newPeer(t, clk), newPeer(t, clk)
	introduce(t, relay, alice)
	introduce(t, relay, bystander) // the bystander also knows the relay's bundle

	box, err := alice.svc.SealFor(ctx, relay.id.ID(), "relay-request", []byte("store this"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, []byte(alice.id.ID())) || bytes.Contains(box, alice.id.PublicKey()) {
		t.Fatal("the request names its sender")
	}
	if got, err := relay.svc.OpenFor(ctx, "relay-request", box); err != nil || string(got) != "store this" {
		t.Fatalf("relay: %q %v", got, err)
	}
	if _, err := bystander.svc.OpenFor(ctx, "relay-request", box); err == nil {
		t.Fatal("someone other than the relay opened the request")
	}
	if _, err := relay.svc.OpenFor(ctx, "other-purpose", box); err == nil {
		t.Fatal("purpose binding not enforced")
	}
	if _, err := alice.svc.SealFor(ctx, "unknown-peer", "relay-request", []byte("x")); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("no bundle: %v", err)
	}
	if _, err := relay.svc.OpenFor(ctx, "relay-request", make([]byte, MaxSealed+1)); err == nil {
		t.Fatal("oversized box accepted")
	}

	// After the relay's signed prekey is gone, requests sealed to it are unreadable.
	clk.advance(SPKRotate + time.Hour)
	_, _ = relay.svc.OurBundleFor(ctx, "x") // rotate
	clk.advance(SPKRetain)
	if err := relay.svc.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.svc.OpenFor(ctx, "relay-request", box); !errors.Is(err, ErrNoPrekey) {
		t.Fatalf("after key deletion: %v", err)
	}
}
