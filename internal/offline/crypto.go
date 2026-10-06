// Package offline implements end-to-end encryption to a recipient who is not
// online, using signed prekeys in the style of Signal's X3DH.
//
// Each peer publishes a bundle: its long-term X25519 key, a signed prekey that
// is rotated weekly, and one-time prekeys. A sender who holds the bundle can
// encrypt a message to the owner at any time; only the owner's private keys can
// open it, so peers that merely store and forward the ciphertext (relays) learn
// nothing about its content.
//
// Authentication is the same as everywhere else in the project: a peer ID is
// the fingerprint of an Ed25519 key, the bundle's keys are signed by that key,
// and so a bundle is self-certifying. Whoever hands it to you (a relay, a
// gossiping peer) cannot substitute their own keys.
//
// Forward secrecy comes from deleting keys: a one-time prekey's private half is
// destroyed the first time it opens a message, and signed prekeys are replaced
// weekly and deleted after a grace period. Messages that did not use a one-time
// prekey are protected only until their signed prekey is deleted.
package offline

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/samaasi/lazy-chat/internal/identity"
)

const (
	labelIK      = "lazy-chat/offline/ik/v1"
	labelSPK     = "lazy-chat/offline/spk/v1"
	labelKDF     = "lazy-chat/offline/sk/v1"
	labelAAD     = "lazy-chat/offline/msg/v1"
	labelReceipt = "lazy-chat/offline/receipt/v1"

	blobVersion = 1

	// MaxPlaintext bounds one sealed message; MaxBlob bounds its ciphertext form.
	MaxPlaintext = 16 << 10
	MaxBlob      = 24 << 10
	// MaxOPKs bounds the one-time prekeys accepted in a single bundle.
	MaxOPKs = 64
)

// Errors returned by the package.
var (
	ErrBadBundle = errors.New("offline: invalid prekey bundle")
	ErrBadBlob   = errors.New("offline: malformed message")
	ErrNoPrekey  = errors.New("offline: the prekey this message used is no longer available")
	ErrDecrypt   = errors.New("offline: message failed authentication")
	ErrTooLarge  = errors.New("offline: message too large")
	ErrNoBundle  = errors.New("offline: no usable prekey bundle for that peer")
)

// SignedPrekey is a medium-term X25519 key signed by the owner's identity key.
type SignedPrekey struct {
	ID      uint32 `json:"id"`
	Pub     []byte `json:"pub"`
	Created int64  `json:"created"` // unix seconds
	Sig     []byte `json:"sig"`
}

// OneTimePrekey is an X25519 key that opens at most one message.
type OneTimePrekey struct {
	ID  uint32 `json:"id"`
	Pub []byte `json:"pub"`
}

// Bundle is everything a sender needs to encrypt to a peer.
type Bundle struct {
	EdPub []byte          `json:"ed"`     // Ed25519 identity key; peer ID is its fingerprint
	IKDH  []byte          `json:"ik"`     // long-term X25519 key
	IKSig []byte          `json:"ik_sig"` // Ed25519 signature binding IKDH to EdPub
	SPK   SignedPrekey    `json:"spk"`
	OPKs  []OneTimePrekey `json:"opks,omitempty"`
}

func signedIK(ik []byte) []byte { return append([]byte(labelIK+"\x00"), ik...) }

func signedSPK(id uint32, pub []byte, created int64) []byte {
	b := append([]byte(labelSPK+"\x00"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(b[len(b)-4:], id)
	b = append(b, pub...)
	b = binary.BigEndian.AppendUint64(b, uint64(created))
	return b
}

// SignPrekey signs a signed-prekey public key with the identity key.
func SignPrekey(id *identity.Identity, spkID uint32, pub []byte, created int64) SignedPrekey {
	return SignedPrekey{ID: spkID, Pub: pub, Created: created, Sig: id.Sign(signedSPK(spkID, pub, created))}
}

// NewBundle assembles our bundle around a signed prekey. One-time prekeys are
// added by the caller.
func NewBundle(id *identity.Identity, spk SignedPrekey) *Bundle {
	ik := id.DHKey().PublicKey().Bytes()
	return &Bundle{EdPub: id.PublicKey(), IKDH: ik, IKSig: id.Sign(signedIK(ik)), SPK: spk}
}

// Verify checks every key length and signature in the bundle and returns the
// peer ID the bundle belongs to. Callers must compare it with the ID they
// expected.
func (b *Bundle) Verify() (string, error) {
	if len(b.EdPub) != ed25519.PublicKeySize || len(b.IKDH) != 32 || len(b.SPK.Pub) != 32 || len(b.OPKs) > MaxOPKs {
		return "", ErrBadBundle
	}
	ed := ed25519.PublicKey(b.EdPub)
	if !identity.Verify(ed, signedIK(b.IKDH), b.IKSig) ||
		!identity.Verify(ed, signedSPK(b.SPK.ID, b.SPK.Pub, b.SPK.Created), b.SPK.Sig) {
		return "", ErrBadBundle
	}
	for _, pub := range [][]byte{b.IKDH, b.SPK.Pub} {
		if _, err := ecdh.X25519().NewPublicKey(pub); err != nil {
			return "", ErrBadBundle
		}
	}
	for _, o := range b.OPKs {
		if o.ID == 0 || len(o.Pub) != 32 {
			return "", ErrBadBundle
		}
		if _, err := ecdh.X25519().NewPublicKey(o.Pub); err != nil {
			return "", ErrBadBundle
		}
	}
	return identity.PeerIDFromPublicKey(ed), nil
}

// ---- Sealing -----------------------------------------------------------------

// blob is the serialised sealed message.
type blob struct {
	V     int    `json:"v"`
	Ed    []byte `json:"ed"`
	IK    []byte `json:"ik"`
	IKSig []byte `json:"ik_sig"`
	EK    []byte `json:"ek"`
	SPK   uint32 `json:"spk"`
	OPK   uint32 `json:"opk"` // 0: none used
	CT    []byte `json:"ct"`
}

func (b *blob) aad(recipientID string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%x|%x|%x|%d|%d", labelAAD, recipientID, b.Ed, b.IK, b.EK, b.SPK, b.OPK))
}

// messageCipher derives the AEAD and nonce from the concatenated DH outputs.
// The key is unique per message because the sender's ephemeral key is.
func messageCipher(dhs [][]byte, senderID, recipientID string) (cipher.AEAD, []byte, error) {
	ikm := make([]byte, 32) // domain separation, as in X3DH
	for i := range ikm {
		ikm[i] = 0xFF
	}
	for _, d := range dhs {
		ikm = append(ikm, d...)
	}
	okm, err := hkdf.Key(sha256.New, ikm, nil, labelKDF+"|"+senderID+"|"+recipientID, 32+12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(okm[:32])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, okm[32:], err
}

// Seal encrypts plaintext to the owner of rb. rb must already have been
// verified and matched to recipientID. opk may be nil when the bundle had no
// one-time prekeys left, which is allowed but weaker (see the package comment).
func Seal(sender *identity.Identity, recipientID string, rb *Bundle, opk *OneTimePrekey, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	x := ecdh.X25519()
	spk, err := x.NewPublicKey(rb.SPK.Pub)
	if err != nil {
		return nil, ErrBadBundle
	}
	ik, err := x.NewPublicKey(rb.IKDH)
	if err != nil {
		return nil, ErrBadBundle
	}
	eph, err := x.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ownIK := sender.DHKey()

	var dhs [][]byte
	for _, pair := range []struct {
		priv *ecdh.PrivateKey
		pub  *ecdh.PublicKey
	}{{ownIK, spk}, {eph, ik}, {eph, spk}} {
		d, err := pair.priv.ECDH(pair.pub)
		if err != nil {
			return nil, ErrBadBundle
		}
		dhs = append(dhs, d)
	}
	hdr := blob{V: blobVersion, Ed: sender.PublicKey(), IK: ownIK.PublicKey().Bytes(),
		IKSig: sender.Sign(signedIK(ownIK.PublicKey().Bytes())), EK: eph.PublicKey().Bytes(), SPK: rb.SPK.ID}
	if opk != nil {
		pub, err := x.NewPublicKey(opk.Pub)
		if err != nil {
			return nil, ErrBadBundle
		}
		d, err := eph.ECDH(pub)
		if err != nil {
			return nil, ErrBadBundle
		}
		dhs = append(dhs, d)
		hdr.OPK = opk.ID
	}

	aead, nonce, err := messageCipher(dhs, sender.ID(), recipientID)
	if err != nil {
		return nil, err
	}
	hdr.CT = aead.Seal(nil, nonce, plaintext, hdr.aad(recipientID))
	return json.Marshal(hdr)
}

// Keys gives Open access to the recipient's private prekeys.
type Keys interface {
	// SPK returns the signed prekey with that ID, if we still hold it.
	SPK(id uint32) (*ecdh.PrivateKey, bool)
	// OPK returns the one-time prekey with that ID if it was reserved for
	// reservedFor and has not been used. It must not delete it: the caller
	// consumes it only after the message authenticates, so that garbage
	// cannot burn a peer's one-time prekeys.
	OPK(id uint32, reservedFor string) (*ecdh.PrivateKey, bool)
}

// Open decrypts a sealed message addressed to recipient. It returns the
// plaintext, the authenticated sender's peer ID and the one-time prekey ID
// used (0 if none), which the caller must now destroy.
func Open(recipient *identity.Identity, keys Keys, raw []byte) (plaintext []byte, senderID string, opkID uint32, err error) {
	if len(raw) > MaxBlob {
		return nil, "", 0, ErrBadBlob
	}
	var b blob
	if err := json.Unmarshal(raw, &b); err != nil || b.V != blobVersion ||
		len(b.Ed) != ed25519.PublicKeySize || len(b.IK) != 32 || len(b.EK) != 32 {
		return nil, "", 0, ErrBadBlob
	}
	if !identity.Verify(ed25519.PublicKey(b.Ed), signedIK(b.IK), b.IKSig) {
		return nil, "", 0, ErrDecrypt // the sender's DH key is not bound to its identity
	}
	senderID = identity.PeerIDFromPublicKey(b.Ed)

	x := ecdh.X25519()
	senderIK, err := x.NewPublicKey(b.IK)
	if err != nil {
		return nil, "", 0, ErrBadBlob
	}
	ek, err := x.NewPublicKey(b.EK)
	if err != nil {
		return nil, "", 0, ErrBadBlob
	}
	spk, ok := keys.SPK(b.SPK)
	if !ok {
		return nil, "", 0, ErrNoPrekey
	}

	ownIK := recipient.DHKey()
	var dhs [][]byte
	for _, pair := range []struct {
		priv *ecdh.PrivateKey
		pub  *ecdh.PublicKey
	}{{spk, senderIK}, {ownIK, ek}, {spk, ek}} {
		d, err := pair.priv.ECDH(pair.pub)
		if err != nil {
			return nil, "", 0, ErrBadBlob
		}
		dhs = append(dhs, d)
	}
	if b.OPK != 0 {
		opk, ok := keys.OPK(b.OPK, senderID)
		if !ok {
			return nil, "", 0, ErrNoPrekey
		}
		d, err := opk.ECDH(ek)
		if err != nil {
			return nil, "", 0, ErrBadBlob
		}
		dhs = append(dhs, d)
	}

	aead, nonce, err := messageCipher(dhs, senderID, recipient.ID())
	if err != nil {
		return nil, "", 0, err
	}
	plaintext, err = aead.Open(nil, nonce, b.CT, b.aad(recipient.ID()))
	if err != nil {
		return nil, "", 0, ErrDecrypt
	}
	return plaintext, senderID, b.OPK, nil
}

// ---- Delivery receipts ------------------------------------------------------

func receiptMessage(msgID, senderID, signerID string) []byte {
	return []byte(labelReceipt + "|" + msgID + "|" + senderID + "|" + signerID)
}

// SignReceipt signs "I, the signer, received message msgID from senderID".
// A relay can pass this on but cannot forge it.
func SignReceipt(signer *identity.Identity, msgID, senderID string) []byte {
	return signer.Sign(receiptMessage(msgID, senderID, signer.ID()))
}

// VerifyReceipt checks a receipt and returns the signer's peer ID.
func VerifyReceipt(edPub, sig []byte, msgID, senderID string) (signerID string, err error) {
	if len(edPub) != ed25519.PublicKeySize {
		return "", ErrBadBundle
	}
	signerID = identity.PeerIDFromPublicKey(edPub)
	if !identity.Verify(ed25519.PublicKey(edPub), receiptMessage(msgID, senderID, signerID), sig) {
		return "", ErrDecrypt
	}
	return signerID, nil
}
