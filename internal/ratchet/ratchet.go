// Package ratchet implements a Double Ratchet (the construction used by
// Signal) for the frames of one peer connection, giving per-message forward
// secrecy and post-compromise security on top of TLS.
//
// Why on top of TLS? TLS 1.3 already gives each connection fresh keys, but a
// chat connection can stay open for days, and one set of traffic keys covers
// all of it. With the ratchet every message is encrypted under its own key
// that is deleted after use, and the keys keep being renewed from fresh
// Diffie-Hellman exchanges, so
//
//   - forward secrecy: capturing the session state now does not reveal any
//     message sent or received earlier, and
//   - post-compromise security: if the state is captured, the session heals
//     itself after one round trip of new messages.
//
// The connection is a reliable, ordered stream, so (unlike Signal) messages
// can never arrive late or out of order and no skipped-message keys are kept:
// the message counter must match exactly, which also rejects replays.
//
// Both sides are authenticated by the TLS handshake. The ratchet's initial
// ephemeral keys are additionally signed with each peer's identity key and
// bound to the TLS session through exported keying material, so a handshake
// cannot be relayed from one connection into another.
package ratchet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
)

const (
	version   = 1
	pubLen    = 32
	headerLen = 1 + pubLen + 4 // version | DH public key | message number
	tagLen    = 16

	// Overhead is the number of bytes sealing adds to a message.
	Overhead = headerLen + tagLen

	initLabel = "lazy-chat/ratchet/init/v1"
)

// Errors returned by the package.
var (
	ErrBadInit   = errors.New("ratchet: invalid handshake message")
	ErrBadSig    = errors.New("ratchet: handshake signature invalid")
	ErrBadHeader = errors.New("ratchet: malformed message header")
	ErrOrder     = errors.New("ratchet: unexpected message number (replay or loss)")
	ErrDecrypt   = errors.New("ratchet: message failed authentication")
	ErrExhausted = errors.New("ratchet: message counter exhausted")
)

// Signer signs handshake transcripts with the peer's identity key.
type Signer interface {
	Sign(msg []byte) []byte
}

// InitMessage is the handshake payload each side sends once.
type InitMessage struct {
	Pub []byte `json:"pub"`
	Sig []byte `json:"sig"`
}

// Handshake is our half of session establishment.
type Handshake struct {
	selfID, peerID string
	binding        []byte
	eph            *ecdh.PrivateKey
}

// Start creates our ephemeral key and the signed InitMessage to send.
// binding must be identical on both sides and unique to this connection
// (TLS exported keying material).
func Start(selfID, peerID string, signer Signer, binding []byte) (*Handshake, []byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: generate key: %w", err)
	}
	pub := eph.PublicKey().Bytes()
	msg, err := json.Marshal(InitMessage{Pub: pub, Sig: signer.Sign(transcript(binding, selfID, peerID, pub))})
	if err != nil {
		return nil, nil, err
	}
	return &Handshake{selfID: selfID, peerID: peerID, binding: binding, eph: eph}, msg, nil
}

// transcript is what each side signs: it commits to the connection, to who is
// talking to whom, and to the ephemeral key.
func transcript(binding []byte, from, to string, pub []byte) []byte {
	var b bytes.Buffer
	b.WriteString(initLabel)
	b.WriteByte(0)
	b.Write(binding)
	b.WriteString(from)
	b.WriteByte(0)
	b.WriteString(to)
	b.WriteByte(0)
	b.Write(pub)
	return b.Bytes()
}

// Finish verifies the peer's InitMessage against its identity key and derives
// the session.
func (h *Handshake) Finish(peerInit []byte, peerKey ed25519.PublicKey) (*Session, error) {
	var m InitMessage
	if err := json.Unmarshal(peerInit, &m); err != nil || len(m.Pub) != pubLen {
		return nil, ErrBadInit
	}
	if len(peerKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(peerKey, transcript(h.binding, h.peerID, h.selfID, m.Pub), m.Sig) {
		return nil, ErrBadSig
	}
	peerEph, err := ecdh.X25519().NewPublicKey(m.Pub)
	if err != nil {
		return nil, ErrBadInit
	}
	shared, err := h.eph.ECDH(peerEph) // rejects low-order points
	if err != nil {
		return nil, ErrBadInit
	}

	// Order everything by peer ID so both sides derive the same values.
	selfIsLo := h.selfID < h.peerID
	loPub, hiPub := h.eph.PublicKey().Bytes(), m.Pub
	if !selfIsLo {
		loPub, hiPub = hiPub, loPub
	}
	info := append(append([]byte("lazy-chat/ratchet/sk/v1"), loPub...), hiPub...)
	sk, err := hkdf.Key(sha256.New, shared, h.binding, string(info), 32)
	if err != nil {
		return nil, err
	}
	expand := func(label string) []byte {
		k, _ := hkdf.Expand(sha256.New, sk, "lazy-chat/ratchet/"+label, 32)
		return k
	}
	loToHi, hiToLo := expand("chain lo>hi"), expand("chain hi>lo")

	s := &Session{rk: expand("root"), dhs: h.eph, dhr: peerEph}
	if selfIsLo {
		s.cks, s.ckr = loToHi, hiToLo
		s.pending = true // the lower ID starts the DH ratchet with its first message
	} else {
		s.cks, s.ckr = hiToLo, loToHi
	}
	wipe(sk)
	return s, nil
}

// Session is the ratchet state for one connection. Seal and Open may be
// called from different goroutines.
type Session struct {
	mu sync.Mutex

	rk       []byte // root key
	dhs      *ecdh.PrivateKey
	dhr      *ecdh.PublicKey
	cks, ckr []byte // sending and receiving chain keys
	ns, nr   uint32 // messages sent / received in the current chains
	pending  bool   // next Seal starts a new DH ratchet step
}

// Seal encrypts plaintext. The output is header || ciphertext.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ns == math.MaxUint32 {
		return nil, ErrExhausted
	}
	if s.pending {
		fresh, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		dh, err := fresh.ECDH(s.dhr)
		if err != nil {
			return nil, err
		}
		rk, ck := kdfRK(s.rk, dh)
		wipe(s.rk)
		wipe(s.cks)
		s.rk, s.cks, s.dhs, s.ns, s.pending = rk, ck, fresh, 0, false
	}

	mk, next := chainStep(s.cks)
	wipe(s.cks)
	s.cks = next

	out := make([]byte, headerLen, headerLen+len(plaintext)+tagLen)
	out[0] = version
	copy(out[1:], s.dhs.PublicKey().Bytes())
	putUint32(out[1+pubLen:], s.ns)
	s.ns++

	aead, nonce, err := messageCipher(mk)
	wipe(mk)
	if err != nil {
		return nil, err
	}
	// The header is authenticated but not encrypted; the ciphertext is
	// appended after it.
	return aead.Seal(out, nonce, plaintext, out[:headerLen]), nil
}

// Open decrypts a message produced by the peer's Seal. State only advances
// if the message authenticates.
func (s *Session) Open(msg []byte) ([]byte, error) {
	if len(msg) < Overhead || msg[0] != version {
		return nil, ErrBadHeader
	}
	hdr, ct := msg[:headerLen], msg[headerLen:]
	theirPub := hdr[1 : 1+pubLen]
	n := getUint32(hdr[1+pubLen:])

	s.mu.Lock()
	defer s.mu.Unlock()

	// Work on copies; commit only after successful decryption.
	rk, ckr, dhr, nr, pending := s.rk, s.ckr, s.dhr, s.nr, s.pending
	var newRK []byte

	if !bytes.Equal(theirPub, s.dhr.Bytes()) {
		// The peer ratcheted: derive the new receiving chain.
		pub, err := ecdh.X25519().NewPublicKey(theirPub)
		if err != nil {
			return nil, ErrBadHeader
		}
		dh, err := s.dhs.ECDH(pub)
		if err != nil {
			return nil, ErrBadHeader
		}
		newRK, ckr = kdfRK(s.rk, dh)
		rk, dhr, nr, pending = newRK, pub, 0, true
	}
	if n != nr {
		wipe(newRK)
		if newRK != nil {
			wipe(ckr)
		}
		return nil, ErrOrder
	}

	mk, next := chainStep(ckr)
	aead, nonce, err := messageCipher(mk)
	wipe(mk)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		wipe(next)
		if newRK != nil {
			wipe(newRK)
			wipe(ckr)
		}
		return nil, ErrDecrypt
	}

	// The old root and chain keys are no longer needed: this is what makes
	// earlier messages unrecoverable from the state that remains.
	wipe(s.ckr)
	if newRK != nil {
		wipe(s.rk)
		wipe(ckr) // the freshly derived chain, now consumed
	}
	s.rk, s.ckr, s.dhr, s.nr, s.pending = rk, next, dhr, nr+1, pending
	return plain, nil
}

// ---- Key derivation ----------------------------------------------------------

// kdfRK derives the next root key and a chain key from a DH output.
func kdfRK(rk, dh []byte) (newRK, chainKey []byte) {
	out, _ := hkdf.Key(sha256.New, dh, rk, "lazy-chat/ratchet/rk", 64)
	return out[:32], out[32:]
}

// chainStep derives a message key and the next chain key.
func chainStep(ck []byte) (mk, next []byte) {
	m := hmac.New(sha256.New, ck)
	m.Write([]byte{0x01})
	mk = m.Sum(nil)
	m = hmac.New(sha256.New, ck)
	m.Write([]byte{0x02})
	return mk, m.Sum(nil)
}

// messageCipher derives an AES-256-GCM key and nonce from a one-time message key.
func messageCipher(mk []byte) (cipher.AEAD, []byte, error) {
	okm, err := hkdf.Key(sha256.New, mk, nil, "lazy-chat/ratchet/msg", 32+12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(okm[:32])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, okm[32:], nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func getUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
