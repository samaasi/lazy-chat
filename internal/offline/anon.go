package offline

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// An anonymous box encrypts to a public key in a way that identifies nobody:
// the sender uses a fresh ephemeral key and signs nothing, so the ciphertext
// carries no trace of who made it. This is the outer layer of a sealed-sender
// message and the wrapper for requests to a relay.
//
//	[ header ][ ephemeral public key (32) ][ AES-256-GCM ciphertext ]
//
// The optional header (for example the ID of the signed prekey used) is sent
// in the clear but authenticated, and aad names the purpose so a box made for
// one use cannot be replayed into another.

const (
	labelAnon = "lazy-chat/offline/anon/v1"
	anonTag   = 16
	// AnonOverhead is what an SPK-addressed box adds to its plaintext.
	AnonOverhead = 4 + 32 + anonTag
)

// ErrBadBox is returned for malformed or unauthenticated anonymous boxes.
var ErrBadBox = errors.New("offline: anonymous box failed to open")

func anonCipher(dh, ephPub, recipientPub []byte, aad string) (cipher.AEAD, []byte, error) {
	okm, err := hkdf.Key(sha256.New, dh, nil, labelAnon+"|"+aad+"|"+string(ephPub)+"|"+string(recipientPub), 32+12)
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

func sealAnon(pub *ecdh.PublicKey, header []byte, aad string, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dh, err := eph.ECDH(pub)
	if err != nil {
		return nil, ErrBadBox
	}
	aead, nonce, err := anonCipher(dh, eph.PublicKey().Bytes(), pub.Bytes(), aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(header)+32+len(plaintext)+anonTag)
	out = append(out, header...)
	out = append(out, eph.PublicKey().Bytes()...)
	return aead.Seal(out, nonce, plaintext, append(append([]byte(nil), header...), aad...)), nil
}

func openAnon(priv *ecdh.PrivateKey, header, rest []byte, aad string) ([]byte, error) {
	if len(rest) < 32+anonTag {
		return nil, ErrBadBox
	}
	ephPub, ct := rest[:32], rest[32:]
	eph, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, ErrBadBox
	}
	dh, err := priv.ECDH(eph)
	if err != nil {
		return nil, ErrBadBox
	}
	aead, nonce, err := anonCipher(dh, ephPub, priv.PublicKey().Bytes(), aad)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, append(append([]byte(nil), header...), aad...))
	if err != nil {
		return nil, ErrBadBox
	}
	return plain, nil
}

// SealToKey encrypts plaintext to a one-off public key (used for replies: the
// requester includes a fresh key, and the answer is sealed to it).
func SealToKey(pub []byte, aad string, plaintext []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, ErrBadBox
	}
	return sealAnon(k, nil, aad, plaintext)
}

// OpenWithKey reverses SealToKey.
func OpenWithKey(priv *ecdh.PrivateKey, aad string, box []byte) ([]byte, error) {
	return openAnon(priv, nil, box, aad)
}

// SealToSPK encrypts plaintext to a signed prekey, naming the prekey in the
// clear header so its owner knows which private key to use.
func SealToSPK(spkID uint32, spkPub []byte, aad string, plaintext []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPublicKey(spkPub)
	if err != nil {
		return nil, ErrBadBox
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], spkID)
	return sealAnon(k, header[:], aad, plaintext)
}

// OpenFromSPK opens a box made by SealToSPK using one of our signed prekeys.
// ErrNoPrekey means the prekey it names is gone, so the box can never be read.
func OpenFromSPK(keys Keys, aad string, box []byte) ([]byte, error) {
	if len(box) < AnonOverhead {
		return nil, ErrBadBox
	}
	spk, ok := keys.SPK(binary.BigEndian.Uint32(box[:4]))
	if !ok {
		return nil, ErrNoPrekey
	}
	return openAnon(spk, box[:4], box[4:], aad)
}
