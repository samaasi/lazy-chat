package identity

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
)

// DHKey returns the peer's long-term X25519 key, used for the Diffie-Hellman
// part of offline (prekey) messages. It is derived from the Ed25519 seed with
// HKDF, so nothing extra has to be stored or backed up: restoring identity.key
// restores this key too. Its public half is published signed by the Ed25519
// key, which is what binds it to the peer ID.
func (i *Identity) DHKey() *ecdh.PrivateKey {
	raw, err := hkdf.Key(sha256.New, i.priv.Seed(), nil, "lazy-chat/identity/x25519/v1", 32)
	if err != nil {
		panic(err) // HKDF with a fixed, valid output length cannot fail
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		panic(err) // any 32 bytes are a valid X25519 private key
	}
	return k
}
