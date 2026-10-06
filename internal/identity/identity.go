// Package identity gives every peer a persistent cryptographic identity.
//
// A peer is its Ed25519 key pair. Its ID is a fingerprint of the public key,
// so an ID cannot be claimed without holding the matching private key. The
// same key backs the TLS certificate used on peer connections and signs
// discovery announcements, which is what makes impersonation and address
// hijacking detectable.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KeyFileName is the identity key file inside the data directory.
const KeyFileName = "identity.key"

// idBytes is how much of the SHA-256 fingerprint forms the peer ID
// (128 bits, 32 hex characters).
const idBytes = 16

// Identity is a peer's key pair and derived ID. It is immutable and safe for
// concurrent use.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

// Sealer encrypts the private key at rest (see package vault).
type Sealer interface {
	Seal(plaintext []byte, aad string) string
	Open(sealed, aad string) ([]byte, error)
}

// ErrSealed is returned when the key file is encrypted but no Sealer was given.
var ErrSealed = errors.New("identity key is encrypted, but encryption is switched off")

const (
	sealedHeader = "LAZYCHAT-SEALED-1\n"
	keyAAD       = "identity.key"
)

// LoadOrCreate loads the identity stored in dir, creating dir (0700) and a new
// key (0600) on first run. The key is stored unencrypted; see LoadOrCreateSealed.
func LoadOrCreate(dir string) (*Identity, error) {
	return LoadOrCreateSealed(dir, nil)
}

// LoadOrCreateSealed is LoadOrCreate with encryption at rest. With a Sealer,
// the private key file is stored encrypted, and an existing plaintext key is
// encrypted in place. Without one, an encrypted key file is an error rather
// than being silently replaced with a new identity.
func LoadOrCreateSealed(dir string, sealer Sealer) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	path := filepath.Join(dir, KeyFileName)

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		id, err := Generate()
		if err != nil {
			return nil, err
		}
		if err := writeNew(path, encode(id, sealer)); err != nil {
			return nil, err
		}
		return id, nil
	default:
		return nil, fmt.Errorf("read identity key: %w", err)
	}

	if rest, sealed := strings.CutPrefix(string(data), sealedHeader); sealed {
		if sealer == nil {
			return nil, ErrSealed
		}
		plain, err := sealer.Open(strings.TrimSpace(rest), keyAAD)
		if err != nil {
			return nil, fmt.Errorf("unlock identity key: %w", err)
		}
		return parse(plain)
	}

	id, err := parse(data)
	if err != nil {
		return nil, err
	}
	if sealer != nil { // encrypt a pre-existing plaintext key
		if err := replace(path, encode(id, sealer)); err != nil {
			return nil, fmt.Errorf("encrypt identity key: %w", err)
		}
	}
	return id, nil
}

// Generate creates a new random identity without persisting it.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	return newIdentity(priv, pub), nil
}

func newIdentity(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Identity {
	return &Identity{priv: priv, pub: pub, id: PeerIDFromPublicKey(pub)}
}

func parse(data []byte) (*Identity, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("identity key file is not a PEM PRIVATE KEY")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not an Ed25519 key")
	}
	return newIdentity(priv, priv.Public().(ed25519.PublicKey)), nil
}

// encode serialises the private key, encrypted when a Sealer is given.
func encode(id *Identity, sealer Sealer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(id.priv)
	if err != nil {
		panic(err) // an Ed25519 key always marshals
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if sealer == nil {
		return pemBytes
	}
	return []byte(sealedHeader + sealer.Seal(pemBytes, keyAAD) + "\n")
}

// writeNew creates the file with O_EXCL so two instances starting at once
// cannot both succeed with different keys, and never leaves a world-readable file.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create identity key: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("write identity key: %w", err)
	}
	return f.Close()
}

// replace atomically swaps in new contents (write a temp file, then rename).
func replace(path string, data []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ID returns the peer ID derived from the public key.
func (i *Identity) ID() string { return i.id }

// PublicKey returns the Ed25519 public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.pub }

// Sign signs msg with the private key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// PeerIDFromPublicKey derives the peer ID for a public key.
func PeerIDFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:idBytes])
}

// Verify reports whether sig is a valid signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig)
}

// ValidID reports whether s has the shape of a peer ID.
func ValidID(s string) bool {
	if len(s) != idBytes*2 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// TLSCertificate returns a fresh self-signed certificate for the identity key.
// Trust never comes from the certificate chain: peers are authenticated by
// comparing the fingerprint of the certificate's public key with the expected
// peer ID (see PeerIDFromCertificate).
func (i *Identity) TLSCertificate() (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: i.id},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, i.pub, i.priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: i.priv}, nil
}

// PeerIDFromCertificate extracts the peer ID from a DER certificate presented
// by a remote peer. The remote proved possession of the matching private key
// during the TLS handshake, so the returned ID is authentic.
func PeerIDFromCertificate(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse peer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("peer certificate does not use an Ed25519 key")
	}
	return PeerIDFromPublicKey(pub), nil
}

// SafetyNumber returns a short number two peers can compare out of band
// (read aloud, or side by side) to confirm they are talking to each other and
// not to an impostor. Both peers compute the same value: it is derived from
// the pair of peer IDs, which are fingerprints of the public keys, so it
// changes if either key does. The result is 60 digits in 12 groups of five.
func SafetyNumber(idA, idB string) string {
	lo, hi := idA, idB
	if lo > hi {
		lo, hi = hi, lo
	}
	sum := sha512.Sum512([]byte("lazy-chat/safety/v1|" + lo + "|" + hi))

	groups := make([]string, 12)
	for i := range groups {
		var v uint64
		for _, b := range sum[i*5 : i*5+5] {
			v = v<<8 | uint64(b)
		}
		groups[i] = fmt.Sprintf("%05d", v%100000)
	}
	return strings.Join(groups, " ")
}
