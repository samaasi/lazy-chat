package update

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
)

// releaseKey is the cosign public key that release checksums are signed with.
// Releases are signed in CI with the matching private key (see RELEASING.md).
//
//go:embed release.pub
var releaseKey []byte

// ErrNoReleaseKey is returned when this build carries no usable release key,
// in which case updates are refused rather than trusted blindly.
var ErrNoReleaseKey = errors.New("this build has no release signing key, so updates cannot be verified (install a release build)")

// ParsePublicKey reads a PEM-encoded ECDSA P-256 public key, the format that
// `cosign generate-key-pair` writes to cosign.pub.
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, ErrNoReleaseKey
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bad release key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" {
		return nil, errors.New("the release key is not an ECDSA P-256 key")
	}
	return pub, nil
}

// ReleaseKey returns the embedded release key.
func ReleaseKey() (*ecdsa.PublicKey, error) { return ParsePublicKey(releaseKey) }
