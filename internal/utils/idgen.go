package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// IDGenerator generates unguessable, collision-resistant identifiers.
// It is stateless and safe for concurrent use.
type IDGenerator struct{}

// NewIDGenerator creates a new ID generator.
func NewIDGenerator() *IDGenerator {
	return &IDGenerator{}
}

// GenerateID returns a random 128-bit identifier encoded as 32 hex characters.
func (g *IDGenerator) GenerateID() string {
	return NewID()
}

// NewID returns a random 128-bit identifier encoded as 32 hex characters.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the OS entropy source is broken; there is
		// no safe way to continue handing out identifiers.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// NewPrefixedID returns NewID() with a human-readable prefix, e.g. "grp_ab12…".
func NewPrefixedID(prefix string) string {
	return prefix + "_" + NewID()
}
