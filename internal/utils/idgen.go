package utils

import (
	"math/rand"
	"time"
)

// IDGenerator generates poetic peer identifiers
type IDGenerator struct {
	rng *rand.Rand
}

// NewIDGenerator creates a new ID generator with a seeded random number generator
func NewIDGenerator() *IDGenerator {
	return &IDGenerator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GeneratePoeticID creates a poetic identifier combining an adjective and noun
func (g *IDGenerator) GeneratePoeticID() string {
	adjectives := []string{
		"crimson", "azure", "golden", "silver", "emerald", "violet", "amber", "coral",
		"gentle", "swift", "quiet", "bright", "mystic", "serene", "bold", "wise",
		"dancing", "whispering", "glowing", "shimmering", "flowing", "soaring", "dreaming", "wandering",
	}
	
	nouns := []string{
		"moon", "star", "river", "ocean", "mountain", "forest", "meadow", "valley",
		"phoenix", "dragon", "wolf", "eagle", "dove", "butterfly", "tiger", "falcon",
		"breeze", "storm", "flame", "crystal", "shadow", "light", "echo", "dream",
	}
	
	adjective := adjectives[g.rng.Intn(len(adjectives))]
	noun := nouns[g.rng.Intn(len(nouns))]
	
	return adjective + "-" + noun
}