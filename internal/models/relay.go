package models

// RelayResult reports how a message was queued with relays for an offline
// recipient.
type RelayResult struct {
	// Relays is how many peers agreed to hold the message.
	Relays int
	// Exposed is how many of them saw who the sender was, because no third
	// peer was available to forward the request anonymously.
	Exposed int
}
