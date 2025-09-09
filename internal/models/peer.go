package models

import (
	"fmt"
	"time"
)

// Peer represents a discovered peer in the network
type Peer struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	LastSeen time.Time `json:"last_seen"`
}

// IsStale checks if the peer hasn't been seen for a specified duration
func (p *Peer) IsStale(threshold time.Duration) bool {
	return time.Since(p.LastSeen) > threshold
}

// Address returns the full network address of the peer
func (p *Peer) NetworkAddress() string {
	return fmt.Sprintf("%s:%d", p.Address, p.Port)
}