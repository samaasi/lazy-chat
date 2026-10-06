package models

import (
	"net"
	"strconv"
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

// NetworkAddress returns the dialable host:port of the peer. IPv6 addresses
// are bracketed correctly.
func (p *Peer) NetworkAddress() string {
	return net.JoinHostPort(p.Address, strconv.Itoa(p.Port))
}
