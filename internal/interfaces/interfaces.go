package interfaces

import (
	"context"
	"net"
	"time"

	"github.com/lazy-chat/internal/models"
)

// PeerDiscovery handles peer discovery functionality
type PeerDiscovery interface {
	// Start begins the discovery process
	Start(ctx context.Context) error
	// Stop gracefully stops the discovery process
	Stop() error
	// GetPeers returns all discovered peers
	GetPeers() map[string]*models.Peer
	// GetPeer returns a specific peer by ID
	GetPeer(id string) (*models.Peer, bool)
}

// NetworkManager handles TCP connections and messaging
type NetworkManager interface {
	// Start begins listening for incoming connections
	Start(ctx context.Context) error
	// Stop gracefully stops the network manager
	Stop() error
	// ConnectToPeer establishes a connection to a peer
	ConnectToPeer(ctx context.Context, peerID string) error
	// SendMessage sends a message to a connected peer
	SendMessage(peerID, message string) error
	// GetConnections returns all active connections
	GetConnections() map[string]net.Conn
	// IsConnected checks if connected to a specific peer
	IsConnected(peerID string) bool
}

// MessageHandler handles incoming chat messages
type MessageHandler interface {
	HandleMessage(msg *models.ChatMessage)
	SetMessageCallback(callback func(*models.ChatMessage))
}

// PeerManager manages peer lifecycle and state
type PeerManager interface {
	// AddPeer adds or updates a peer
	AddPeer(peer *models.Peer)
	// RemovePeer removes a peer
	RemovePeer(peerID string)
	// GetPeer retrieves a peer by ID
	GetPeer(peerID string) (*models.Peer, bool)
	// GetAllPeers returns all peers
	GetAllPeers() map[string]*models.Peer
	// CleanupStalePeers removes peers that haven't been seen recently
	CleanupStalePeers(threshold time.Duration)
}

// Logger defines logging interface
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Fatal(msg string, keysAndValues ...interface{})
}

// IDGenerator generates unique identifiers
type IDGenerator interface {
	// GeneratePoeticID creates a poetic identifier
	GeneratePoeticID() string
}