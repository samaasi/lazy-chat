package interfaces

import (
	"context"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/protocol"
)

// PeerDiscovery handles peer discovery functionality
type PeerDiscovery interface {
	// Start begins the discovery process
	Start(ctx context.Context) error
	// Stop gracefully stops the discovery process
	Stop() error
}

// FrameHandler receives the body of a frame from an authenticated peer.
// peerID is the identity proven by the TLS handshake and is the only thing a
// handler may trust about who sent the frame. Handlers run on the
// connection's read goroutine and must not block for long.
type FrameHandler func(peerID string, body []byte)

// PeerListener is told when authenticated peer connections come and go.
type PeerListener interface {
	PeerConnected(peerID, username string)
	PeerDisconnected(peerID string)
}

// NetworkManager handles authenticated, encrypted peer connections.
type NetworkManager interface {
	// Start begins listening for incoming connections
	Start(ctx context.Context) error
	// Stop gracefully stops the network manager
	Stop() error
	// ConnectToPeer establishes a connection to a discovered peer
	ConnectToPeer(ctx context.Context, peerID string) error
	// Disconnect closes the connection to a peer, if any
	Disconnect(peerID string)
	// Send queues a frame for a peer, connecting first if needed
	Send(ctx context.Context, peerID string, kind protocol.Kind, body []byte) error
	// SendJSON marshals payload and sends it as a frame
	SendJSON(ctx context.Context, peerID string, kind protocol.Kind, payload any) error
	// IsConnected checks if connected to a specific peer
	IsConnected(peerID string) bool
	// ConnectedPeers returns the IDs of all connected peers
	ConnectedPeers() []string
	// PeerName returns the display name a peer announced, if known
	PeerName(peerID string) (string, bool)
	// Handle registers the handler for a frame kind
	Handle(kind protocol.Kind, h FrameHandler)
	// AddListener subscribes to connect/disconnect events
	AddListener(l PeerListener)
}

// PeerManager manages the set of known peers
type PeerManager interface {
	// AddPeer adds or updates a peer; it reports whether the peer is new.
	AddPeer(peer *models.Peer) (added bool)
	// RemovePeer removes a peer
	RemovePeer(peerID string)
	// GetPeer retrieves a peer by ID
	GetPeer(peerID string) (*models.Peer, bool)
	// Peers returns a snapshot of all peers, sorted by name
	Peers() []*models.Peer
	// ResolvePeer finds a peer by full ID, unique ID prefix, or username
	ResolvePeer(query string) (*models.Peer, error)
	// CleanupStalePeers removes peers that haven't been seen recently
	CleanupStalePeers(threshold time.Duration)
}

// NotificationManager handles OS notifications
type NotificationManager interface {
	// NotifyMessageReceived sends a notification for received messages
	NotifyMessageReceived(sender, message string) error
	// NotifyFileReceived sends a notification for received files
	NotifyFileReceived(sender, filename string) error
	// NotifyPeerConnected sends a notification when a peer connects
	NotifyPeerConnected(peerName string) error
	// NotifyPeerDisconnected sends a notification when a peer disconnects
	NotifyPeerDisconnected(peerName string) error
	// SetEnabled enables or disables notifications
	SetEnabled(enabled bool)
	// IsEnabled returns whether notifications are enabled
	IsEnabled() bool
}

// Logger defines logging interface
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
	Fatal(msg string, keysAndValues ...any)
}
