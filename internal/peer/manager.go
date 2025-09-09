package peer

import (
	"sync"
	"time"

	"github.com/lazy-chat/internal/interfaces"
	"github.com/lazy-chat/internal/models"
)

// Manager implements the PeerManager interface
type Manager struct {
	peers  map[string]*models.Peer
	mu     sync.RWMutex
	logger interfaces.Logger
}

// NewManager creates a new peer manager
func NewManager(logger interfaces.Logger) *Manager {
	return &Manager{
		peers:  make(map[string]*models.Peer),
		logger: logger,
	}
}

// AddPeer adds or updates a peer
func (m *Manager) AddPeer(peer *models.Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existingPeer, exists := m.peers[peer.ID]
	if !exists {
		m.logger.Info("New peer discovered", "id", peer.ID, "username", peer.Username, "address", peer.NetworkAddress())
	} else {
		m.logger.Debug("Peer updated", "id", peer.ID, "username", peer.Username, "address", peer.NetworkAddress())
	}

	// Update the peer information
	m.peers[peer.ID] = peer

	// Log if this is a new peer or if the peer's information changed
	if !exists || existingPeer.Address != peer.Address || existingPeer.Port != peer.Port {
		m.logger.Debug("Peer information updated", "id", peer.ID, "old_addr", func() string {
			if exists {
				return existingPeer.NetworkAddress()
			}
			return "none"
		}(), "new_addr", peer.NetworkAddress())
	}
}

// RemovePeer removes a peer
func (m *Manager) RemovePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if peer, exists := m.peers[peerID]; exists {
		delete(m.peers, peerID)
		m.logger.Info("Peer removed", "id", peerID, "username", peer.Username)
	}
}

// GetPeer retrieves a peer by ID
func (m *Manager) GetPeer(peerID string) (*models.Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, exists := m.peers[peerID]
	return peer, exists
}

// GetAllPeers returns all peers
func (m *Manager) GetAllPeers() map[string]*models.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]*models.Peer, len(m.peers))
	for id, peer := range m.peers {
		result[id] = peer
	}
	return result
}

// CleanupStalePeers removes peers that haven't been seen recently
func (m *Manager) CleanupStalePeers(threshold time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var removedCount int

	for id, peer := range m.peers {
		if peer.IsStale(threshold) {
			m.logger.Debug("Removing stale peer", "id", id, "username", peer.Username, "last_seen", peer.LastSeen)
			delete(m.peers, id)
			removedCount++
		}
	}

	if removedCount > 0 {
		m.logger.Info("Cleaned up stale peers", "count", removedCount, "threshold", threshold)
	}
}

// GetPeerCount returns the number of discovered peers
func (m *Manager) GetPeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}