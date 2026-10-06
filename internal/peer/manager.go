package peer

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
)

const (
	// MaxPeers bounds the table so announcement floods cannot exhaust memory.
	MaxPeers = 1024
	// MaxPeersPerAddress bounds how many identities one source address can
	// register. Identities are free to mint, so without this a single host
	// could fill the table and lock real peers out.
	MaxPeersPerAddress = 16
	// minPrefixLen is the shortest ID prefix ResolvePeer accepts.
	minPrefixLen = 4
)

// Manager implements the PeerManager interface. It stores copies of the peers
// it is given and hands out copies, so callers can never race with updates.
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

// AddPeer adds or updates a peer. It reports whether the peer was new, and
// ignores peers that would exceed the table limits.
func (m *Manager) AddPeer(p *models.Peer) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *p
	existing, exists := m.peers[cp.ID]
	if !exists {
		if len(m.peers) >= MaxPeers || m.countAddressLocked(cp.Address) >= MaxPeersPerAddress {
			m.logger.Debug("Peer table limit reached; ignoring peer", "address", cp.Address)
			return false
		}
		m.logger.Debug("New peer discovered", "id", cp.ID, "address", cp.NetworkAddress())
	} else if existing.Address != cp.Address || existing.Port != cp.Port {
		m.logger.Debug("Peer address changed", "id", cp.ID, "old", existing.NetworkAddress(), "new", cp.NetworkAddress())
	}
	m.peers[cp.ID] = &cp
	return !exists
}

func (m *Manager) countAddressLocked(addr string) int {
	n := 0
	for _, p := range m.peers {
		if p.Address == addr {
			n++
		}
	}
	return n
}

// RemovePeer removes a peer
func (m *Manager) RemovePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, peerID)
}

// GetPeer retrieves a copy of a peer by ID
func (m *Manager) GetPeer(peerID string) (*models.Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.peers[peerID]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Peers returns copies of all peers sorted by username, then ID.
func (m *Manager) Peers() []*models.Peer {
	m.mu.RLock()
	out := make([]*models.Peer, 0, len(m.peers))
	for _, p := range m.peers {
		cp := *p
		out = append(out, &cp)
	}
	m.mu.RUnlock()

	slices.SortFunc(out, func(a, b *models.Peer) int {
		if c := strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// ResolvePeer finds a peer by exact ID, by unique ID prefix (at least 4
// characters), or by case-insensitive username. Ambiguous queries are an
// error rather than a guess: sending a message to the wrong person is worse
// than asking again.
func (m *Manager) ResolvePeer(query string) (*models.Peer, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, apperrors.ErrPeerInvalidID.WithContext("reason", "empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if p, ok := m.peers[strings.ToLower(query)]; ok {
		cp := *p
		return &cp, nil
	}

	var matches []*models.Peer
	lower := strings.ToLower(query)
	if len(lower) >= minPrefixLen {
		for id, p := range m.peers {
			if strings.HasPrefix(id, lower) {
				matches = append(matches, p)
			}
		}
	}
	if len(matches) == 0 {
		for _, p := range m.peers {
			if strings.EqualFold(p.Username, query) {
				matches = append(matches, p)
			}
		}
	}

	switch len(matches) {
	case 0:
		return nil, apperrors.ErrPeerNotFound.WithContext("query", query)
	case 1:
		cp := *matches[0]
		return &cp, nil
	default:
		return nil, apperrors.ErrPeerInvalidID.WithContext("reason", fmt.Sprintf("%q matches %d peers; use a longer ID prefix", query, len(matches)))
	}
}

// CleanupStalePeers removes peers that haven't been seen recently
func (m *Manager) CleanupStalePeers(threshold time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	for id, p := range m.peers {
		if p.IsStale(threshold) {
			delete(m.peers, id)
			removed++
		}
	}
	if removed > 0 {
		m.logger.Debug("Cleaned up stale peers", "count", removed, "threshold", threshold)
	}
}

// Count returns the number of known peers
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}
