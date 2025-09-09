package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
)

// Service implements the PeerDiscovery interface
type Service struct {
	config      *config.Config
	logger      interfaces.Logger
	peerManager interfaces.PeerManager
	conn        *net.UDPConn
	peerID      string
	username    string
	port        int
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
}

// NewService creates a new discovery service
func NewService(cfg *config.Config, logger interfaces.Logger, peerManager interfaces.PeerManager, peerID, username string, port int) *Service {
	return &Service{
		config:      cfg,
		logger:      logger,
		peerManager: peerManager,
		peerID:      peerID,
		username:    username,
		port:        port,
	}
}

// Start begins the discovery process
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ctx != nil {
		return errors.ErrAppAlreadyRunning.WithContext("component", "discovery_service")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	// Try to find an available discovery port
	var conn *net.UDPConn
	var err error
	var discoveryPort int

	for port := s.config.DiscoveryPort; port < s.config.DiscoveryPort+s.config.DiscoveryRange; port++ {
		addr, addrErr := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if addrErr != nil {
			continue
		}

		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			discoveryPort = port
			break
		}
	}

	if conn == nil {
		return errors.Wrap(err, errors.ErrorTypeDiscovery, "DISC001", "failed to bind to any discovery port").WithContext("port_range", fmt.Sprintf("%d-%d", s.config.DiscoveryPort, s.config.DiscoveryPort+s.config.DiscoveryRange-1))
	}

	s.conn = conn
	s.logger.Info("Discovery started", "port", discoveryPort)

	// Start listening for discovery messages
	s.wg.Add(1)
	go s.listenForDiscovery()

	// Start broadcasting our presence
	s.wg.Add(1)
	go s.broadcastPresence(discoveryPort)

	return nil
}

// Stop gracefully stops the discovery process
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.conn != nil {
		s.conn.Close()
	}

	s.wg.Wait()
	s.logger.Info("Discovery service stopped")
	return nil
}

// GetPeers returns all discovered peers
func (s *Service) GetPeers() map[string]*models.Peer {
	return s.peerManager.GetAllPeers()
}

// GetPeer returns a specific peer by ID
func (s *Service) GetPeer(id string) (*models.Peer, bool) {
	return s.peerManager.GetPeer(id)
}

// listenForDiscovery listens for incoming discovery messages
func (s *Service) listenForDiscovery() {
	defer s.wg.Done()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Error("Failed to read UDP message", "error", err)
			continue
		}

		var msg models.DiscoveryMessage
		if err := json.Unmarshal(buffer[:n], &msg); err != nil {
			s.logger.Debug("Failed to unmarshal discovery message", "error", err)
			continue
		}

		// Ignore our own messages
		if msg.PeerID == s.peerID {
			continue
		}

		peer := &models.Peer{
			ID:       msg.PeerID,
			Username: msg.Username,
			Address:  addr.IP.String(),
			Port:     msg.Port,
			LastSeen: time.Now(),
		}

		s.peerManager.AddPeer(peer)
		s.logger.Debug("Discovered peer", "id", peer.ID, "username", peer.Username, "address", peer.NetworkAddress())
	}
}

// broadcastPresence broadcasts our presence to the network
func (s *Service) broadcastPresence(discoveryPort int) {
	defer s.wg.Done()

	msg := models.NewDiscoveryMessage(s.peerID, s.username, s.port)
	data, err := json.Marshal(msg)
	if err != nil {
		s.logger.Error("Failed to marshal discovery message", "error", err)
		return
	}

	ticker := time.NewTicker(time.Duration(s.config.BroadcastInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.broadcast(data)
		}
	}
}

// broadcast sends discovery message to all ports in the discovery range
func (s *Service) broadcast(data []byte) {
	for port := s.config.DiscoveryPort; port < s.config.DiscoveryPort+s.config.DiscoveryRange; port++ {
		broadcastAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.config.BroadcastAddr, port))
		if err != nil {
			continue
		}

		conn, err := net.DialUDP("udp", nil, broadcastAddr)
		if err != nil {
			continue
		}

		conn.Write(data)
		conn.Close()
	}
}
