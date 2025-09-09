package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lazy-chat/internal/errors"
	"github.com/lazy-chat/internal/interfaces"
	"github.com/lazy-chat/internal/models"
)

// Manager implements the NetworkManager interface
type Manager struct {
	port        int
	username    string
	logger      interfaces.Logger
	peerManager interfaces.PeerManager
	msgHandler  interfaces.MessageHandler
	notificationMgr interfaces.NotificationManager
	listener    net.Listener
	connections map[string]net.Conn
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewManager creates a new network manager
func NewManager(port int, username string, logger interfaces.Logger, peerManager interfaces.PeerManager, msgHandler interfaces.MessageHandler, notificationMgr interfaces.NotificationManager) *Manager {
	return &Manager{
		port:        port,
		username:    username,
		logger:      logger,
		peerManager: peerManager,
		msgHandler:  msgHandler,
		notificationMgr: notificationMgr,
		connections: make(map[string]net.Conn),
	}
}

// Start begins listening for incoming connections
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ctx != nil {
		return errors.ErrAppAlreadyRunning.WithContext("component", "network_manager")
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.port))
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeNetwork, "NET002", "failed to start TCP listener").WithContext("port", m.port)
	}

	m.listener = listener
	m.logger.Info("TCP server started", "port", m.port)

	// Start accepting connections
	m.wg.Add(1)
	go m.acceptConnections()

	return nil
}

// Stop gracefully stops the network manager
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}

	if m.listener != nil {
		m.listener.Close()
	}

	// Close all connections
	for peerID, conn := range m.connections {
		m.logger.Debug("Closing connection", "peer_id", peerID)
		conn.Close()
	}

	m.wg.Wait()
	m.logger.Info("Network manager stopped")
	return nil
}

// ConnectToPeer establishes a connection to a peer
func (m *Manager) ConnectToPeer(ctx context.Context, peerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already connected
	if _, exists := m.connections[peerID]; exists {
		return errors.ErrPeerAlreadyConnected.WithContext("peer_id", peerID)
	}

	// Get peer information
	peer, exists := m.peerManager.GetPeer(peerID)
	if !exists {
		return errors.ErrPeerNotFound.WithContext("peer_id", peerID)
	}

	// Establish connection with timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", peer.NetworkAddress())
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeNetwork, "NET001", "failed to connect to peer").WithContext("peer_id", peerID).WithContext("address", peer.NetworkAddress())
	}

	m.connections[peerID] = conn
	m.logger.Info("Connected to peer", "peer_id", peerID, "username", peer.Username, "address", peer.NetworkAddress())

	// Send notification for peer connection
	if err := m.notificationMgr.NotifyPeerConnected(peer.Username); err != nil {
		m.logger.Debug("Failed to send peer connected notification", "error", err)
	}

	// Start handling messages from this connection
	m.wg.Add(1)
	go m.handleConnection(peerID, conn)

	return nil
}

// SendMessage sends a message to a connected peer
func (m *Manager) SendMessage(peerID, message string) error {
	m.mu.RLock()
	conn, exists := m.connections[peerID]
	m.mu.RUnlock()

	if !exists {
		return errors.ErrPeerNotConnected.WithContext("peer_id", peerID)
	}

	chatMsg := models.NewChatMessage(m.username, message)
	data, err := json.Marshal(chatMsg)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeMessage, "MSG005", "failed to marshal message").WithContext("peer_id", peerID)
	}

	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		m.logger.Error("Failed to send message", "peer_id", peerID, "error", err)
		// Remove the failed connection
		m.removeConnection(peerID)
		return errors.Wrap(err, errors.ErrorTypeNetwork, "NET003", "failed to send message to peer").WithContext("peer_id", peerID)
	}

	m.logger.Debug("Message sent", "peer_id", peerID, "message", message)
	return nil
}

// GetConnections returns all active connections
func (m *Manager) GetConnections() map[string]net.Conn {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]net.Conn, len(m.connections))
	for id, conn := range m.connections {
		result[id] = conn
	}
	return result
}

// IsConnected checks if connected to a specific peer
func (m *Manager) IsConnected(peerID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.connections[peerID]
	return exists
}

// acceptConnections accepts incoming TCP connections
func (m *Manager) acceptConnections() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		conn, err := m.listener.Accept()
		if err != nil {
			if m.ctx.Err() != nil {
				return // Context cancelled, expected error
			}
			m.logger.Error("Failed to accept connection", "error", err)
			continue
		}

		m.logger.Debug("Incoming connection accepted", "remote_addr", conn.RemoteAddr())

		// Handle the connection in a separate goroutine
		m.wg.Add(1)
		go m.handleIncomingConnection(conn)
	}
}

// handleIncomingConnection handles an incoming connection
func (m *Manager) handleIncomingConnection(conn net.Conn) {
	defer m.wg.Done()
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		var msg models.ChatMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			m.logger.Debug("Failed to unmarshal incoming message", "error", err)
			continue
		}

		m.msgHandler.HandleMessage(&msg)
	}

	if err := scanner.Err(); err != nil {
		m.logger.Debug("Connection scanner error", "error", err)
	}
}

// handleConnection handles an outgoing connection
func (m *Manager) handleConnection(peerID string, conn net.Conn) {
	defer m.wg.Done()
	defer m.removeConnection(peerID)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		var msg models.ChatMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			m.logger.Debug("Failed to unmarshal message from peer", "peer_id", peerID, "error", err)
			continue
		}

		m.msgHandler.HandleMessage(&msg)
	}

	if err := scanner.Err(); err != nil {
		m.logger.Debug("Connection scanner error", "peer_id", peerID, "error", err)
	}

	m.logger.Info("Connection to peer closed", "peer_id", peerID)

	// Send notification for peer disconnection
	if peer, exists := m.peerManager.GetPeer(peerID); exists {
		if err := m.notificationMgr.NotifyPeerDisconnected(peer.Username); err != nil {
			m.logger.Debug("Failed to send peer disconnected notification", "error", err)
		}
	}
}

// removeConnection safely removes a connection
func (m *Manager) removeConnection(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[peerID]; exists {
		conn.Close()
		delete(m.connections, peerID)
		m.logger.Debug("Connection removed", "peer_id", peerID)
		
		// Send notification for peer disconnection
		if peer, exists := m.peerManager.GetPeer(peerID); exists {
			if err := m.notificationMgr.NotifyPeerDisconnected(peer.Username); err != nil {
				m.logger.Debug("Failed to send peer disconnected notification", "error", err)
			}
		}
	}
}