package models

import (
	"time"
)

// DiscoveryMessage represents a peer discovery broadcast message
type DiscoveryMessage struct {
	Type     string `json:"type"`
	PeerID   string `json:"peer_id"`
	Username string `json:"username"`
	Port     int    `json:"port"`
}

// ChatMessage represents a chat message between peers
type ChatMessage struct {
	From      string    `json:"from"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// NewChatMessage creates a new chat message with current timestamp
func NewChatMessage(from, message string) *ChatMessage {
	return &ChatMessage{
		From:      from,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// NewDiscoveryMessage creates a new discovery announcement message
func NewDiscoveryMessage(peerID, username string, port int) *DiscoveryMessage {
	return &DiscoveryMessage{
		Type:     "announce",
		PeerID:   peerID,
		Username: username,
		Port:     port,
	}
}