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

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeDirect MessageType = "direct"
	MessageTypeGroup  MessageType = "group"
	MessageTypeSystem MessageType = "system"
)

// ChatMessage represents a chat message between peers or in groups
type ChatMessage struct {
	ID        string      `json:"id" db:"id"`
	From      string      `json:"from" db:"from_peer_id"`
	To        string      `json:"to,omitempty" db:"to_peer_id"` // For direct messages
	GroupID   string      `json:"group_id,omitempty" db:"group_id"` // For group messages
	Message   string      `json:"message" db:"content"`
	Type      MessageType `json:"type" db:"message_type"`
	Timestamp time.Time   `json:"timestamp" db:"created_at"`
	Delivered bool        `json:"delivered" db:"delivered"`
	Read      bool        `json:"read" db:"read_status"`
}

// NewChatMessage creates a new direct chat message with current timestamp
func NewChatMessage(id, from, to, message string) *ChatMessage {
	return &ChatMessage{
		ID:        id,
		From:      from,
		To:        to,
		Message:   message,
		Type:      MessageTypeDirect,
		Timestamp: time.Now(),
		Delivered: false,
		Read:      false,
	}
}

// NewGroupMessage creates a new group chat message with current timestamp
func NewGroupMessage(id, from, groupID, message string) *ChatMessage {
	return &ChatMessage{
		ID:        id,
		From:      from,
		GroupID:   groupID,
		Message:   message,
		Type:      MessageTypeGroup,
		Timestamp: time.Now(),
		Delivered: false,
		Read:      false,
	}
}

// NewSystemMessage creates a new system message
func NewSystemMessage(id, message string) *ChatMessage {
	return &ChatMessage{
		ID:        id,
		From:      "system",
		Message:   message,
		Type:      MessageTypeSystem,
		Timestamp: time.Now(),
		Delivered: true,
		Read:      false,
	}
}

// IsDirectMessage checks if the message is a direct message
func (m *ChatMessage) IsDirectMessage() bool {
	return m.Type == MessageTypeDirect
}

// IsGroupMessage checks if the message is a group message
func (m *ChatMessage) IsGroupMessage() bool {
	return m.Type == MessageTypeGroup
}

// IsSystemMessage checks if the message is a system message
func (m *ChatMessage) IsSystemMessage() bool {
	return m.Type == MessageTypeSystem
}

// MarkAsDelivered marks the message as delivered
func (m *ChatMessage) MarkAsDelivered() {
	m.Delivered = true
}

// MarkAsRead marks the message as read
func (m *ChatMessage) MarkAsRead() {
	m.Read = true
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