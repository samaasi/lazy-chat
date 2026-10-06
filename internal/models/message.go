package models

import (
	"time"
)

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeDirect MessageType = "direct"
	MessageTypeGroup  MessageType = "group"
	MessageTypeSystem MessageType = "system"
)

// ChatMessage represents a chat message between peers or in groups.
//
// On the wire only ID, From, To, GroupID, Message, Type and Timestamp are
// sent. Delivered and Read are local bookkeeping and are never serialised,
// so a peer cannot pre-mark its own messages as read or delivered. Seq is the
// local storage sequence number used for pagination.
type ChatMessage struct {
	Seq       int64       `json:"-"`
	ID        string      `json:"id"`
	From      string      `json:"from"`
	To        string      `json:"to,omitempty"`       // For direct messages
	GroupID   string      `json:"group_id,omitempty"` // For group messages
	Message   string      `json:"message"`
	Type      MessageType `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Delivered bool        `json:"-"`
	Read      bool        `json:"-"`
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
	}
}

// IsDirectMessage checks if the message is a direct message
func (m *ChatMessage) IsDirectMessage() bool { return m.Type == MessageTypeDirect }

// IsGroupMessage checks if the message is a group message
func (m *ChatMessage) IsGroupMessage() bool { return m.Type == MessageTypeGroup }

// IsSystemMessage checks if the message is a system message
func (m *ChatMessage) IsSystemMessage() bool { return m.Type == MessageTypeSystem }
