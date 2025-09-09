package services

import (
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
)

type MessageHistoryService struct {
	messageStorage storage.MessageStorage
	groupStorage   storage.GroupStorage
}

func NewMessageHistoryService(messageStorage storage.MessageStorage, groupStorage storage.GroupStorage) *MessageHistoryService {
	return &MessageHistoryService{
		messageStorage: messageStorage,
		groupStorage:   groupStorage,
	}
}

// GetDirectMessageHistory retrieves message history between two peers
func (mhs *MessageHistoryService) GetDirectMessageHistory(peerID1, peerID2 string, limit int, offset int) ([]*models.ChatMessage, error) {
	if peerID1 == "" || peerID2 == "" {
		return nil, fmt.Errorf("peer IDs cannot be empty")
	}

	messages, err := mhs.messageStorage.GetDirectMessages(peerID1, peerID2, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get direct messages: %w", err)
	}

	return messages, nil
}

// GetGroupMessageHistory retrieves message history for a group
func (mhs *MessageHistoryService) GetGroupMessageHistory(groupID string, limit int, offset int) ([]*models.ChatMessage, error) {
	if groupID == "" {
		return nil, fmt.Errorf("group ID cannot be empty")
	}

	// Verify group exists
	group, err := mhs.groupStorage.GetGroup(groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify group: %w", err)
	}
	if group == nil {
		return nil, fmt.Errorf("group not found")
	}

	messages, err := mhs.messageStorage.GetGroupMessages(groupID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get group messages: %w", err)
	}

	return messages, nil
}

// GetRecentMessages retrieves recent messages for a user across all conversations
func (mhs *MessageHistoryService) GetRecentMessages(userID string, limit int) ([]*models.ChatMessage, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	messages, err := mhs.messageStorage.GetRecentMessages(userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent messages: %w", err)
	}

	return messages, nil
}

// SearchMessages searches for messages containing specific text
func (mhs *MessageHistoryService) SearchMessages(userID, query string, limit int, offset int) ([]*models.ChatMessage, error) {
	if userID == "" || query == "" {
		return nil, fmt.Errorf("user ID and query cannot be empty")
	}

	messages, err := mhs.messageStorage.SearchMessages(userID, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}

	return messages, nil
}

// GetMessagesByDateRange retrieves messages within a specific date range
func (mhs *MessageHistoryService) GetMessagesByDateRange(userID string, startDate, endDate time.Time, limit int, offset int) ([]*models.ChatMessage, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	messages, err := mhs.messageStorage.GetMessagesByDateRange(userID, startDate, endDate, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages by date range: %w", err)
	}

	return messages, nil
}

// GetUnreadMessages retrieves unread messages for a user
func (mhs *MessageHistoryService) GetUnreadMessages(userID string) ([]*models.ChatMessage, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	messages, err := mhs.messageStorage.GetUnreadMessages(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get unread messages: %w", err)
	}

	return messages, nil
}

// MarkMessageAsRead marks a specific message as read
func (mhs *MessageHistoryService) MarkMessageAsRead(messageID, userID string) error {
	if messageID == "" || userID == "" {
		return fmt.Errorf("message ID and user ID cannot be empty")
	}

	err := mhs.messageStorage.MarkMessageAsRead(messageID, userID)
	if err != nil {
		return fmt.Errorf("failed to mark message as read: %w", err)
	}

	return nil
}

// MarkAllMessagesAsRead marks all messages in a conversation as read
func (mhs *MessageHistoryService) MarkAllMessagesAsRead(userID, conversationID string, isGroup bool) error {
	if userID == "" || conversationID == "" {
		return fmt.Errorf("user ID and conversation ID cannot be empty")
	}

	err := mhs.messageStorage.MarkAllMessagesAsRead(userID, conversationID, isGroup)
	if err != nil {
		return fmt.Errorf("failed to mark all messages as read: %w", err)
	}

	return nil
}

// DeleteMessage deletes a message (soft delete - marks as deleted)
func (mhs *MessageHistoryService) DeleteMessage(messageID, userID string) error {
	if messageID == "" || userID == "" {
		return fmt.Errorf("message ID and user ID cannot be empty")
	}

	// Get the message to verify ownership
	message, err := mhs.messageStorage.GetMessage(messageID)
	if err != nil {
		return fmt.Errorf("failed to get message: %w", err)
	}

	if message == nil {
		return fmt.Errorf("message not found")
	}

	// Only allow deletion by the sender
	if message.From != userID {
		return fmt.Errorf("only the sender can delete their own messages")
	}

	err = mhs.messageStorage.DeleteMessage(messageID)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	return nil
}

// GetConversationList retrieves a list of conversations for a user
func (mhs *MessageHistoryService) GetConversationList(userID string) ([]ConversationSummary, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Get direct conversations
	directConversations, err := mhs.messageStorage.GetDirectConversations(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get direct conversations: %w", err)
	}

	// Get group conversations
	groupConversations, err := mhs.messageStorage.GetGroupConversations(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group conversations: %w", err)
	}

	// Combine and return
	var conversations []ConversationSummary
	conversations = append(conversations, directConversations...)
	conversations = append(conversations, groupConversations...)

	return conversations, nil
}

// ConversationSummary represents a summary of a conversation
type ConversationSummary struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"` // "direct" or "group"
	LastMessage     string    `json:"last_message"`
	LastMessageTime time.Time `json:"last_message_time"`
	UnreadCount     int       `json:"unread_count"`
	Participants    []string  `json:"participants,omitempty"`
}

// ExportMessageHistory exports message history to a specific format
func (mhs *MessageHistoryService) ExportMessageHistory(userID string, conversationID string, isGroup bool, format string) ([]byte, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	var messages []*models.ChatMessage
	var err error

	if isGroup {
		messages, err = mhs.GetGroupMessageHistory(conversationID, 0, 0) // Get all messages
	} else {
		messages, err = mhs.GetDirectMessageHistory(userID, conversationID, 0, 0) // Get all messages
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get messages for export: %w", err)
	}

	// For now, just return a simple text format
	// In a real implementation, you might support JSON, CSV, etc.
	var result string
	for _, msg := range messages {
		result += fmt.Sprintf("[%s] %s: %s\n", msg.Timestamp.Format("2006-01-02 15:04:05"), msg.From, msg.Content)
	}

	return []byte(result), nil
}