package messaging

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
)

// Handler implements the MessageHandler interface
type Handler struct {
	logger               interfaces.Logger
	callback             func(*models.ChatMessage)
	notificationMgr      interfaces.NotificationManager
	messageStorage       storage.MessageStorage
	groupService         *services.GroupService
	groupMessageCallback func(*models.ChatMessage)
	idGenerator          interfaces.IDGenerator
	netManager           interfaces.NetworkManager
}

// NewHandler creates a new message handler
func NewHandler(logger interfaces.Logger, notificationMgr interfaces.NotificationManager, messageStorage storage.MessageStorage, groupService *services.GroupService, idGenerator interfaces.IDGenerator, netManager interfaces.NetworkManager) *Handler {
	return &Handler{
		logger:          logger,
		notificationMgr: notificationMgr,
		messageStorage:  messageStorage,
		groupService:    groupService,
		idGenerator:     idGenerator,
		netManager:      netManager,
	}
}

// HandleMessage processes incoming messages
func (h *Handler) HandleMessage(msg *models.ChatMessage) {
	if err := h.ValidateMessage(msg); err != nil {
		h.logger.Error("Invalid message received", "error", err)
		return
	}

	// Store the received message
	if h.messageStorage != nil {
		err := h.messageStorage.SaveMessage(context.Background(), msg)
		if err != nil {
			h.logger.Error("Failed to store received message", "error", err)
		}
	}

	h.logger.Info("Message received", "from", msg.From, "content", msg.Message)

	// Handle based on message type
	if msg.IsGroupMessage() {
		h.handleGroupMessage(msg)
	} else {
		h.handleDirectMessage(msg)
	}
}

// handleDirectMessage processes direct messages
func (h *Handler) handleDirectMessage(msg *models.ChatMessage) {
	if h.callback != nil {
		h.callback(msg)
	}

	// Display the message to the user
	h.displayMessage(msg)

	if h.notificationMgr != nil {
		if err := h.notificationMgr.NotifyMessageReceived(msg.From, msg.Message); err != nil {
			h.logger.Debug("Failed to send notification", "error", err)
		}
	}
}

// handleGroupMessage processes group messages
func (h *Handler) handleGroupMessage(msg *models.ChatMessage) {
	// Verify the sender is a member of the group
	if h.groupService != nil && msg.GroupID != "" {
		members, err := h.groupService.GetGroupMembers(msg.GroupID)
		if err != nil {
			h.logger.Error("Failed to verify group membership", "error", err)
			return
		}

		// Check if sender is a member
		isMember := false
		for _, member := range members {
			if member.PeerID == msg.From {
				isMember = true
				break
			}
		}

		if !isMember {
			h.logger.Warn("Received group message from non-member", "from", msg.From, "groupID", msg.GroupID)
			return
		}
	}

	if h.groupMessageCallback != nil {
		h.groupMessageCallback(msg)
	}

	// Display the message to the user
	h.displayMessage(msg)

	if h.notificationMgr != nil {
		if err := h.notificationMgr.NotifyMessageReceived(msg.From, fmt.Sprintf("Group: %s", msg.Message)); err != nil {
			h.logger.Debug("Failed to send group notification", "error", err)
		}
	}
}

// displayMessage formats and displays a chat message
func (h *Handler) displayMessage(msg *models.ChatMessage) {
	// Format timestamp for display
	timestamp := msg.Timestamp.Format("15:04:05")

	// Display the formatted message
	fmt.Printf("[%s] %s: %s\n", timestamp, msg.From, msg.Message)
}

// SendMessage sends a message to a specific peer
func (h *Handler) SendMessage(to, content string) error {
	message := models.NewChatMessage(h.idGenerator.GenerateID(), "", to, content)

	if err := h.ValidateMessage(message); err != nil {
		return err
	}

	// Store the message
	if h.messageStorage != nil {
		err := h.messageStorage.SaveMessage(context.Background(), message)
		if err != nil {
			h.logger.Debug("Failed to store message", "error", err)
		}
	}

	h.logger.Debug("Sending message", "to", to, "content", content)

	// Here you would implement the actual network sending logic
	// For now, we'll just log it
	h.logger.Debug("Message sent successfully")

	return nil
}

// SendGroupMessage sends a message to a group
func (h *Handler) SendGroupMessage(groupID, content string) error {
	message := models.NewChatMessage(h.idGenerator.GenerateID(), "", groupID, content)
	message.Type = models.MessageTypeGroup
	message.GroupID = groupID

	if err := h.ValidateMessage(message); err != nil {
		return err
	}

	// Get group members
	if h.groupService == nil {
		return fmt.Errorf("group service not available")
	}

	members, err := h.groupService.GetGroupMembers(groupID)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}

	if len(members) == 0 {
		return fmt.Errorf("no members found in group %s", groupID)
	}

	// Store the message
	if h.messageStorage != nil {
		err := h.messageStorage.SaveMessage(context.Background(), message)
		if err != nil {
			h.logger.Debug("Failed to store group message", "error", err)
		}
	}

	h.logger.Debug("Sending group message", "groupID", groupID, "content", content, "member_count", len(members))

	// Send message to all group members via network manager
	if h.netManager != nil {
		// Extract peer IDs from group members
		var peerIDs []string
		for _, member := range members {
			// Skip sending to self
			if member.PeerID != message.From {
				peerIDs = append(peerIDs, member.PeerID)
			}
		}

		if len(peerIDs) > 0 {
			err = h.netManager.SendGroupMessage(peerIDs, message)
			if err != nil {
				h.logger.Error("Failed to send group message", "groupID", groupID, "error", err)
				return fmt.Errorf("failed to send group message: %w", err)
			}
		}
	}

	h.logger.Debug("Group message sent successfully", "groupID", groupID)
	return nil
}

// SetMessageCallback sets a callback for message processing
func (h *Handler) SetMessageCallback(callback func(*models.ChatMessage)) {
	h.callback = callback
}

// SetGroupMessageCallback sets the callback function for received group messages
func (h *Handler) SetGroupMessageCallback(callback func(*models.ChatMessage)) {
	h.groupMessageCallback = callback
}

// ValidateMessage checks if a message is valid
func (h *Handler) ValidateMessage(msg *models.ChatMessage) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	if msg.From == "" {
		return fmt.Errorf("message sender is empty")
	}

	// Validate message content
	if strings.TrimSpace(msg.Message) == "" {
		return errors.ErrMessageValidation.WithContext("reason", "empty_content")
	}

	if len(msg.Message) > 1000 {
		return errors.ErrMessageValidation.WithContext("reason", "content_too_long").WithContext("length", len(msg.Message)).WithContext("max_length", 1000)
	}

	if msg.Timestamp.IsZero() {
		return fmt.Errorf("message timestamp is invalid")
	}

	// Check if timestamp is too far in the future (more than 1 minute)
	if msg.Timestamp.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("message timestamp is too far in the future")
	}

	// Check if timestamp is too old (more than 24 hours)
	if msg.Timestamp.Before(time.Now().Add(-24 * time.Hour)) {
		return fmt.Errorf("message timestamp is too old")
	}

	return nil
}
