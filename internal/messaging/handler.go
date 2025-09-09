package messaging

import (
	"fmt"
	"strings"
	"time"

	"github.com/lazy-chat/internal/errors"
	"github.com/lazy-chat/internal/interfaces"
	"github.com/lazy-chat/internal/models"
)

// Handler implements the MessageHandler interface
type Handler struct {
	logger       interfaces.Logger
	callback     func(*models.ChatMessage)
	notificationMgr interfaces.NotificationManager
}

// NewHandler creates a new message handler
func NewHandler(logger interfaces.Logger, notificationMgr interfaces.NotificationManager) *Handler {
	return &Handler{
		logger:          logger,
		notificationMgr: notificationMgr,
	}
}

// HandleMessage processes incoming chat messages
func (h *Handler) HandleMessage(msg *models.ChatMessage) {
	if msg == nil {
		h.logger.Debug("Received nil message")
		return
	}

	// Log the message for debugging
	h.logger.Debug("Message received", "from", msg.From, "content", msg.Message, "timestamp", msg.Timestamp)

	// Call callback if set
	if h.callback != nil {
		h.callback(msg)
	}

	// Display the message to the user
	h.displayMessage(msg)
	
	// Send OS notification for received message
	if err := h.notificationMgr.NotifyMessageReceived(msg.From, msg.Message); err != nil {
		h.logger.Debug("Failed to send notification", "error", err)
	}
}

// displayMessage formats and displays a chat message
func (h *Handler) displayMessage(msg *models.ChatMessage) {
	// Format timestamp for display
	timestamp := msg.Timestamp.Format("15:04:05")
	
	// Display the formatted message
	fmt.Printf("[%s] %s: %s\n", timestamp, msg.From, msg.Message)
}

// SendMessage creates and formats a message for sending
func (h *Handler) SendMessage(from, content string) *models.ChatMessage {
	msg := models.NewChatMessage(from, content)
	h.logger.Debug("Message created for sending", "from", from, "content", content)
	return msg
}

// SetMessageCallback sets a callback for message processing
func (h *Handler) SetMessageCallback(callback func(*models.ChatMessage)) {
	h.callback = callback
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