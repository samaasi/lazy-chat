package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
)

// maxExportMessages bounds a single export so it cannot exhaust memory or disk.
const maxExportMessages = 200_000

// MessageHistoryService reads and manages the local peer's message history.
// Every operation is scoped to the local peer: it can only see conversations
// it took part in and groups it belongs to.
type MessageHistoryService struct {
	messages storage.MessageStorage
	groups   storage.GroupStorage
	selfID   string
}

// NewMessageHistoryService creates the history service for the local peer.
func NewMessageHistoryService(messages storage.MessageStorage, groups storage.GroupStorage, selfID string) *MessageHistoryService {
	return &MessageHistoryService{messages: messages, groups: groups, selfID: selfID}
}

// Chronological reverses a newest-first page into reading order.
func Chronological(msgs []*models.ChatMessage) []*models.ChatMessage {
	out := slices.Clone(msgs)
	slices.Reverse(out)
	return out
}

// GetDirectMessageHistory retrieves a page of the conversation with peerID, newest first.
func (s *MessageHistoryService) GetDirectMessageHistory(ctx context.Context, peerID string, p storage.Page) ([]*models.ChatMessage, error) {
	if peerID == "" {
		return nil, errors.New("peer ID cannot be empty")
	}
	msgs, err := s.messages.GetDirectMessages(ctx, s.selfID, peerID, p)
	if err != nil {
		return nil, fmt.Errorf("failed to get direct messages: %w", err)
	}
	return msgs, nil
}

// GetGroupMessageHistory retrieves a page of a group's messages, newest first.
// The local peer must be a member.
func (s *MessageHistoryService) GetGroupMessageHistory(ctx context.Context, groupID string, p storage.Page) ([]*models.ChatMessage, error) {
	if groupID == "" {
		return nil, errors.New("group ID cannot be empty")
	}
	member, err := s.groups.IsGroupMember(ctx, groupID, s.selfID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify group: %w", err)
	}
	if !member {
		return nil, ErrNotMember
	}
	msgs, err := s.messages.GetGroupMessages(ctx, groupID, p)
	if err != nil {
		return nil, fmt.Errorf("failed to get group messages: %w", err)
	}
	return msgs, nil
}

// GetRecentMessages retrieves the newest messages across all conversations.
func (s *MessageHistoryService) GetRecentMessages(ctx context.Context, limit int) ([]*models.ChatMessage, error) {
	msgs, err := s.messages.GetMessages(ctx, storage.Page{Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("failed to get recent messages: %w", err)
	}
	return msgs, nil
}

// SearchMessages searches for messages containing specific text.
func (s *MessageHistoryService) SearchMessages(ctx context.Context, query string, p storage.Page) ([]*models.ChatMessage, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("query cannot be empty")
	}
	msgs, err := s.messages.SearchMessages(ctx, query, p)
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}
	return msgs, nil
}

// GetMessagesByDateRange retrieves messages within a specific date range.
func (s *MessageHistoryService) GetMessagesByDateRange(ctx context.Context, start, end time.Time, p storage.Page) ([]*models.ChatMessage, error) {
	if start.After(end) {
		return nil, errors.New("start date cannot be after end date")
	}
	msgs, err := s.messages.GetMessagesByTimeRange(ctx, start, end, p)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages by date range: %w", err)
	}
	return msgs, nil
}

// MarkMessageAsRead marks a message addressed to the local peer as read.
func (s *MessageHistoryService) MarkMessageAsRead(ctx context.Context, messageID string) error {
	if messageID == "" {
		return errors.New("message ID cannot be empty")
	}
	if err := s.messages.MarkMessageAsRead(ctx, s.selfID, messageID); err != nil {
		return fmt.Errorf("failed to mark message as read: %w", err)
	}
	return nil
}

// DeleteMessage removes a message from the local history. It refuses
// messages that do not belong to one of the local peer's conversations.
func (s *MessageHistoryService) DeleteMessage(ctx context.Context, messageID string) error {
	if messageID == "" {
		return errors.New("message ID cannot be empty")
	}
	if err := s.messages.DeleteMessage(ctx, s.selfID, messageID); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return nil
}

// ExportFormats lists the formats accepted by ExportConversation.
var ExportFormats = []string{"text", "json"}

// ExportConversation streams a whole conversation to w, oldest first, as
// "text" or "json" (one JSON object per line). The conversation is read in
// pages, so memory use stays flat however long it is.
func (s *MessageHistoryService) ExportConversation(ctx context.Context, w io.Writer, conversationID string, isGroup bool, format string) error {
	if !slices.Contains(ExportFormats, format) {
		return fmt.Errorf("unknown export format %q (use %s)", format, strings.Join(ExportFormats, " or "))
	}

	// Collect pages newest-first, then write them out oldest-first.
	var pages [][]*models.ChatMessage
	total := 0
	page := storage.Page{Limit: 500}
	for {
		var (
			batch []*models.ChatMessage
			err   error
		)
		if isGroup {
			batch, err = s.GetGroupMessageHistory(ctx, conversationID, page)
		} else {
			batch, err = s.GetDirectMessageHistory(ctx, conversationID, page)
		}
		if err != nil {
			return fmt.Errorf("failed to read messages for export: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		pages = append(pages, batch)
		total += len(batch)
		if total > maxExportMessages {
			return fmt.Errorf("conversation has more than %d messages; export a narrower range", maxExportMessages)
		}
		page.Before = batch[len(batch)-1].Seq
	}

	enc := json.NewEncoder(w)
	for i := len(pages) - 1; i >= 0; i-- {
		for _, msg := range Chronological(pages[i]) {
			if format == "json" {
				if err := enc.Encode(msg); err != nil {
					return err
				}
				continue
			}
			if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", msg.Timestamp.Format("2006-01-02 15:04:05"), msg.From, strings.ReplaceAll(msg.Message, "\n", " ")); err != nil {
				return err
			}
		}
	}
	return nil
}
