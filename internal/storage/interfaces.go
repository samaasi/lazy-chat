package storage

import (
	"context"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

// MessageStorage defines the interface for message persistence
type MessageStorage interface {
	// SaveMessage stores a message in the database
	SaveMessage(ctx context.Context, msg *models.ChatMessage) error
	// GetMessages retrieves messages with pagination
	GetMessages(ctx context.Context, limit, offset int) ([]*models.ChatMessage, error)
	// GetDirectMessages retrieves direct messages between two peers
	GetDirectMessages(ctx context.Context, peerID1, peerID2 string, limit, offset int) ([]*models.ChatMessage, error)
	// GetGroupMessages retrieves messages from a specific group
	GetGroupMessages(ctx context.Context, groupID string, limit, offset int) ([]*models.ChatMessage, error)
	// GetMessagesByTimeRange retrieves messages within a time range
	GetMessagesByTimeRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*models.ChatMessage, error)
	// MarkMessageAsDelivered marks a message as delivered
	MarkMessageAsDelivered(ctx context.Context, messageID string) error
	// MarkMessageAsRead marks a message as read
	MarkMessageAsRead(ctx context.Context, messageID string) error
	// DeleteMessage deletes a message (soft delete)
	DeleteMessage(ctx context.Context, messageID string) error
	// SearchMessages searches for messages containing specific text
	SearchMessages(ctx context.Context, query string, limit, offset int) ([]*models.ChatMessage, error)
}

// GroupStorage defines the interface for group persistence
type GroupStorage interface {
	// CreateGroup creates a new group
	CreateGroup(ctx context.Context, group *models.Group) error
	// GetGroup retrieves a group by ID
	GetGroup(ctx context.Context, groupID string) (*models.Group, error)
	// GetGroupsByMember retrieves all groups a peer is a member of
	GetGroupsByMember(ctx context.Context, peerID string) ([]*models.Group, error)
	// UpdateGroup updates group information
	UpdateGroup(ctx context.Context, group *models.Group) error
	// DeleteGroup deletes a group (soft delete)
	DeleteGroup(ctx context.Context, groupID string) error
	// AddGroupMember adds a member to a group
	AddGroupMember(ctx context.Context, member *models.GroupMember) error
	// RemoveGroupMember removes a member from a group
	RemoveGroupMember(ctx context.Context, groupID, peerID string) error
	// GetGroupMembers retrieves all members of a group
	GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMember, error)
	// IsGroupMember checks if a peer is a member of a group
	IsGroupMember(ctx context.Context, groupID, peerID string) (bool, error)
}

// InviteStorage defines the interface for group invitation persistence
type InviteStorage interface {
	// CreateInvite creates a new group invitation
	CreateInvite(ctx context.Context, invite *models.GroupInvite) error
	// GetInvite retrieves an invitation by ID
	GetInvite(ctx context.Context, inviteID string) (*models.GroupInvite, error)
	// GetInvitesByInvitee retrieves all invitations for a specific invitee
	GetInvitesByInvitee(ctx context.Context, inviteeID string) ([]*models.GroupInvite, error)
	// GetInvitesByGroup retrieves all invitations for a specific group
	GetInvitesByGroup(ctx context.Context, groupID string) ([]*models.GroupInvite, error)
	// UpdateInviteStatus updates the status of an invitation
	UpdateInviteStatus(ctx context.Context, inviteID, status string) error
	// DeleteInvite deletes an invitation
	DeleteInvite(ctx context.Context, inviteID string) error
	// CleanupExpiredInvites removes expired invitations
	CleanupExpiredInvites(ctx context.Context) error
}

// Database defines the main database interface
type Database interface {
	MessageStorage
	GroupStorage
	InviteStorage
	// Connect establishes database connection
	Connect(ctx context.Context) error
	// Close closes database connection
	Close() error
	// Migrate runs database migrations
	Migrate(ctx context.Context) error
	// Health checks database health
	Health(ctx context.Context) error
}
