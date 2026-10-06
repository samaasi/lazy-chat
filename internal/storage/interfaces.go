package storage

import (
	"context"
	"errors"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

// ErrNotFound is returned when a requested record does not exist (or the
// caller is not allowed to see it).
var ErrNotFound = errors.New("not found")

// ErrInviteUnusable is returned when accepting an invite that is expired,
// already answered, or addressed to someone else.
var ErrInviteUnusable = errors.New("invitation is expired, already answered or not addressed to you")

// Page selects a window of results, newest first, using keyset pagination:
// pass the Seq of the oldest message already seen as Before to get the next
// page. Before == 0 starts from the newest message. Unlike OFFSET this stays
// fast and stable while new messages arrive.
type Page struct {
	Limit  int
	Before int64
}

// MessageStorage defines the interface for message persistence
type MessageStorage interface {
	// SaveMessage stores a message. It reports inserted=false (and no error)
	// when the sender already used this message ID, so replays and duplicate
	// deliveries are harmless. msg.Seq is set when inserted.
	SaveMessage(ctx context.Context, msg *models.ChatMessage) (inserted bool, err error)
	// GetMessages retrieves the newest messages first.
	GetMessages(ctx context.Context, p Page) ([]*models.ChatMessage, error)
	// GetDirectMessages retrieves direct messages between two peers
	GetDirectMessages(ctx context.Context, peerID1, peerID2 string, p Page) ([]*models.ChatMessage, error)
	// GetGroupMessages retrieves messages from a specific group
	GetGroupMessages(ctx context.Context, groupID string, p Page) ([]*models.ChatMessage, error)
	// GetMessagesByTimeRange retrieves messages within a time range
	GetMessagesByTimeRange(ctx context.Context, start, end time.Time, p Page) ([]*models.ChatMessage, error)
	// MarkMessageAsDelivered marks a message sent by fromPeerID as delivered
	MarkMessageAsDelivered(ctx context.Context, fromPeerID, messageID string) error
	// MarkMessageAsRead marks a message as read, if userID is its recipient
	// (directly or as a member of its group). ErrNotFound otherwise.
	MarkMessageAsRead(ctx context.Context, userID, messageID string) error
	// DeleteMessage soft-deletes a message userID sent or may read.
	// ErrNotFound if there is no such message for that user.
	DeleteMessage(ctx context.Context, userID, messageID string) error
	// SearchMessages searches for messages containing specific text
	SearchMessages(ctx context.Context, query string, p Page) ([]*models.ChatMessage, error)
}

// GroupStorage defines the interface for group persistence
type GroupStorage interface {
	// CreateGroup atomically stores a group and its initial members
	// (group.Members); group.CreatedBy becomes the admin.
	CreateGroup(ctx context.Context, group *models.Group) error
	// GetGroup retrieves an active group and its active members.
	GetGroup(ctx context.Context, groupID string) (*models.Group, error)
	// GetGroupsByMember retrieves all groups a peer is an active member of
	GetGroupsByMember(ctx context.Context, peerID string) ([]*models.Group, error)
	// UpdateGroup updates group name and description
	UpdateGroup(ctx context.Context, group *models.Group) error
	// DeleteGroup deletes a group (soft delete)
	DeleteGroup(ctx context.Context, groupID string) error
	// AddGroupMember adds (or re-activates) a member
	AddGroupMember(ctx context.Context, member *models.GroupMember) error
	// RemoveGroupMember deactivates a member; history is kept
	RemoveGroupMember(ctx context.Context, groupID, peerID string) error
	// GetGroupMembers retrieves the active members of a group
	GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMember, error)
	// IsGroupMember checks if a peer is an active member of an active group
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
	// CountPendingInvitesFrom counts unexpired pending invites received from a peer
	CountPendingInvitesFrom(ctx context.Context, inviterID, inviteeID string, now time.Time) (int, error)
	// UpdateInviteStatus updates the status of an invitation
	UpdateInviteStatus(ctx context.Context, inviteID, status string) error
	// DeleteInvite deletes an invitation
	DeleteInvite(ctx context.Context, inviteID string) error
	// CleanupExpiredInvites marks pending invites past their expiry as expired
	CleanupExpiredInvites(ctx context.Context, now time.Time) (int64, error)
	// AcceptInvite atomically validates a pending invite addressed to
	// inviteeID, creates (or re-activates) the group with the snapshot
	// members plus the invitee (stored under inviteeName), and marks the invite accepted.
	AcceptInvite(ctx context.Context, inviteID, inviteeID, inviteeName string, now time.Time) (*models.Group, error)
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
