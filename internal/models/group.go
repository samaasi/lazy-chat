package models

import (
	"time"
)

// Group represents a chat group
type Group struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	CreatedBy   string            `json:"created_by" db:"created_by"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	Members     map[string]string `json:"members" db:"-"` // PeerID -> Username mapping
	IsActive    bool              `json:"is_active" db:"is_active"`
}

// GroupMember represents a member of a group
type GroupMember struct {
	GroupID   string    `json:"group_id" db:"group_id"`
	PeerID    string    `json:"peer_id" db:"peer_id"`
	Username  string    `json:"username" db:"username"`
	JoinedAt  time.Time `json:"joined_at" db:"joined_at"`
	Role      string    `json:"role" db:"role"` // "admin", "member"
	IsActive  bool      `json:"is_active" db:"is_active"`
}

// GroupInvite represents an invitation to join a group
type GroupInvite struct {
	ID        string    `json:"id" db:"id"`
	GroupID   string    `json:"group_id" db:"group_id"`
	InviterID string    `json:"inviter_id" db:"inviter_id"`
	InviteeID string    `json:"invitee_id" db:"invitee_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Status    string    `json:"status" db:"status"` // "pending", "accepted", "declined", "expired"
}

// NewGroup creates a new group
func NewGroup(id, name, description, createdBy string) *Group {
	now := time.Now()
	return &Group{
		ID:          id,
		Name:        name,
		Description: description,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
		Members:     make(map[string]string),
		IsActive:    true,
	}
}

// NewGroupMember creates a new group member
func NewGroupMember(groupID, peerID, username, role string) *GroupMember {
	return &GroupMember{
		GroupID:  groupID,
		PeerID:   peerID,
		Username: username,
		JoinedAt: time.Now(),
		Role:     role,
		IsActive: true,
	}
}

// NewGroupInvite creates a new group invitation
func NewGroupInvite(id, groupID, inviterID, inviteeID string, expiresAt time.Time) *GroupInvite {
	return &GroupInvite{
		ID:        id,
		GroupID:   groupID,
		InviterID: inviterID,
		InviteeID: inviteeID,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Status:    "pending",
	}
}

// AddMember adds a member to the group
func (g *Group) AddMember(peerID, username string) {
	g.Members[peerID] = username
	g.UpdatedAt = time.Now()
}

// RemoveMember removes a member from the group
func (g *Group) RemoveMember(peerID string) {
	delete(g.Members, peerID)
	g.UpdatedAt = time.Now()
}

// HasMember checks if a peer is a member of the group
func (g *Group) HasMember(peerID string) bool {
	_, exists := g.Members[peerID]
	return exists
}

// GetMemberCount returns the number of active members
func (g *Group) GetMemberCount() int {
	return len(g.Members)
}

// IsExpired checks if the invitation has expired
func (gi *GroupInvite) IsExpired() bool {
	return time.Now().After(gi.ExpiresAt)
}

// Accept marks the invitation as accepted
func (gi *GroupInvite) Accept() {
	gi.Status = "accepted"
}

// Decline marks the invitation as declined
func (gi *GroupInvite) Decline() {
	gi.Status = "declined"
}

// Expire marks the invitation as expired
func (gi *GroupInvite) Expire() {
	gi.Status = "expired"
}