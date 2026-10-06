package models

import (
	"time"
)

// Roles within a group. The creator is the only admin.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Invite lifecycle states.
const (
	InviteStatusPending  = "pending"
	InviteStatusAccepted = "accepted"
	InviteStatusDeclined = "declined"
	InviteStatusExpired  = "expired"
)

// Limits applied to group data, locally and on everything received.
const (
	MaxGroupNameLen        = 64
	MaxGroupDescriptionLen = 256
	MaxGroupMembers        = 256
)

// Group represents a chat group
type Group struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Members     map[string]string `json:"members"` // PeerID -> Username mapping (active members)
	IsActive    bool              `json:"is_active"`
}

// GroupMember represents a member of a group
type GroupMember struct {
	GroupID  string    `json:"group_id"`
	PeerID   string    `json:"peer_id"`
	Username string    `json:"username"`
	JoinedAt time.Time `json:"joined_at"`
	Role     string    `json:"role"` // RoleAdmin or RoleMember
	IsActive bool      `json:"is_active"`
}

// MemberRef names a group member inside an invitation snapshot.
type MemberRef struct {
	PeerID   string `json:"peer_id"`
	Username string `json:"username"`
}

// GroupInvite represents an invitation to join a group. The group details are
// a snapshot taken by the inviter, so the invitee can create the group
// locally when it accepts.
type GroupInvite struct {
	ID               string      `json:"id"`
	GroupID          string      `json:"group_id"`
	GroupName        string      `json:"group_name"`
	GroupDescription string      `json:"group_description"`
	GroupCreator     string      `json:"group_creator"`
	InviterID        string      `json:"inviter_id"`
	InviteeID        string      `json:"invitee_id"`
	CreatedAt        time.Time   `json:"created_at"`
	ExpiresAt        time.Time   `json:"expires_at"`
	Status           string      `json:"status"`
	Members          []MemberRef `json:"members"`
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

// AddMember adds a member to the group
func (g *Group) AddMember(peerID, username string) {
	if g.Members == nil {
		g.Members = make(map[string]string)
	}
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
func (g *Group) GetMemberCount() int { return len(g.Members) }

// IsExpired checks if the invitation has expired
func (gi *GroupInvite) IsExpired(now time.Time) bool { return now.After(gi.ExpiresAt) }
