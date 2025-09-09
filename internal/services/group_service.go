package services

import import (
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
)

type GroupService struct {
	groupStorage  storage.GroupStorage
	inviteStorage storage.InviteStorage
	currentPeerID string
}

func NewGroupService(groupStorage storage.GroupStorage, inviteStorage storage.InviteStorage, peerID string) *GroupService {
	return &GroupService{
		groupStorage:  groupStorage,
		inviteStorage: inviteStorage,
		currentPeerID: peerID,
	}
}

// CreateGroup creates a new group with the current peer as admin
func (gs *GroupService) CreateGroup(name, description string) (*models.Group, error) {
	if name == "" {
		return nil, errors.New("group name cannot be empty")
	}

	group := &models.Group{
		ID:          generateGroupID(),
		Name:        name,
		Description: description,
		AdminID:     gs.currentPeerID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Add creator as first member
	group.AddMember(gs.currentPeerID, models.RoleAdmin)

	err := gs.groupStorage.CreateGroup(group)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return group, nil
}

// JoinGroup allows a peer to join a group (if public or invited)
func (gs *GroupService) JoinGroup(groupID, peerID string) error {
	group, err := gs.groupStorage.GetGroup(groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return errors.New("group not found")
	}

	// Check if already a member
	if group.IsMember(peerID) {
		return errors.New("already a member of this group")
	}

	// For private groups, check if there's a valid invitation
	if !group.IsPublic {
		invite, err := gs.inviteStorage.GetInvite(groupID, peerID)
		if err != nil {
			return fmt.Errorf("failed to check invitation: %w", err)
		}
		if invite == nil || invite.IsExpired() {
			return errors.New("no valid invitation found")
		}
	}

	err = gs.groupStorage.AddGroupMember(groupID, peerID, models.RoleMember)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	// Mark invitation as used if it exists
	if !group.IsPublic {
		err = gs.inviteStorage.AcceptInvite(groupID, peerID)
		if err != nil {
			// Log error but don't fail the join operation
			fmt.Printf("Warning: failed to mark invitation as accepted: %v\n", err)
		}
	}

	return nil
}

// LeaveGroup allows a peer to leave a group
func (gs *GroupService) LeaveGroup(groupID, peerID string) error {
	group, err := gs.groupStorage.GetGroup(groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return errors.New("group not found")
	}

	if !group.IsMember(peerID) {
		return errors.New("not a member of this group")
	}

	// Check if this is the admin leaving
	if group.AdminID == peerID {
		// Transfer admin rights to another member or delete group if no members
		members, err := gs.groupStorage.GetGroupMembers(groupID)
		if err != nil {
			return fmt.Errorf("failed to get group members: %w", err)
		}

		// Find another member to promote to admin
		var newAdmin string
		for _, member := range members {
			if member.PeerID != peerID {
				newAdmin = member.PeerID
				break
			}
		}

		if newAdmin != "" {
			// Promote new admin
			err = gs.groupStorage.UpdateMemberRole(groupID, newAdmin, models.RoleAdmin)
			if err != nil {
				return fmt.Errorf("failed to promote new admin: %w", err)
			}
			group.AdminID = newAdmin
			err = gs.groupStorage.UpdateGroup(group)
			if err != nil {
				return fmt.Errorf("failed to update group admin: %w", err)
			}
		} else {
			// No other members, delete the group
			err = gs.groupStorage.DeleteGroup(groupID)
			if err != nil {
				return fmt.Errorf("failed to delete empty group: %w", err)
			}
			return nil
		}
	}

	err = gs.groupStorage.RemoveGroupMember(groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	return nil
}

// InviteToGroup creates an invitation for a peer to join a group
func (gs *GroupService) InviteToGroup(groupID, inviterID, inviteeID string, expiresIn time.Duration) (*models.GroupInvite, error) {
	group, err := gs.groupStorage.GetGroup(groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return nil, errors.New("group not found")
	}

	// Check if inviter is a member with invite permissions
	if !group.IsMember(inviterID) {
		return nil, errors.New("only group members can send invitations")
	}

	// Check if invitee is already a member
	if group.IsMember(inviteeID) {
		return nil, errors.New("user is already a member of this group")
	}

	invite := &models.GroupInvite{
		ID:        generateInviteID(),
		GroupID:   groupID,
		InviterID: inviterID,
		InviteeID: inviteeID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
		Status:    models.InviteStatusPending,
	}

	err = gs.inviteStorage.CreateInvite(invite)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	return invite, nil
}

// GetUserGroups returns all groups a user is a member of
func (gs *GroupService) GetUserGroups(peerID string) ([]*models.Group, error) {
	groups, err := gs.groupStorage.GetUserGroups(peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	return groups, nil
}

// GetGroupMembers returns all members of a group
func (gs *GroupService) GetGroupMembers(groupID string) ([]*models.GroupMember, error) {
	members, err := gs.groupStorage.GetGroupMembers(groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return members, nil
}

// GetPendingInvites returns all pending invitations for a user
func (gs *GroupService) GetPendingInvites(peerID string) ([]*models.GroupInvite, error) {
	invites, err := gs.inviteStorage.GetPendingInvites(peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invites: %w", err)
	}
	return invites, nil
}

// AcceptInvite accepts a group invitation
func (gs *GroupService) AcceptInvite(groupID, peerID string) error {
	invite, err := gs.inviteStorage.GetInvite(groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to get invitation: %w", err)
	}

	if invite == nil {
		return errors.New("invitation not found")
	}

	if invite.IsExpired() {
		return errors.New("invitation has expired")
	}

	if invite.Status != models.InviteStatusPending {
		return errors.New("invitation is not pending")
	}

	// Join the group
	err = gs.JoinGroup(groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to join group: %w", err)
	}

	return nil
}

// DeclineInvite declines a group invitation
func (gs *GroupService) DeclineInvite(groupID, peerID string) error {
	err := gs.inviteStorage.DeclineInvite(groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to decline invitation: %w", err)
	}
	return nil
}

// Helper functions for ID generation
func generateGroupID() string {
	return fmt.Sprintf("group_%d", time.Now().UnixNano())
}

func generateInviteID() string {
	return fmt.Sprintf("invite_%d", time.Now().UnixNano())
}