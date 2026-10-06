package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/utils"
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
		CreatedBy:   gs.currentPeerID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Members:     make(map[string]string),
		IsActive:    true,
	}

	// Add creator as first member
	group.AddMember(gs.currentPeerID, "admin")

	err := gs.groupStorage.CreateGroup(context.Background(), group)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return group, nil
}

// JoinGroup allows a peer to join a group (if public or invited)
func (gs *GroupService) JoinGroup(groupID, peerID string) error {
	group, err := gs.groupStorage.GetGroup(context.Background(), groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return errors.New("group not found")
	}

	// Check if already a member
	if group.HasMember(peerID) {
		return errors.New("already a member of this group")
	}

	// For now, allow anyone to join (simplified logic)
	// In a real implementation, you would check invitations

	// Create group member
	member := models.NewGroupMember(groupID, peerID, peerID, "member")
	err = gs.groupStorage.AddGroupMember(context.Background(), member)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	// Add to group's member map
	group.AddMember(peerID, peerID)
	err = gs.groupStorage.UpdateGroup(context.Background(), group)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	return nil
}

// LeaveGroup allows a peer to leave a group
func (gs *GroupService) LeaveGroup(groupID, peerID string) error {
	group, err := gs.groupStorage.GetGroup(context.Background(), groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return errors.New("group not found")
	}

	if !group.HasMember(peerID) {
		return errors.New("not a member of this group")
	}

	// Remove member from group
	err = gs.groupStorage.RemoveGroupMember(context.Background(), groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	// Update group's member map
	group.RemoveMember(peerID)
	err = gs.groupStorage.UpdateGroup(context.Background(), group)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	return nil
}

// InviteToGroup creates an invitation for a peer to join a group
func (gs *GroupService) InviteToGroup(groupID, inviterID, inviteeID string, expiresIn time.Duration) (*models.GroupInvite, error) {
	group, err := gs.groupStorage.GetGroup(context.Background(), groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if group == nil {
		return nil, errors.New("group not found")
	}

	// Check if inviter is a member with invite permissions
	if !group.HasMember(inviterID) {
		return nil, errors.New("only group members can send invitations")
	}

	// Check if invitee is already a member
	if group.HasMember(inviteeID) {
		return nil, errors.New("user is already a member of this group")
	}

	invite := models.NewGroupInvite(
		generateInviteID(),
		groupID,
		inviterID,
		inviteeID,
		time.Now().Add(expiresIn),
	)

	err = gs.inviteStorage.CreateInvite(context.Background(), invite)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	return invite, nil
}

// GetUserGroups returns all groups a user is a member of
func (gs *GroupService) GetUserGroups(peerID string) ([]*models.Group, error) {
	groups, err := gs.groupStorage.GetGroupsByMember(context.Background(), peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	return groups, nil
}

// GetGroupMembers returns all members of a group
func (gs *GroupService) GetGroupMembers(groupID string) ([]*models.GroupMember, error) {
	members, err := gs.groupStorage.GetGroupMembers(context.Background(), groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return members, nil
}

// GetPendingInvites returns all pending invitations for a user
func (gs *GroupService) GetPendingInvites(peerID string) ([]*models.GroupInvite, error) {
	invites, err := gs.inviteStorage.GetInvitesByInvitee(context.Background(), peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invites: %w", err)
	}
	return invites, nil
}

// AcceptInvite accepts a group invitation
func (gs *GroupService) AcceptInvite(groupID, peerID string) error {
	// Find invite by group and invitee
	invites, err := gs.inviteStorage.GetInvitesByInvitee(context.Background(), peerID)
	if err != nil {
		return fmt.Errorf("failed to get invitations: %w", err)
	}

	var invite *models.GroupInvite
	for _, inv := range invites {
		if inv.GroupID == groupID && inv.Status == "pending" {
			invite = inv
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get invitation: %w", err)
	}

	if invite == nil {
		return errors.New("invitation not found")
	}

	if invite.IsExpired() {
		return errors.New("invitation has expired")
	}

	if invite.Status != "pending" {
		return errors.New("invitation is not pending")
	}

	// Join the group
	err = gs.JoinGroup(groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to join group: %w", err)
	}

	// Update invite status
	invite.Accept()
	err = gs.inviteStorage.UpdateInviteStatus(context.Background(), invite.ID, "accepted")
	if err != nil {
		return fmt.Errorf("failed to update invite status: %w", err)
	}

	return nil
}

// DeclineInvite declines a group invitation
func (gs *GroupService) DeclineInvite(groupID, peerID string) error {
	// Find invite by group and invitee
	invites, err := gs.inviteStorage.GetInvitesByInvitee(context.Background(), peerID)
	if err != nil {
		return fmt.Errorf("failed to get invitations: %w", err)
	}

	var invite *models.GroupInvite
	for _, inv := range invites {
		if inv.GroupID == groupID && inv.Status == "pending" {
			invite = inv
			break
		}
	}

	if invite == nil {
		return errors.New("invitation not found")
	}

	invite.Decline()
	err = gs.inviteStorage.UpdateInviteStatus(context.Background(), invite.ID, "declined")
	if err != nil {
		return fmt.Errorf("failed to decline invitation: %w", err)
	}
	return nil
}

// Helper functions for ID generation
func generateGroupID() string {
	return utils.NewPrefixedID("grp")
}

func generateInviteID() string {
	return utils.NewPrefixedID("inv")
}
