package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/utils"
)

// Errors returned by the group service. They are comparable with errors.Is.
var (
	ErrGroupNotFound = errors.New("group not found")
	ErrNotMember     = errors.New("not a member of this group")
	ErrNotAdmin      = errors.New("only the group creator can do that")
	ErrInvalid       = errors.New("invalid request")
	ErrNoInvite      = errors.New("no pending invitation for that group")
	ErrTooManyInvite = errors.New("too many pending invitations from this peer")
)

const (
	minInviteTTL = time.Minute
	maxInviteTTL = 30 * 24 * time.Hour
	// maxPendingInvitesPerPeer bounds what one peer can park in our database.
	maxPendingInvitesPerPeer = 10
)

// GroupService implements group membership rules for the local peer.
//
// The model is deliberately simple: every peer keeps its own copy of a
// group, the creator is the only admin, and membership changes are
// accepted over the network only from the creator (adds/removes) or from the
// member concerned (leaving). Authenticating who sent a change is the
// transport's job; this service decides whether that sender is allowed to.
type GroupService struct {
	groups   storage.GroupStorage
	invites  storage.InviteStorage
	selfID   string
	selfName string
	now      func() time.Time
}

// NewGroupService creates the service for the local peer.
func NewGroupService(groups storage.GroupStorage, invites storage.InviteStorage, selfID, selfName string) *GroupService {
	return &GroupService{groups: groups, invites: invites, selfID: selfID, selfName: selfName, now: time.Now}
}

// SelfID returns the local peer's ID.
func (gs *GroupService) SelfID() string { return gs.selfID }

// cleanLabel sanitises untrusted display text and trims the whitespace that
// sanitising (newlines become spaces) can leave behind.
func cleanLabel(s string, maxRunes int) string {
	return strings.TrimSpace(utils.SanitizeText(s, maxRunes))
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func (gs *GroupService) loadGroup(ctx context.Context, groupID string) (*models.Group, error) {
	g, err := gs.groups.GetGroup(ctx, groupID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrGroupNotFound
	}
	return g, err
}

// CreateGroup creates a new group with the local peer as its admin.
func (gs *GroupService) CreateGroup(ctx context.Context, name, description string) (*models.Group, error) {
	name = cleanLabel(name, models.MaxGroupNameLen)
	description = cleanLabel(description, models.MaxGroupDescriptionLen)
	if name == "" {
		return nil, invalid("group name cannot be empty")
	}

	group := models.NewGroup(utils.NewPrefixedID("grp"), name, description, gs.selfID)
	group.AddMember(gs.selfID, gs.selfName)

	if err := gs.groups.CreateGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	return group, nil
}

// GetGroup returns a group the local peer belongs to.
func (gs *GroupService) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	g, err := gs.loadGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if !g.HasMember(gs.selfID) {
		return nil, ErrNotMember
	}
	return g, nil
}

// GetUserGroups returns the groups the local peer belongs to.
func (gs *GroupService) GetUserGroups(ctx context.Context) ([]*models.Group, error) {
	groups, err := gs.groups.GetGroupsByMember(ctx, gs.selfID)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups: %w", err)
	}
	return groups, nil
}

// GetGroupMembers returns the active members of a group the local peer belongs to.
func (gs *GroupService) GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMember, error) {
	if _, err := gs.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	return gs.groups.GetGroupMembers(ctx, groupID)
}

// IsMember reports whether peerID is an active member of an active group.
func (gs *GroupService) IsMember(ctx context.Context, groupID, peerID string) (bool, error) {
	return gs.groups.IsGroupMember(ctx, groupID, peerID)
}

// InviteToGroup creates an invitation for a peer to join a group. Only the
// creator may invite. The returned invite carries the member snapshot that
// is sent to the invitee.
func (gs *GroupService) InviteToGroup(ctx context.Context, groupID, inviteeID string, ttl time.Duration) (*models.GroupInvite, error) {
	if !identity.ValidID(inviteeID) {
		return nil, invalid("invitee is not a valid peer ID")
	}
	if inviteeID == gs.selfID {
		return nil, invalid("you cannot invite yourself")
	}
	if ttl < minInviteTTL || ttl > maxInviteTTL {
		return nil, invalid("invitation lifetime must be between %s and %s", minInviteTTL, maxInviteTTL)
	}

	group, err := gs.loadGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if !group.HasMember(gs.selfID) {
		return nil, ErrNotMember
	}
	if group.CreatedBy != gs.selfID {
		return nil, ErrNotAdmin
	}
	if group.HasMember(inviteeID) {
		return nil, invalid("that peer is already a member")
	}
	if group.GetMemberCount() >= models.MaxGroupMembers {
		return nil, invalid("group is full (%d members)", models.MaxGroupMembers)
	}

	now := gs.now()
	inv := &models.GroupInvite{
		ID:               utils.NewPrefixedID("inv"),
		GroupID:          group.ID,
		GroupName:        group.Name,
		GroupDescription: group.Description,
		GroupCreator:     group.CreatedBy,
		InviterID:        gs.selfID,
		InviteeID:        inviteeID,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
		Status:           models.InviteStatusPending,
	}
	for peerID, username := range group.Members {
		inv.Members = append(inv.Members, models.MemberRef{PeerID: peerID, Username: username})
	}

	if err := gs.invites.CreateInvite(ctx, inv); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	return inv, nil
}

// ReceiveInvite validates and stores an invitation that arrived from the
// network. inv.InviterID must be the *authenticated* sender, not a value the
// sender claimed. The inviter is taken to be the group creator, matching the
// rule that only the creator can invite.
func (gs *GroupService) ReceiveInvite(ctx context.Context, inv *models.GroupInvite) error {
	now := gs.now()

	switch {
	case inv.InviteeID != gs.selfID:
		return invalid("invitation is not addressed to this peer")
	case !identity.ValidID(inv.InviterID) || inv.InviterID == gs.selfID:
		return invalid("bad inviter")
	case len(inv.ID) == 0 || len(inv.ID) > 64 || len(inv.GroupID) == 0 || len(inv.GroupID) > 64:
		return invalid("bad identifiers")
	case !inv.ExpiresAt.After(now) || inv.ExpiresAt.After(now.Add(maxInviteTTL+time.Minute)):
		return invalid("bad expiry")
	case len(inv.Members) == 0 || len(inv.Members) > models.MaxGroupMembers:
		return invalid("bad member list")
	}

	inv.GroupName = cleanLabel(inv.GroupName, models.MaxGroupNameLen)
	inv.GroupDescription = cleanLabel(inv.GroupDescription, models.MaxGroupDescriptionLen)
	if inv.GroupName == "" {
		return invalid("group name cannot be empty")
	}
	inv.GroupCreator = inv.InviterID
	inv.Status = models.InviteStatusPending
	inv.CreatedAt = now

	seen := make(map[string]bool, len(inv.Members))
	hasInviter := false
	for i := range inv.Members {
		m := &inv.Members[i]
		if !identity.ValidID(m.PeerID) || seen[m.PeerID] {
			return invalid("bad member entry")
		}
		seen[m.PeerID] = true
		m.Username = cleanLabel(m.Username, 32)
		if m.Username == "" {
			m.Username = m.PeerID[:8]
		}
		hasInviter = hasInviter || m.PeerID == inv.InviterID
	}
	if !hasInviter {
		return invalid("inviter is not in the member list")
	}

	if member, err := gs.groups.IsGroupMember(ctx, inv.GroupID, gs.selfID); err != nil {
		return err
	} else if member {
		return invalid("already a member of this group")
	}
	if _, err := gs.invites.GetInvite(ctx, inv.ID); err == nil {
		return invalid("duplicate invitation")
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	n, err := gs.invites.CountPendingInvitesFrom(ctx, inv.InviterID, gs.selfID, now)
	if err != nil {
		return err
	}
	if n >= maxPendingInvitesPerPeer {
		return ErrTooManyInvite
	}
	return gs.invites.CreateInvite(ctx, inv)
}

// pendingInvite finds the newest unexpired pending invitation to groupID.
func (gs *GroupService) pendingInvite(ctx context.Context, groupID string) (*models.GroupInvite, error) {
	invites, err := gs.invites.GetInvitesByInvitee(ctx, gs.selfID)
	if err != nil {
		return nil, fmt.Errorf("failed to get invitations: %w", err)
	}
	now := gs.now()
	for _, inv := range invites { // newest first
		if inv.GroupID == groupID && inv.Status == models.InviteStatusPending && !inv.IsExpired(now) {
			return inv, nil
		}
	}
	return nil, ErrNoInvite
}

// GetPendingInvites returns unexpired invitations waiting for the local peer.
func (gs *GroupService) GetPendingInvites(ctx context.Context) ([]*models.GroupInvite, error) {
	invites, err := gs.invites.GetInvitesByInvitee(ctx, gs.selfID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invites: %w", err)
	}
	now := gs.now()
	pending := invites[:0]
	for _, inv := range invites {
		if inv.Status == models.InviteStatusPending && !inv.IsExpired(now) {
			pending = append(pending, inv)
		}
	}
	return pending, nil
}

// AcceptInvite accepts the pending invitation to groupID and joins the group.
func (gs *GroupService) AcceptInvite(ctx context.Context, groupID string) (*models.Group, *models.GroupInvite, error) {
	inv, err := gs.pendingInvite(ctx, groupID)
	if err != nil {
		return nil, nil, err
	}
	group, err := gs.invites.AcceptInvite(ctx, inv.ID, gs.selfID, gs.selfName, gs.now())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to accept invitation: %w", err)
	}
	return group, inv, nil
}

// DeclineInvite declines the pending invitation to groupID.
func (gs *GroupService) DeclineInvite(ctx context.Context, groupID string) (*models.GroupInvite, error) {
	inv, err := gs.pendingInvite(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if err := gs.invites.UpdateInviteStatus(ctx, inv.ID, models.InviteStatusDeclined); err != nil {
		return nil, fmt.Errorf("failed to decline invitation: %w", err)
	}
	return inv, nil
}

// ApplyInviteReply processes the answer to an invitation we sent. from is the
// authenticated sender; only the peer we invited may answer. When accepted,
// the peer becomes a member and the updated group is returned so the caller
// can tell the other members.
func (gs *GroupService) ApplyInviteReply(ctx context.Context, from, inviteID string, accepted bool, username string) (*models.Group, error) {
	inv, err := gs.invites.GetInvite(ctx, inviteID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrNoInvite
	}
	if err != nil {
		return nil, err
	}
	if inv.InviterID != gs.selfID || inv.InviteeID != from || inv.Status != models.InviteStatusPending {
		return nil, ErrNoInvite
	}
	if inv.IsExpired(gs.now()) {
		_ = gs.invites.UpdateInviteStatus(ctx, inv.ID, models.InviteStatusExpired)
		return nil, ErrNoInvite
	}

	if !accepted {
		return nil, gs.invites.UpdateInviteStatus(ctx, inv.ID, models.InviteStatusDeclined)
	}

	group, err := gs.loadGroup(ctx, inv.GroupID)
	if err != nil {
		return nil, err
	}
	if group.CreatedBy != gs.selfID {
		return nil, ErrNotAdmin
	}
	if group.GetMemberCount() >= models.MaxGroupMembers {
		return nil, invalid("group is full")
	}
	username = cleanLabel(username, 32)
	if username == "" {
		username = from[:8]
	}
	if err := gs.groups.AddGroupMember(ctx, models.NewGroupMember(group.ID, from, username, models.RoleMember)); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}
	if err := gs.invites.UpdateInviteStatus(ctx, inv.ID, models.InviteStatusAccepted); err != nil {
		return nil, err
	}
	group.AddMember(from, username)
	return group, nil
}

// LeaveGroup removes the local peer from a group and returns the other
// members, who should be told.
func (gs *GroupService) LeaveGroup(ctx context.Context, groupID string) ([]string, error) {
	group, err := gs.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	var others []string
	for peerID := range group.Members {
		if peerID != gs.selfID {
			others = append(others, peerID)
		}
	}
	if err := gs.groups.RemoveGroupMember(ctx, groupID, gs.selfID); err != nil {
		return nil, fmt.Errorf("failed to leave group: %w", err)
	}
	return others, nil
}

// RemoveMember lets the creator remove another member. It returns every
// member of the group before the removal (including the removed peer) so the
// caller can notify them all.
func (gs *GroupService) RemoveMember(ctx context.Context, groupID, peerID string) ([]string, error) {
	group, err := gs.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if group.CreatedBy != gs.selfID {
		return nil, ErrNotAdmin
	}
	if peerID == gs.selfID {
		return nil, invalid("use leave to remove yourself")
	}
	if !group.HasMember(peerID) {
		return nil, invalid("that peer is not a member")
	}
	if err := gs.groups.RemoveGroupMember(ctx, groupID, peerID); err != nil {
		return nil, fmt.Errorf("failed to remove member: %w", err)
	}
	audience := make([]string, 0, len(group.Members))
	for id := range group.Members {
		if id != gs.selfID {
			audience = append(audience, id)
		}
	}
	return audience, nil
}

// MemberChange is a membership update received from a peer.
type MemberChange struct {
	GroupID string
	Added   []models.MemberRef
	Removed []string
}

// ApplyUpdate applies a membership change sent by `sender` (authenticated).
// The creator may add and remove anyone; any member may remove only itself.
// Anything else is rejected. It returns the human-readable changes made.
func (gs *GroupService) ApplyUpdate(ctx context.Context, sender string, ch MemberChange) ([]string, error) {
	group, err := gs.loadGroup(ctx, ch.GroupID)
	if err != nil {
		return nil, err
	}
	if !group.HasMember(gs.selfID) || !group.HasMember(sender) {
		return nil, ErrNotMember
	}
	senderIsAdmin := sender == group.CreatedBy

	var changes []string
	for _, m := range ch.Added {
		if !senderIsAdmin {
			return changes, ErrNotAdmin
		}
		if !identity.ValidID(m.PeerID) || group.HasMember(m.PeerID) {
			continue
		}
		if group.GetMemberCount() >= models.MaxGroupMembers {
			return changes, invalid("group is full")
		}
		name := cleanLabel(m.Username, 32)
		if name == "" {
			name = m.PeerID[:8]
		}
		if err := gs.groups.AddGroupMember(ctx, models.NewGroupMember(group.ID, m.PeerID, name, models.RoleMember)); err != nil {
			return changes, err
		}
		group.AddMember(m.PeerID, name)
		changes = append(changes, name+" joined")
	}
	for _, peerID := range ch.Removed {
		if peerID != sender && !senderIsAdmin {
			return changes, ErrNotAdmin
		}
		name, wasMember := group.Members[peerID]
		if !wasMember {
			continue
		}
		if err := gs.groups.RemoveGroupMember(ctx, group.ID, peerID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return changes, err
		}
		group.RemoveMember(peerID)
		if peerID == gs.selfID {
			changes = append(changes, "you were removed")
		} else {
			changes = append(changes, name+" left")
		}
	}
	return changes, nil
}

// BroadcastTargets returns the members of a group other than the local peer.
func (gs *GroupService) BroadcastTargets(ctx context.Context, groupID string) ([]string, error) {
	group, err := gs.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(group.Members))
	for peerID := range group.Members {
		if peerID != gs.selfID {
			targets = append(targets, peerID)
		}
	}
	return targets, nil
}

// CleanupExpiredInvites marks expired invitations; intended for periodic use.
func (gs *GroupService) CleanupExpiredInvites(ctx context.Context) (int64, error) {
	return gs.invites.CleanupExpiredInvites(ctx, gs.now())
}
