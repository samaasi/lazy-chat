package messaging

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/utils"
)

// InviteTTL is how long an invitation stays valid.
const InviteTTL = 24 * time.Hour

func toWireMembers(members []models.MemberRef) []protocol.MemberInfo {
	out := make([]protocol.MemberInfo, len(members))
	for i, m := range members {
		out[i] = protocol.MemberInfo{PeerID: m.PeerID, Username: m.Username}
	}
	return out
}

func toRefs(members []protocol.MemberInfo) []models.MemberRef {
	out := make([]models.MemberRef, len(members))
	for i, m := range members {
		out[i] = models.MemberRef{PeerID: m.PeerID, Username: m.Username}
	}
	return out
}

func groupMemberInfos(g *models.Group) []protocol.MemberInfo {
	out := make([]protocol.MemberInfo, 0, len(g.Members))
	for id, name := range g.Members {
		out = append(out, protocol.MemberInfo{PeerID: id, Username: name})
	}
	return out
}

// ---- Outgoing --------------------------------------------------------------

// InviteToGroup invites a peer. Only the group's creator may invite.
func (h *Handler) InviteToGroup(ctx context.Context, groupID, peerID string) error {
	inv, err := h.Groups.InviteToGroup(ctx, groupID, peerID, InviteTTL)
	if err != nil {
		return err
	}
	payload := protocol.GroupInvite{
		InviteID:         inv.ID,
		GroupID:          inv.GroupID,
		GroupName:        inv.GroupName,
		GroupDescription: inv.GroupDescription,
		ExpiresAt:        inv.ExpiresAt.UnixMilli(),
		Members:          toWireMembers(inv.Members),
	}
	if err := h.Net.SendJSON(ctx, peerID, protocol.KindGroupInvite, payload); err != nil {
		return fmt.Errorf("invitation created but could not be delivered: %w", err)
	}
	return nil
}

// AcceptInvite joins a group we were invited to and tells the inviter.
func (h *Handler) AcceptInvite(ctx context.Context, groupID string) (*models.Group, error) {
	group, inv, err := h.Groups.AcceptInvite(ctx, groupID)
	if err != nil {
		return nil, err
	}
	reply := protocol.GroupInviteReply{InviteID: inv.ID, GroupID: inv.GroupID, Accepted: true, Username: h.SelfName}
	if err := h.Net.SendJSON(ctx, inv.InviterID, protocol.KindGroupInviteReply, reply); err != nil {
		return group, fmt.Errorf("joined, but the inviter could not be notified: %w", err)
	}
	return group, nil
}

// DeclineInvite declines an invitation and tells the inviter.
func (h *Handler) DeclineInvite(ctx context.Context, groupID string) error {
	inv, err := h.Groups.DeclineInvite(ctx, groupID)
	if err != nil {
		return err
	}
	reply := protocol.GroupInviteReply{InviteID: inv.ID, GroupID: inv.GroupID, Accepted: false, Username: h.SelfName}
	if err := h.Net.SendJSON(ctx, inv.InviterID, protocol.KindGroupInviteReply, reply); err != nil {
		return fmt.Errorf("declined, but the inviter could not be notified: %w", err)
	}
	return nil
}

// LeaveGroup leaves a group and tells the other members (best effort).
func (h *Handler) LeaveGroup(ctx context.Context, groupID string) error {
	others, err := h.Groups.LeaveGroup(ctx, groupID)
	if err != nil {
		return err
	}
	h.broadcastUpdate(ctx, others, protocol.GroupUpdate{GroupID: groupID, Removed: []string{h.SelfID}})
	return nil
}

// RemoveMember removes a member (creator only) and tells everyone, including
// the removed peer so its copy of the group is deactivated.
func (h *Handler) RemoveMember(ctx context.Context, groupID, peerID string) error {
	audience, err := h.Groups.RemoveMember(ctx, groupID, peerID)
	if err != nil {
		return err
	}
	h.broadcastUpdate(ctx, audience, protocol.GroupUpdate{GroupID: groupID, Removed: []string{peerID}})
	return nil
}

func (h *Handler) broadcastUpdate(ctx context.Context, to []string, upd protocol.GroupUpdate) {
	h.fanOut(ctx, to, func(ctx context.Context, peerID string) error {
		return h.Net.SendJSON(ctx, peerID, protocol.KindGroupUpdate, upd)
	}, func(peerID string, err error) {
		if err != nil {
			h.Logger.Debug("Group update not delivered", "peer", shortID(peerID), "error", err)
		}
	})
}

// ---- Incoming --------------------------------------------------------------

func (h *Handler) onGroupInvite(from string, body []byte) {
	var p protocol.GroupInvite
	if err := protocol.Unmarshal(body, &p); err != nil {
		h.Logger.Debug("Malformed group invite", "peer", shortID(from), "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	inv := &models.GroupInvite{
		ID:               p.InviteID,
		GroupID:          p.GroupID,
		GroupName:        p.GroupName,
		GroupDescription: p.GroupDescription,
		InviterID:        from, // authenticated, not claimed
		InviteeID:        h.SelfID,
		ExpiresAt:        time.UnixMilli(p.ExpiresAt),
		Members:          toRefs(p.Members),
	}
	if !validWireID(p.InviteID) || !validWireID(p.GroupID) {
		h.Logger.Debug("Rejected group invite: bad identifiers", "peer", shortID(from))
		return
	}
	if err := h.Groups.ReceiveInvite(ctx, inv); err != nil {
		h.Logger.Debug("Rejected group invite", "peer", shortID(from), "reason", err.Error())
		return
	}

	h.Out.Printf("* %s invited you to group \"%s\" (%s) - /accept %s  or  /decline %s",
		h.DisplayName(from), inv.GroupName, shortID(inv.GroupID), inv.GroupID, inv.GroupID)
	if h.Notifier != nil {
		_ = h.Notifier.NotifyMessageReceived(h.DisplayName(from), "invited you to group "+inv.GroupName)
	}
}

func (h *Handler) onGroupInviteReply(from string, body []byte) {
	var p protocol.GroupInviteReply
	if err := protocol.Unmarshal(body, &p); err != nil || !validWireID(p.InviteID) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	group, err := h.Groups.ApplyInviteReply(ctx, from, p.InviteID, p.Accepted, p.Username)
	if err != nil {
		h.Logger.Debug("Ignored group invite reply", "peer", shortID(from), "reason", err.Error())
		return
	}
	if !p.Accepted {
		h.Out.Printf("* %s declined your invitation", h.DisplayName(from))
		return
	}
	h.Out.Printf("* %s joined group \"%s\"", h.DisplayName(from), utils.SanitizeText(group.Name, models.MaxGroupNameLen))

	// Tell the newcomer who is in the group now (their invite snapshot may be
	// stale), and tell the existing members about the newcomer.
	newcomerName := group.Members[from]
	var others []string
	for id := range group.Members {
		if id != h.SelfID && id != from {
			others = append(others, id)
		}
	}
	h.background(func(ctx context.Context) {
		_ = h.Net.SendJSON(ctx, from, protocol.KindGroupUpdate, protocol.GroupUpdate{GroupID: group.ID, Added: groupMemberInfos(group)})
	})
	h.background(func(ctx context.Context) {
		h.broadcastUpdate(ctx, others, protocol.GroupUpdate{
			GroupID: group.ID,
			Added:   []protocol.MemberInfo{{PeerID: from, Username: newcomerName}},
		})
	})
}

func (h *Handler) onGroupUpdate(from string, body []byte) {
	var p protocol.GroupUpdate
	if err := protocol.Unmarshal(body, &p); err != nil || !validWireID(p.GroupID) {
		return
	}
	if len(p.Added) > models.MaxGroupMembers || len(p.Removed) > models.MaxGroupMembers {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	changes, err := h.Groups.ApplyUpdate(ctx, from, services.MemberChange{
		GroupID: p.GroupID,
		Added:   toRefs(p.Added),
		Removed: p.Removed,
	})
	if err != nil && !errors.Is(err, services.ErrGroupNotFound) {
		h.Logger.Debug("Rejected group update", "peer", shortID(from), "reason", err.Error())
	}
	for _, c := range changes {
		h.Out.Printf("* group %s: %s", shortID(p.GroupID), utils.SanitizeText(c, 80))
	}
}
