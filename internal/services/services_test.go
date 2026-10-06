package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/storage"
)

var ctx = context.Background()

// pid builds a syntactically valid peer ID.
func pid(n int) string { return fmt.Sprintf("%032x", n) }

type peerEnv struct {
	id    string
	name  string
	db    *storage.SQLiteDB
	group *GroupService
	hist  *MessageHistoryService
}

func newPeer(t *testing.T, n int, name string) *peerEnv {
	t.Helper()
	db := storage.NewSQLiteDB(filepath.Join(t.TempDir(), "p.db"))
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id := pid(n)
	return &peerEnv{
		id: id, name: name, db: db,
		group: NewGroupService(db, db, id, name),
		hist:  NewMessageHistoryService(db, db, id),
	}
}

// wire simulates what the network does: the receiver sees the invite with the
// authenticated sender as inviter and itself as invitee.
func wire(inv *models.GroupInvite, to *peerEnv) *models.GroupInvite {
	c := *inv
	c.InviteeID = to.id
	c.Members = append([]models.MemberRef(nil), inv.Members...)
	return &c
}

func TestCreateGroupPersistsCreatorAsAdmin(t *testing.T) {
	alice := newPeer(t, 1, "Alice")
	g, err := alice.group.CreateGroup(ctx, "  Team \x1b[31mRed\n", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(g.Name, "\x1b\n") {
		t.Fatalf("name not sanitised: %q", g.Name)
	}
	// This was the original bug: the creator existed only in memory.
	members, err := alice.group.GetGroupMembers(ctx, g.ID)
	if err != nil || len(members) != 1 || members[0].PeerID != alice.id || members[0].Role != models.RoleAdmin {
		t.Fatalf("creator not persisted as admin: %+v %v", members, err)
	}
	if groups, _ := alice.group.GetUserGroups(ctx); len(groups) != 1 {
		t.Fatalf("creator cannot see own group: %d", len(groups))
	}
	if _, err := alice.group.CreateGroup(ctx, " \n ", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
}

func TestInviteAcceptFlowBetweenTwoPeers(t *testing.T) {
	alice, bob := newPeer(t, 1, "Alice"), newPeer(t, 2, "Bob")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")

	inv, err := alice.group.InviteToGroup(ctx, g.ID, bob.id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.group.ReceiveInvite(ctx, wire(inv, bob)); err != nil {
		t.Fatal(err)
	}
	pending, _ := bob.group.GetPendingInvites(ctx)
	if len(pending) != 1 || pending[0].GroupName != "Crew" {
		t.Fatalf("pending: %+v", pending)
	}

	bg, _, err := bob.group.AcceptInvite(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bg.HasMember(alice.id) || !bg.HasMember(bob.id) || bg.CreatedBy != alice.id {
		t.Fatalf("bob's copy: %+v", bg)
	}
	if ok, _ := bob.group.IsMember(ctx, g.ID, bob.id); !ok {
		t.Fatal("bob not a member after accepting")
	}

	updated, err := alice.group.ApplyInviteReply(ctx, bob.id, inv.ID, true, "Bob")
	if err != nil || !updated.HasMember(bob.id) {
		t.Fatalf("reply: %+v %v", updated, err)
	}
	if ok, _ := alice.group.IsMember(ctx, g.ID, bob.id); !ok {
		t.Fatal("alice does not see bob as a member")
	}
	if _, err := alice.group.ApplyInviteReply(ctx, bob.id, inv.ID, true, "Bob"); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("an invite can only be answered once: %v", err)
	}
}

func TestInviteAuthorisation(t *testing.T) {
	alice, bob, carol := newPeer(t, 1, "Alice"), newPeer(t, 2, "Bob"), newPeer(t, 3, "Carol")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	inv, _ := alice.group.InviteToGroup(ctx, g.ID, bob.id, time.Hour)
	_ = bob.group.ReceiveInvite(ctx, wire(inv, bob))
	_, _, _ = bob.group.AcceptInvite(ctx, g.ID)
	_, _ = alice.group.ApplyInviteReply(ctx, bob.id, inv.ID, true, "Bob")

	// Bob is a member but not the creator.
	if _, err := bob.group.InviteToGroup(ctx, g.ID, carol.id, time.Hour); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("member invited: %v", err)
	}
	// A stranger cannot invite to a group they are not in.
	if _, err := carol.group.InviteToGroup(ctx, g.ID, bob.id, time.Hour); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("stranger invited: %v", err)
	}

	cases := map[string]struct {
		invitee string
		ttl     time.Duration
	}{
		"bad id":   {"not-an-id", time.Hour},
		"self":     {alice.id, time.Hour},
		"member":   {bob.id, time.Hour},
		"ttl low":  {carol.id, time.Second},
		"ttl high": {carol.id, 365 * 24 * time.Hour},
	}
	for name, c := range cases {
		if _, err := alice.group.InviteToGroup(ctx, g.ID, c.invitee, c.ttl); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestReceiveInviteRejectsBadInvites(t *testing.T) {
	alice, bob := newPeer(t, 1, "Alice"), newPeer(t, 2, "Bob")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	base, _ := alice.group.InviteToGroup(ctx, g.ID, bob.id, time.Hour)

	mutate := map[string]func(*models.GroupInvite){
		"wrong invitee":     func(i *models.GroupInvite) { i.InviteeID = pid(99) },
		"expired":           func(i *models.GroupInvite) { i.ExpiresAt = time.Now().Add(-time.Minute) },
		"expires too late":  func(i *models.GroupInvite) { i.ExpiresAt = time.Now().Add(400 * 24 * time.Hour) },
		"inviter missing":   func(i *models.GroupInvite) { i.Members = []models.MemberRef{{PeerID: pid(50), Username: "x"}} },
		"no members":        func(i *models.GroupInvite) { i.Members = nil },
		"bad member id":     func(i *models.GroupInvite) { i.Members = append(i.Members, models.MemberRef{PeerID: "zz"}) },
		"duplicate member":  func(i *models.GroupInvite) { i.Members = append(i.Members, i.Members[0]) },
		"empty group name":  func(i *models.GroupInvite) { i.GroupName = "\x1b\n" },
		"oversize id":       func(i *models.GroupInvite) { i.ID = strings.Repeat("a", 65) },
		"inviter is self":   func(i *models.GroupInvite) { i.InviterID = bob.id },
		"inviter not an id": func(i *models.GroupInvite) { i.InviterID = "alice" },
	}
	for name, fn := range mutate {
		inv := wire(base, bob)
		fn(inv)
		if err := bob.group.ReceiveInvite(ctx, inv); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	if pending, _ := bob.group.GetPendingInvites(ctx); len(pending) != 0 {
		t.Fatalf("rejected invites were stored: %d", len(pending))
	}

	// Valid, then the same one again, then sanitisation of a hostile name.
	good := wire(base, bob)
	good.GroupName = "Ops\x1b[2J\nroom"
	good.Members[0].Username = "‮evil"
	if err := bob.group.ReceiveInvite(ctx, good); err != nil {
		t.Fatal(err)
	}
	if err := bob.group.ReceiveInvite(ctx, wire(base, bob)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate invite id: %v", err)
	}
	stored, _ := bob.db.GetInvite(ctx, base.ID)
	if strings.ContainsAny(stored.GroupName, "\x1b\n") || strings.ContainsRune(stored.Members[0].Username, '‮') {
		t.Fatalf("hostile text stored: %q %q", stored.GroupName, stored.Members[0].Username)
	}
}

func TestInviteSpamIsCapped(t *testing.T) {
	bob := newPeer(t, 2, "Bob")
	spammer := pid(7)
	var last error
	for i := range maxPendingInvitesPerPeer + 3 {
		inv := &models.GroupInvite{
			ID: fmt.Sprintf("i%d", i), GroupID: fmt.Sprintf("g%d", i), GroupName: "spam",
			InviterID: spammer, InviteeID: bob.id, ExpiresAt: time.Now().Add(time.Hour),
			Members: []models.MemberRef{{PeerID: spammer, Username: "s"}},
		}
		last = bob.group.ReceiveInvite(ctx, inv)
		if i < maxPendingInvitesPerPeer && last != nil {
			t.Fatalf("invite %d refused too early: %v", i, last)
		}
	}
	if !errors.Is(last, ErrTooManyInvite) {
		t.Fatalf("flood not capped: %v", last)
	}
}

func TestInviteReplyMustComeFromTheInvitee(t *testing.T) {
	alice, bob, mallory := newPeer(t, 1, "A"), newPeer(t, 2, "B"), newPeer(t, 3, "M")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	inv, _ := alice.group.InviteToGroup(ctx, g.ID, bob.id, time.Hour)

	if _, err := alice.group.ApplyInviteReply(ctx, mallory.id, inv.ID, true, "M"); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("a reply from someone else was accepted: %v", err)
	}
	if ok, _ := alice.group.IsMember(ctx, g.ID, mallory.id); ok {
		t.Fatal("mallory joined without an invite")
	}
	if _, err := alice.group.ApplyInviteReply(ctx, bob.id, inv.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.group.ApplyInviteReply(ctx, bob.id, inv.ID, true, "B"); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("declined invite can be revived: %v", err)
	}
}

func joined(t *testing.T) (alice, bob, carol *peerEnv, groupID string) {
	t.Helper()
	alice, bob, carol = newPeer(t, 1, "Alice"), newPeer(t, 2, "Bob"), newPeer(t, 3, "Carol")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	for _, p := range []*peerEnv{bob, carol} {
		inv, err := alice.group.InviteToGroup(ctx, g.ID, p.id, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.group.ReceiveInvite(ctx, wire(inv, p)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.group.AcceptInvite(ctx, g.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := alice.group.ApplyInviteReply(ctx, p.id, inv.ID, true, p.name); err != nil {
			t.Fatal(err)
		}
	}
	// Bring bob and carol's copies up to date, as the network would.
	_, _ = bob.group.ApplyUpdate(ctx, alice.id, MemberChange{GroupID: g.ID, Added: []models.MemberRef{{PeerID: carol.id, Username: "Carol"}}})
	return alice, bob, carol, g.ID
}

func TestApplyUpdateEnforcesWhoMayChangeMembership(t *testing.T) {
	alice, bob, carol, gid := joined(t)
	dave := pid(4)

	// A non-admin member cannot add anyone, nor remove someone else.
	if _, err := bob.group.ApplyUpdate(ctx, carol.id, MemberChange{GroupID: gid, Added: []models.MemberRef{{PeerID: dave, Username: "D"}}}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("member added someone: %v", err)
	}
	if _, err := bob.group.ApplyUpdate(ctx, carol.id, MemberChange{GroupID: gid, Removed: []string{alice.id}}); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("member removed the admin: %v", err)
	}
	// A non-member sender is ignored outright.
	if _, err := bob.group.ApplyUpdate(ctx, dave, MemberChange{GroupID: gid, Removed: []string{carol.id}}); !errors.Is(err, ErrNotMember) {
		t.Fatalf("outsider changed the group: %v", err)
	}
	// Unknown group.
	if _, err := bob.group.ApplyUpdate(ctx, alice.id, MemberChange{GroupID: "nope"}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("unknown group: %v", err)
	}

	// A member may remove themselves.
	if changes, err := bob.group.ApplyUpdate(ctx, carol.id, MemberChange{GroupID: gid, Removed: []string{carol.id}}); err != nil || len(changes) != 1 {
		t.Fatalf("self-leave: %v %v", changes, err)
	}
	if ok, _ := bob.group.IsMember(ctx, gid, carol.id); ok {
		t.Fatal("carol still a member after leaving")
	}
	// The admin may remove and add.
	if _, err := bob.group.ApplyUpdate(ctx, alice.id, MemberChange{GroupID: gid, Added: []models.MemberRef{{PeerID: dave, Username: "Dave"}}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := bob.group.IsMember(ctx, gid, dave); !ok {
		t.Fatal("admin add ignored")
	}
	// Being removed deactivates the group for us.
	changes, err := bob.group.ApplyUpdate(ctx, alice.id, MemberChange{GroupID: gid, Removed: []string{bob.id}})
	if err != nil || len(changes) != 1 || changes[0] != "you were removed" {
		t.Fatalf("removal of self: %v %v", changes, err)
	}
	if ok, _ := bob.group.IsMember(ctx, gid, bob.id); ok {
		t.Fatal("removed member can still post")
	}
	if groups, _ := bob.group.GetUserGroups(ctx); len(groups) != 0 {
		t.Fatal("removed member still lists the group")
	}
}

func TestLeaveGroup(t *testing.T) {
	alice, bob, carol, gid := joined(t)
	_ = alice
	_, _ = bob.group.ApplyUpdate(ctx, alice.id, MemberChange{GroupID: gid, Added: []models.MemberRef{{PeerID: carol.id, Username: "Carol"}}})
	others, err := bob.group.LeaveGroup(ctx, gid)
	if err != nil || len(others) == 0 {
		t.Fatalf("leave: %v %v", others, err)
	}
	for _, o := range others {
		if o == bob.id {
			t.Fatal("leaver listed among those to notify")
		}
	}
	if _, err := bob.group.GetGroup(ctx, gid); !errors.Is(err, ErrNotMember) && !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("group still readable after leaving: %v", err)
	}
	if _, err := bob.group.LeaveGroup(ctx, gid); err == nil {
		t.Fatal("leaving twice must fail")
	}
}

func TestExpiredInviteCannotBeAccepted(t *testing.T) {
	alice, bob := newPeer(t, 1, "A"), newPeer(t, 2, "B")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	inv, _ := alice.group.InviteToGroup(ctx, g.ID, bob.id, time.Minute)
	_ = bob.group.ReceiveInvite(ctx, wire(inv, bob))

	bob.group.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, _, err := bob.group.AcceptInvite(ctx, g.ID); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("expired invite accepted: %v", err)
	}
	if n, err := bob.group.CleanupExpiredInvites(ctx); err != nil || n != 1 {
		t.Fatalf("cleanup: %d %v", n, err)
	}
	if _, err := bob.group.DeclineInvite(ctx, g.ID); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("decline after expiry: %v", err)
	}
}

// ---- History ---------------------------------------------------------------

func TestHistoryIsScopedToTheLocalPeer(t *testing.T) {
	alice := newPeer(t, 1, "Alice")
	bob, carol := pid(2), pid(3)
	for i, m := range []*models.ChatMessage{
		models.NewChatMessage("1", alice.id, bob, "to bob"),
		models.NewChatMessage("2", bob, alice.id, "from bob"),
		models.NewChatMessage("3", bob, carol, "bob and carol only"),
	} {
		if ok, err := alice.db.SaveMessage(ctx, m); err != nil || !ok {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	got, err := alice.hist.GetDirectMessageHistory(ctx, bob, storage.Page{})
	if err != nil || len(got) != 2 {
		t.Fatalf("history: %d %v", len(got), err)
	}
	// Asking for a conversation between two other peers cannot be expressed.
	if other, _ := alice.hist.GetDirectMessageHistory(ctx, carol, storage.Page{}); len(other) != 0 {
		t.Fatalf("leaked a third-party conversation: %d", len(other))
	}
	if err := alice.hist.DeleteMessage(ctx, "3"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deleted someone else's conversation: %v", err)
	}
	if err := alice.hist.DeleteMessage(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	if err := alice.hist.MarkMessageAsRead(ctx, "2"); err != nil {
		t.Fatal(err)
	}
	if err := alice.hist.MarkMessageAsRead(ctx, ""); err == nil {
		t.Fatal("empty id accepted")
	}
}

func TestGroupHistoryRequiresMembership(t *testing.T) {
	alice, bob := newPeer(t, 1, "Alice"), newPeer(t, 2, "Bob")
	g, _ := alice.group.CreateGroup(ctx, "Crew", "")
	_, _ = alice.db.SaveMessage(ctx, models.NewGroupMessage("m", alice.id, g.ID, "hello"))

	if got, err := alice.hist.GetGroupMessageHistory(ctx, g.ID, storage.Page{}); err != nil || len(got) != 1 {
		t.Fatalf("member: %v %v", got, err)
	}
	_, _ = bob.db.SaveMessage(ctx, models.NewGroupMessage("m", alice.id, g.ID, "hello")) // bob's DB has it, but he is not a member
	if _, err := bob.hist.GetGroupMessageHistory(ctx, g.ID, storage.Page{}); !errors.Is(err, ErrNotMember) {
		t.Fatalf("non-member read group history: %v", err)
	}
}

func TestSearchAndRangeValidation(t *testing.T) {
	alice := newPeer(t, 1, "A")
	if _, err := alice.hist.SearchMessages(ctx, "  ", storage.Page{}); err == nil {
		t.Fatal("blank query accepted")
	}
	now := time.Now()
	if _, err := alice.hist.GetMessagesByDateRange(ctx, now, now.Add(-time.Hour), storage.Page{}); err == nil {
		t.Fatal("inverted range accepted")
	}
}

func TestExportOldestFirstInBothFormats(t *testing.T) {
	alice := newPeer(t, 1, "Alice")
	bob := pid(2)
	for i := range 1200 { // more than one internal page
		m := models.NewChatMessage(fmt.Sprintf("m%04d", i), alice.id, bob, fmt.Sprintf("line %d\nsecond", i))
		if _, err := alice.db.SaveMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}

	var text bytes.Buffer
	if err := alice.hist.ExportConversation(ctx, &text, bob, false, "text"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(text.String()), "\n")
	if len(lines) != 1200 || !strings.HasSuffix(lines[0], "line 0 second") || !strings.HasSuffix(lines[1199], "line 1199 second") {
		t.Fatalf("text export: %d lines, first %q last %q", len(lines), lines[0], lines[len(lines)-1])
	}

	var js bytes.Buffer
	if err := alice.hist.ExportConversation(ctx, &js, bob, false, "json"); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&js)
	var first models.ChatMessage
	if err := dec.Decode(&first); err != nil || first.ID != "m0000" {
		t.Fatalf("json export first: %+v %v", first, err)
	}

	if err := alice.hist.ExportConversation(ctx, &text, bob, false, "xml"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if err := alice.hist.ExportConversation(ctx, &text, "nogroup", true, "text"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("export of a group we are not in: %v", err)
	}
}

func TestChronologicalDoesNotMutateInput(t *testing.T) {
	in := []*models.ChatMessage{{ID: "new"}, {ID: "old"}}
	out := Chronological(in)
	if out[0].ID != "old" || in[0].ID != "new" {
		t.Fatalf("in=%v out=%v", in, out)
	}
}
