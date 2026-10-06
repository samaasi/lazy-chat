package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/peer"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
)

var bg = context.Background()

func pid(n int) string { return fmt.Sprintf("%032x", n) }

// ---- Fakes -----------------------------------------------------------------

type sentFrame struct {
	to      string
	kind    protocol.Kind
	payload []byte
}

type fakeNet struct {
	mu       sync.Mutex
	sent     []sentFrame
	names    map[string]string
	failFor  map[string]error
	handlers map[protocol.Kind]interfaces.FrameHandler
	listener []interfaces.PeerListener
}

func newFakeNet() *fakeNet {
	return &fakeNet{names: map[string]string{}, failFor: map[string]error{}, handlers: map[protocol.Kind]interfaces.FrameHandler{}}
}

func (f *fakeNet) Start(context.Context) error                       { return nil }
func (f *fakeNet) Stop() error                                       { return nil }
func (f *fakeNet) ConnectToPeer(context.Context, string) error       { return nil }
func (f *fakeNet) Disconnect(string)                                 {}
func (f *fakeNet) IsConnected(string) bool                           { return true }
func (f *fakeNet) ConnectedPeers() []string                          { return nil }
func (f *fakeNet) Handle(k protocol.Kind, h interfaces.FrameHandler) { f.handlers[k] = h }
func (f *fakeNet) AddListener(l interfaces.PeerListener)             { f.listener = append(f.listener, l) }
func (f *fakeNet) PeerName(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.names[id]
	return n, ok
}
func (f *fakeNet) Send(_ context.Context, to string, k protocol.Kind, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failFor[to]; err != nil {
		return err
	}
	f.sent = append(f.sent, sentFrame{to, k, body})
	return nil
}
func (f *fakeNet) SendJSON(ctx context.Context, to string, k protocol.Kind, v any) error {
	b, err := protocol.Marshal(v)
	if err != nil {
		return err
	}
	return f.Send(ctx, to, k, b)
}
func (f *fakeNet) framesTo(to string, k protocol.Kind) []sentFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sentFrame
	for _, s := range f.sent {
		if s.to == to && s.kind == k {
			out = append(out, s)
		}
	}
	return out
}
func (f *fakeNet) count(k protocol.Kind) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.sent {
		if s.kind == k {
			n++
		}
	}
	return n
}

type capture struct {
	mu    sync.Mutex
	lines []string
}

func (c *capture) Printf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}
func (c *capture) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}
func (c *capture) n() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.lines) }

type fakeNotifier struct {
	mu    sync.Mutex
	calls []string
}

func (n *fakeNotifier) rec(s string) { n.mu.Lock(); n.calls = append(n.calls, s); n.mu.Unlock() }
func (n *fakeNotifier) NotifyMessageReceived(s, m string) error {
	n.rec("msg:" + s + ":" + m)
	return nil
}
func (n *fakeNotifier) NotifyFileReceived(s, f string) error  { n.rec("file:" + s); return nil }
func (n *fakeNotifier) NotifyPeerConnected(s string) error    { n.rec("up:" + s); return nil }
func (n *fakeNotifier) NotifyPeerDisconnected(s string) error { n.rec("down:" + s); return nil }
func (n *fakeNotifier) SetEnabled(bool)                       {}
func (n *fakeNotifier) IsEnabled() bool                       { return true }

type env struct {
	h     *Handler
	net   *fakeNet
	out   *capture
	note  *fakeNotifier
	db    *storage.SQLiteDB
	peers *peer.Manager
	self  string
}

func newEnv(t *testing.T, selfN int, name string) *env {
	t.Helper()
	db := storage.NewSQLiteDB(filepath.Join(t.TempDir(), "m.db"))
	if err := db.Connect(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(bg); err != nil {
		t.Fatal(err)
	}
	e := &env{net: newFakeNet(), out: &capture{}, note: &fakeNotifier{}, db: db, self: pid(selfN)}
	log := logger.Discard()
	e.peers = peer.NewManager(log)
	e.h = NewHandler(Deps{
		Logger: log, SelfID: e.self, SelfName: name, Net: e.net, Store: db,
		Groups: services.NewGroupService(db, db, e.self, name), Peers: e.peers, Notifier: e.note, Out: e.out,
	})
	e.h.Register()
	t.Cleanup(e.h.Close)
	return e
}

func wireMsg(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

func directBody(id, to, text string) []byte {
	return wireMsg(map[string]any{"id": id, "to": to, "message": text, "type": "direct", "timestamp": time.Now()})
}

func (e *env) stored(t *testing.T) []*models.ChatMessage {
	t.Helper()
	msgs, err := e.db.GetMessages(bg, storage.Page{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

func (e *env) settle() { e.h.Close() } // waits for ack goroutines

// ---- Receiving -------------------------------------------------------------

func TestReceivedMessageUsesAuthenticatedSenderAndLocalState(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	e.net.names[alice] = "Alice"

	// The payload lies about who sent it, when, and its flags.
	body := wireMsg(map[string]any{
		"id": "m1", "from": pid(666), "to": e.self, "message": "hello", "type": "direct",
		"timestamp": "2001-01-01T00:00:00Z", "delivered": false, "read": true, "seq": 99,
	})
	e.net.handlers[protocol.KindMessage](alice, body)
	e.settle()

	msgs := e.stored(t)
	if len(msgs) != 1 {
		t.Fatalf("stored %d messages", len(msgs))
	}
	m := msgs[0]
	if m.From != alice {
		t.Fatalf("sender = %s, want the authenticated %s", m.From, alice)
	}
	if m.Read || !m.Delivered {
		t.Fatalf("flags came from the payload: delivered=%v read=%v", m.Delivered, m.Read)
	}
	if time.Since(m.Timestamp) > time.Minute {
		t.Fatalf("sender-supplied timestamp was trusted: %v", m.Timestamp)
	}
	if !strings.Contains(e.out.all(), "Alice (00000000): hello") {
		t.Fatalf("output: %q", e.out.all())
	}
	acks := e.net.framesTo(alice, protocol.KindAck)
	if len(acks) != 1 || !strings.Contains(string(acks[0].payload), `"m1"`) {
		t.Fatalf("acks: %+v", acks)
	}
	if len(e.note.calls) != 1 {
		t.Fatalf("notifications: %v", e.note.calls)
	}
}

func TestInvalidMessagesAreDroppedSilently(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	g, err := e.h.Groups.CreateGroup(bg, "Crew", "")
	if err != nil {
		t.Fatal(err)
	}

	bad := map[string][]byte{
		"empty text":        directBody("a1", e.self, "   "),
		"too long":          directBody("a2", e.self, strings.Repeat("x", MaxMessageBytes+1)),
		"id with newline":   directBody("a\nb", e.self, "hi"),
		"id too long":       directBody(strings.Repeat("a", 65), e.self, "hi"),
		"empty id":          directBody("", e.self, "hi"),
		"addressed to bob":  directBody("a4", pid(3), "hi"),
		"no recipient":      directBody("a5", "", "hi"),
		"direct with group": wireMsg(map[string]any{"id": "a6", "to": e.self, "group_id": g.ID, "message": "hi", "type": "direct"}),
		"system type":       wireMsg(map[string]any{"id": "a7", "to": e.self, "message": "hi", "type": "system"}),
		"unknown type":      wireMsg(map[string]any{"id": "a8", "to": e.self, "message": "hi", "type": "admin"}),
		"no type":           wireMsg(map[string]any{"id": "a9", "to": e.self, "message": "hi"}),
		"group, non-member": wireMsg(map[string]any{"id": "b1", "group_id": g.ID, "message": "hi", "type": "group"}),
		"group, unknown":    wireMsg(map[string]any{"id": "b2", "group_id": "nope", "message": "hi", "type": "group"}),
		"group with to":     wireMsg(map[string]any{"id": "b3", "to": e.self, "group_id": g.ID, "message": "hi", "type": "group"}),
		"group bad id":      wireMsg(map[string]any{"id": "b4", "group_id": "../x", "message": "hi", "type": "group"}),
		"not json":          []byte("garbage"),
		"json array":        []byte("[1,2]"),
	}
	for _, body := range bad {
		e.net.handlers[protocol.KindMessage](alice, body)
	}
	e.settle()

	if got := e.stored(t); len(got) != 0 {
		for _, m := range got {
			t.Logf("stored: %+v", *m)
		}
		t.Fatalf("%d invalid messages were stored", len(got))
	}
	if e.out.n() != 0 || len(e.note.calls) != 0 {
		t.Fatalf("invalid messages reached the user: %q", e.out.all())
	}
	if e.net.count(protocol.KindAck) != 0 {
		t.Fatal("invalid messages were acknowledged")
	}
}

func TestDuplicateIsAckedButShownOnce(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	body := directBody("dup", e.self, "once")
	e.net.handlers[protocol.KindMessage](alice, body)
	e.net.handlers[protocol.KindMessage](alice, body)
	e.settle()
	if len(e.stored(t)) != 1 || e.out.n() != 1 {
		t.Fatalf("stored=%d shown=%d", len(e.stored(t)), e.out.n())
	}
	if n := len(e.net.framesTo(alice, protocol.KindAck)); n != 2 {
		t.Fatalf("acks = %d; a re-delivery means our ack was lost, so it must be re-sent", n)
	}
}

func TestPeerCannotSquatAnotherPeersMessageID(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice, mallory := pid(2), pid(3)
	e.net.handlers[protocol.KindMessage](mallory, directBody("shared-id", e.self, "squatting"))
	e.net.handlers[protocol.KindMessage](alice, directBody("shared-id", e.self, "the real one"))
	e.settle()
	var texts []string
	for _, m := range e.stored(t) {
		texts = append(texts, m.From[len(m.From)-1:]+":"+m.Message)
	}
	if len(texts) != 2 {
		t.Fatalf("stored %v", texts)
	}
	if !strings.Contains(e.out.all(), "the real one") {
		t.Fatal("the legitimate message was suppressed by the squatter")
	}
}

func TestHostileTextCannotReachTheTerminalOrNotifications(t *testing.T) {
	e := newEnv(t, 1, "me")
	evil := pid(9)
	e.net.names[evil] = "evil\x1b[2J‮nam\ne"
	e.net.handlers[protocol.KindMessage](evil, directBody("x1", e.self, "line1\n\x1b[31mred\x1b]0;title\x07‮txt.exe\r\nline2"))
	e.settle()

	out := e.out.all()
	if strings.ContainsAny(out, "\x1b\x07‮\r") || strings.Count(out, "\n") != 0 {
		t.Fatalf("unsafe output: %q", out)
	}
	for _, call := range e.note.calls {
		if strings.ContainsAny(call, "\x1b\x07‮") {
			t.Fatalf("unsafe notification: %q", call)
		}
	}
}

func TestGroupMessagesRequireMembershipAndNameTheGroup(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice, outsider := pid(2), pid(3)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, alice, "Alice", models.RoleMember))
	body := func(id string) []byte {
		return wireMsg(map[string]any{"id": id, "group_id": g.ID, "message": "team talk", "type": "group"})
	}

	e.net.handlers[protocol.KindMessage](alice, body("g1"))
	e.net.handlers[protocol.KindMessage](outsider, body("g2"))
	e.settle()

	if got := e.stored(t); len(got) != 1 || got[0].From != alice || got[0].GroupID != g.ID {
		t.Fatalf("stored: %+v", got)
	}
	if !strings.Contains(e.out.all(), "[Crew] Alice") {
		t.Fatalf("output %q", e.out.all())
	}
	if e.net.count(protocol.KindAck) != 1 {
		t.Fatal("only the member's message should be acknowledged")
	}

	// Once removed, the same peer is refused.
	if err := e.db.RemoveGroupMember(bg, g.ID, alice); err != nil {
		t.Fatal(err)
	}
	e.net.handlers[protocol.KindMessage](alice, body("g3"))
	if len(e.stored(t)) != 1 {
		t.Fatal("a removed member can still post")
	}
}

func TestAckMarksOnlyOurOwnMessagesDelivered(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	if err := e.h.SendMessage(bg, alice, "ping"); err != nil {
		t.Fatal(err)
	}
	sent := e.net.framesTo(alice, protocol.KindMessage)
	var m models.ChatMessage
	_ = json.Unmarshal(sent[0].payload, &m)
	if e.stored(t)[0].Delivered {
		t.Fatal("message delivered before any ack")
	}

	// An ack for an ID that is not ours changes nothing; for ours, it does.
	e.net.handlers[protocol.KindAck](alice, wireMsg(map[string]any{"message_id": "someone-elses"}))
	e.net.handlers[protocol.KindAck](alice, []byte("junk"))
	e.net.handlers[protocol.KindAck](alice, wireMsg(map[string]any{"message_id": "bad id!"}))
	if e.stored(t)[0].Delivered {
		t.Fatal("unrelated acks marked the message")
	}
	e.net.handlers[protocol.KindAck](alice, wireMsg(map[string]any{"message_id": m.ID}))
	if !e.stored(t)[0].Delivered {
		t.Fatal("ack did not mark the message delivered")
	}
}

// ---- Sending ---------------------------------------------------------------

func TestSendMessage(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)

	for _, text := range []string{"", "  \n", strings.Repeat("x", MaxMessageBytes+1), "\xff"} {
		if err := e.h.SendMessage(bg, alice, text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	if len(e.stored(t)) != 0 || len(e.net.sent) != 0 {
		t.Fatal("invalid messages were stored or sent")
	}

	if err := e.h.SendMessage(bg, alice, "hello"); err != nil {
		t.Fatal(err)
	}
	var wire models.ChatMessage
	_ = json.Unmarshal(e.net.framesTo(alice, protocol.KindMessage)[0].payload, &wire)
	if wire.From != e.self || wire.To != alice || wire.Message != "hello" || wire.Type != models.MessageTypeDirect || len(wire.ID) != 32 {
		t.Fatalf("wire message: %+v", wire)
	}

	// Unreachable peer: kept in history as undelivered, and the user is told.
	offline := pid(3)
	e.net.failFor[offline] = apperrors.ErrPeerNotFound
	err := e.h.SendMessage(bg, offline, "are you there")
	if !errors.Is(err, apperrors.ErrPeerNotFound) || !strings.Contains(err.Error(), "saved but not delivered") {
		t.Fatalf("got %v", err)
	}
	found := false
	for _, m := range e.stored(t) {
		if m.Message == "are you there" {
			found = true
			if m.Delivered {
				t.Fatal("undeliverable message marked delivered")
			}
		}
	}
	if !found {
		t.Fatal("undeliverable message was not kept")
	}
}

func TestSendGroupMessage(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice, bob := pid(2), pid(3)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, alice, "Alice", models.RoleMember))
	_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, bob, "Bob", models.RoleMember))

	res, err := e.h.SendGroupMessage(bg, g.ID, "all hands")
	if err != nil || len(res.Queued) != 2 || len(res.Failed) != 0 {
		t.Fatalf("result: %+v err=%v", res, err)
	}
	if len(e.net.framesTo(e.self, protocol.KindMessage)) != 0 {
		t.Fatal("sent a group message to ourselves")
	}

	// One member unreachable: partial success, not an error.
	e.net.failFor[bob] = errors.New("offline")
	res, err = e.h.SendGroupMessage(bg, g.ID, "second")
	if err != nil || len(res.Queued) != 1 || res.Failed[bob] == nil {
		t.Fatalf("partial: %+v err=%v", res, err)
	}

	// Nobody reachable: stored, but an error.
	e.net.failFor[alice] = errors.New("offline")
	if _, err := e.h.SendGroupMessage(bg, g.ID, "third"); err == nil || !strings.Contains(err.Error(), "saved but not delivered") {
		t.Fatalf("got %v", err)
	}
	if n := len(e.stored(t)); n != 3 {
		t.Fatalf("stored %d, want 3", n)
	}

	// Not a member / unknown group / invalid text.
	if _, err := e.h.SendGroupMessage(bg, "nope", "x"); !errors.Is(err, services.ErrGroupNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.h.SendGroupMessage(bg, g.ID, " "); err == nil {
		t.Fatal("blank group message accepted")
	}

	// Alone in a group: fine, nothing to send.
	solo, _ := e.h.Groups.CreateGroup(bg, "Solo", "")
	before := e.net.count(protocol.KindMessage)
	if res, err := e.h.SendGroupMessage(bg, solo.ID, "notes to self"); err != nil || len(res.Queued) != 0 {
		t.Fatalf("solo: %+v %v", res, err)
	}
	if e.net.count(protocol.KindMessage) != before {
		t.Fatal("sent something for a solo group")
	}
}

// ---- Group protocol ----------------------------------------------------------

func TestInviteIsAttributedToTheAuthenticatedSender(t *testing.T) {
	e := newEnv(t, 1, "me")
	inviter, victim := pid(2), pid(3)
	body := wireMsg(map[string]any{
		"invite_id": "inv1", "group_id": "grp1", "group_name": "Totally Legit\x1b[2J",
		"expires_at": time.Now().Add(time.Hour).UnixMilli(),
		"members":    []map[string]string{{"peer_id": inviter, "username": "Alice"}},
		// Fields that are not part of the payload must have no effect.
		"inviter_id": victim, "invitee_id": pid(77), "group_creator": victim,
	})
	e.net.handlers[protocol.KindGroupInvite](inviter, body)

	inv, err := e.db.GetInvite(bg, "inv1")
	if err != nil {
		t.Fatal(err)
	}
	if inv.InviterID != inviter || inv.InviteeID != e.self || inv.GroupCreator != inviter {
		t.Fatalf("invite attribution: %+v", inv)
	}
	if strings.ContainsAny(e.out.all(), "\x1b") || !strings.Contains(e.out.all(), "/accept grp1") {
		t.Fatalf("output %q", e.out.all())
	}

	// Garbage and invalid invites are ignored quietly.
	before := e.out.n()
	e.net.handlers[protocol.KindGroupInvite](inviter, []byte("nope"))
	e.net.handlers[protocol.KindGroupInvite](inviter, wireMsg(map[string]any{"invite_id": "../x", "group_id": "g"}))
	e.net.handlers[protocol.KindGroupInvite](inviter, wireMsg(map[string]any{"invite_id": "i2", "group_id": "g2", "expires_at": 1, "members": []any{}}))
	if e.out.n() != before {
		t.Fatalf("bad invites were shown: %q", e.out.all())
	}
}

func TestAcceptAndDeclineNotifyTheInviter(t *testing.T) {
	e := newEnv(t, 1, "me")
	inviter := pid(2)
	invite := func(id, group string) {
		e.net.handlers[protocol.KindGroupInvite](inviter, wireMsg(map[string]any{
			"invite_id": id, "group_id": group, "group_name": group, "expires_at": time.Now().Add(time.Hour).UnixMilli(),
			"members": []map[string]string{{"peer_id": inviter, "username": "Alice"}},
		}))
	}
	invite("i1", "g1")
	invite("i2", "g2")

	g, err := e.h.AcceptInvite(bg, "g1")
	if err != nil || !g.HasMember(e.self) {
		t.Fatalf("accept: %v %v", g, err)
	}
	var reply protocol.GroupInviteReply
	frames := e.net.framesTo(inviter, protocol.KindGroupInviteReply)
	_ = json.Unmarshal(frames[0].payload, &reply)
	if !reply.Accepted || reply.InviteID != "i1" || reply.Username != "me" {
		t.Fatalf("reply: %+v", reply)
	}

	if err := e.h.DeclineInvite(bg, "g2"); err != nil {
		t.Fatal(err)
	}
	frames = e.net.framesTo(inviter, protocol.KindGroupInviteReply)
	_ = json.Unmarshal(frames[1].payload, &reply)
	if reply.Accepted || reply.InviteID != "i2" {
		t.Fatalf("decline reply: %+v", reply)
	}
	if _, err := e.h.AcceptInvite(bg, "g1"); err == nil {
		t.Fatal("accepted the same invitation twice")
	}

	// An unreachable inviter is reported, but we are in the group.
	invite("i3", "g3")
	e.net.failFor[inviter] = errors.New("offline")
	g3, err := e.h.AcceptInvite(bg, "g3")
	if g3 == nil || err == nil || !strings.Contains(err.Error(), "joined") {
		t.Fatalf("got %v %v", g3, err)
	}
}

func TestCreatorFlowInviteReplyAndBroadcasts(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob, carol := pid(2), pid(3)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")

	if err := e.h.InviteToGroup(bg, g.ID, bob); err != nil {
		t.Fatal(err)
	}
	var inv protocol.GroupInvite
	_ = json.Unmarshal(e.net.framesTo(bob, protocol.KindGroupInvite)[0].payload, &inv)
	if inv.GroupID != g.ID || inv.GroupName != "Crew" || len(inv.Members) != 1 || inv.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("invite payload: %+v", inv)
	}

	// An impostor answering for Bob's invitation is ignored.
	e.net.handlers[protocol.KindGroupInviteReply](carol, wireMsg(map[string]any{"invite_id": inv.InviteID, "accepted": true, "username": "Carol"}))
	if ok, _ := e.h.Groups.IsMember(bg, g.ID, carol); ok {
		t.Fatal("a reply from the wrong peer added a member")
	}

	// Bob joins.
	e.net.handlers[protocol.KindGroupInviteReply](bob, wireMsg(map[string]any{"invite_id": inv.InviteID, "group_id": g.ID, "accepted": true, "username": "Bob\x1b[0m"}))
	e.settle()
	if ok, _ := e.h.Groups.IsMember(bg, g.ID, bob); !ok {
		t.Fatal("bob not added")
	}
	if !strings.Contains(e.out.all(), "joined group \"Crew\"") || strings.Contains(e.out.all(), "\x1b") {
		t.Fatalf("output %q", e.out.all())
	}
	// The newcomer is sent the full roster.
	if n := len(e.net.framesTo(bob, protocol.KindGroupUpdate)); n != 1 {
		t.Fatalf("roster updates to bob: %d", n)
	}

	// Inviting a member again, or a non-admin inviting, fails.
	if err := e.h.InviteToGroup(bg, g.ID, bob); err == nil {
		t.Fatal("invited an existing member")
	}

	// Removing Bob notifies him and applies locally.
	if err := e.h.RemoveMember(bg, g.ID, bob); err != nil {
		t.Fatal(err)
	}
	var upd protocol.GroupUpdate
	frames := e.net.framesTo(bob, protocol.KindGroupUpdate)
	_ = json.Unmarshal(frames[len(frames)-1].payload, &upd)
	if len(upd.Removed) != 1 || upd.Removed[0] != bob {
		t.Fatalf("removal update: %+v", upd)
	}
	if ok, _ := e.h.Groups.IsMember(bg, g.ID, bob); ok {
		t.Fatal("bob still a member")
	}
}

func TestGroupUpdateAuthorisation(t *testing.T) {
	e := newEnv(t, 1, "me")
	admin, member, stranger := pid(2), pid(3), pid(4)
	// Build a group created by `admin` that we belong to, via the invite path.
	e.net.handlers[protocol.KindGroupInvite](admin, wireMsg(map[string]any{
		"invite_id": "i1", "group_id": "g1", "group_name": "Crew", "expires_at": time.Now().Add(time.Hour).UnixMilli(),
		"members": []map[string]string{{"peer_id": admin, "username": "Admin"}, {"peer_id": member, "username": "Member"}},
	}))
	if _, err := e.h.AcceptInvite(bg, "g1"); err != nil {
		t.Fatal(err)
	}
	e.out.lines = nil

	upd := func(m map[string]any) []byte { m["group_id"] = "g1"; return wireMsg(m) }
	newbie := map[string]string{"peer_id": pid(50), "username": "Newbie"}

	e.net.handlers[protocol.KindGroupUpdate](stranger, upd(map[string]any{"added": []any{newbie}}))
	e.net.handlers[protocol.KindGroupUpdate](member, upd(map[string]any{"added": []any{newbie}}))
	e.net.handlers[protocol.KindGroupUpdate](member, upd(map[string]any{"removed": []string{admin}}))
	if ok, _ := e.h.Groups.IsMember(bg, "g1", pid(50)); ok {
		t.Fatal("unauthorised add applied")
	}
	if ok, _ := e.h.Groups.IsMember(bg, "g1", admin); !ok {
		t.Fatal("a member removed the admin")
	}
	if e.out.n() != 0 {
		t.Fatalf("rejected updates printed: %q", e.out.all())
	}

	e.net.handlers[protocol.KindGroupUpdate](admin, upd(map[string]any{"added": []any{newbie}}))
	e.net.handlers[protocol.KindGroupUpdate](member, upd(map[string]any{"removed": []string{member}}))
	if ok, _ := e.h.Groups.IsMember(bg, "g1", pid(50)); !ok {
		t.Fatal("admin add not applied")
	}
	if ok, _ := e.h.Groups.IsMember(bg, "g1", member); ok {
		t.Fatal("self-removal not applied")
	}
	if !strings.Contains(e.out.all(), "Newbie joined") || !strings.Contains(e.out.all(), "Member left") {
		t.Fatalf("output %q", e.out.all())
	}

	// Leaving notifies the rest; updates for unknown groups are ignored.
	if err := e.h.LeaveGroup(bg, "g1"); err != nil {
		t.Fatal(err)
	}
	if e.net.count(protocol.KindGroupUpdate) == 0 {
		t.Fatal("leaving was not announced")
	}
	e.net.handlers[protocol.KindGroupUpdate](admin, wireMsg(map[string]any{"group_id": "unknown", "added": []any{newbie}}))
	e.net.handlers[protocol.KindGroupUpdate](admin, []byte("junk"))
}

// ---- Peer events and lifecycle -----------------------------------------------

func TestPeerEventsUseRememberedNames(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	e.h.PeerConnected(alice, "Alice")
	e.h.PeerDisconnected(alice) // the connection (and its name) is gone by now
	out := e.out.all()
	if !strings.Contains(out, "Alice (00000000) connected") || !strings.Contains(out, "Alice (00000000) disconnected") {
		t.Fatalf("output %q", out)
	}
	if len(e.note.calls) != 2 {
		t.Fatalf("notifications %v", e.note.calls)
	}
}

func TestDisplayNameFallbacks(t *testing.T) {
	e := newEnv(t, 1, "me")
	p := pid(7)
	if got := e.h.DisplayName(p); got != "unknown (00000000)" {
		t.Fatalf("got %q", got)
	}
	e.peers.AddPeer(&models.Peer{ID: p, Username: "FromDiscovery", Address: "10.0.0.1", Port: 1, LastSeen: time.Now()})
	if got := e.h.DisplayName(p); got != "FromDiscovery (00000000)" {
		t.Fatalf("got %q", got)
	}
	e.net.names[p] = "FromHello"
	if got := e.h.DisplayName(p); got != "FromHello (00000000)" {
		t.Fatalf("got %q", got)
	}
	if got := e.h.DisplayName(e.self); got != "you" {
		t.Fatalf("got %q", got)
	}
}

func TestCloseStopsBackgroundWork(t *testing.T) {
	e := newEnv(t, 1, "me")
	e.h.Close()
	e.h.Close() // idempotent
	// After Close an incoming message is still stored and shown, but no
	// goroutine may be started to acknowledge it.
	e.net.handlers[protocol.KindMessage](pid(2), directBody("late", e.self, "after close"))
	if len(e.stored(t)) != 1 {
		t.Fatal("message lost after Close")
	}
	if e.net.count(protocol.KindAck) != 0 {
		t.Fatal("ack goroutine started after Close")
	}
}

func TestValidateContentAndWireID(t *testing.T) {
	good := []string{"hi", "multi\nline", "unicode ✓", strings.Repeat("x", MaxMessageBytes)}
	for _, s := range good {
		if err := ValidateContent(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	if err := ValidateContent(""); !errors.Is(err, apperrors.ErrMessageEmpty) {
		t.Errorf("got %v", err)
	}
	if err := ValidateContent(strings.Repeat("x", MaxMessageBytes+1)); !errors.Is(err, apperrors.ErrMessageTooLarge) {
		t.Errorf("got %v", err)
	}
	for id, want := range map[string]bool{"abc-123_X": true, "": false, "a b": false, "a/b": false, "é": false, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false} {
		if validWireID(id) != want {
			t.Errorf("validWireID(%q) != %v", id, want)
		}
	}
}
