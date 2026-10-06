package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

type dispatched struct {
	to   string
	text string
	id   string
}

// fakeRelay records what the handler hands to relays.
type fakeRelay struct {
	mu    sync.Mutex
	calls []dispatched
	err   error            // returned for every call
	errTo map[string]error // or per recipient
	n     int
}

func (f *fakeRelay) Dispatch(_ context.Context, to string, plaintext []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errTo[to]; err != nil {
		return 0, err
	}
	if f.err != nil {
		return 0, f.err
	}
	var m models.ChatMessage
	_ = json.Unmarshal(plaintext, &m)
	f.calls = append(f.calls, dispatched{to: to, text: m.Message, id: m.ID})
	if f.n == 0 {
		return 1, nil
	}
	return f.n, nil
}

func (f *fakeRelay) to(peer string) []dispatched {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []dispatched
	for _, c := range f.calls {
		if c.to == peer {
			out = append(out, c)
		}
	}
	return out
}

func withRelay(e *env) *fakeRelay {
	f := &fakeRelay{errTo: map[string]error{}}
	e.h.Relay = f
	return f
}

func TestOfflineRecipientGetsAQueuedMessageNotAnError(t *testing.T) {
	e := newEnv(t, 1, "me")
	relay := withRelay(e)
	bob := pid(2)
	e.net.failFor[bob] = errors.New("peer not reachable")

	err := e.h.SendMessage(bg, bob, "hello while you are away")
	if !IsQueued(err) {
		t.Fatalf("got %v, want a QueuedError", err)
	}
	var q *QueuedError
	if !errors.As(err, &q) || q.Relays != 1 || !strings.Contains(err.Error(), "queued") {
		t.Fatalf("queued error: %+v %v", q, err)
	}
	calls := relay.to(bob)
	if len(calls) != 1 || calls[0].text != "hello while you are away" {
		t.Fatalf("relay got %+v", calls)
	}

	// Stored locally, still undelivered (delivery is proven by a receipt), but
	// flagged as relayed so it is not queued again.
	stored := e.stored(t)
	if len(stored) != 1 || stored[0].Delivered {
		t.Fatalf("stored: %+v", stored)
	}
	if unrelayed, _ := e.db.GetUnrelayedDirect(bg, e.self, bob, time.Now().Add(-time.Hour), 10); len(unrelayed) != 0 {
		t.Fatal("a queued message is still marked as not relayed")
	}
	if und, _ := e.db.GetUndeliveredDirect(bg, e.self, bob, time.Now().Add(-time.Hour), 10); len(und) != 1 {
		t.Fatal("queueing with a relay must not count as delivery")
	}
}

func TestWhenNoRelayCanHelpTheOriginalErrorIsReported(t *testing.T) {
	e := newEnv(t, 1, "me")
	relay := withRelay(e)
	relay.err = errors.New("no connected peer agreed to hold the message")
	bob := pid(2)
	e.net.failFor[bob] = errors.New("peer not reachable")

	err := e.h.SendMessage(bg, bob, "anyone?")
	if err == nil || IsQueued(err) || !strings.Contains(err.Error(), "saved but not delivered") {
		t.Fatalf("got %v", err)
	}
	// It stays eligible for relaying later.
	if unrelayed, _ := e.db.GetUnrelayedDirect(bg, e.self, bob, time.Now().Add(-time.Hour), 10); len(unrelayed) != 1 {
		t.Fatal("a message that could not be queued must remain unrelayed")
	}
}

func TestReachableRecipientsAreNotRelayed(t *testing.T) {
	e := newEnv(t, 1, "me")
	relay := withRelay(e)
	if err := e.h.SendMessage(bg, pid(2), "direct is better"); err != nil {
		t.Fatal(err)
	}
	if len(relay.calls) != 0 {
		t.Fatal("a message that went out directly was also given to relays")
	}
}

func TestRetryQueuesPendingMessagesWithRelaysOnceAndOnlyOnce(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob := pid(2)
	queue(t, e, bob, "one", "two") // no relay is attached yet, so both stay unrelayed
	relay := withRelay(e)          // ...until the relay becomes available
	e.net.failFor[bob] = errors.New("offline")

	n, err := e.h.RetryUndelivered(bg, bob)
	if err == nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := relay.to(bob); len(got) != 2 || got[0].text != "one" || got[1].text != "two" {
		t.Fatalf("relayed %+v (oldest first)", got)
	}
	if !strings.Contains(e.out.all(), "2 message(s) queued with relays") {
		t.Fatalf("user not told: %q", e.out.all())
	}
	_, _ = e.h.RetryUndelivered(bg, bob) // the periodic retry runs again
	if len(relay.to(bob)) != 2 {
		t.Fatalf("messages were queued with relays again: %d", len(relay.to(bob)))
	}
}

func TestRetryAllQueuesForPeersWeCannotSee(t *testing.T) {
	e := newEnv(t, 1, "me")
	invisible := pid(2)
	queue(t, e, invisible, "for the invisible peer")
	relay := withRelay(e)
	e.net.offline[invisible] = true // not connected, not in the peer registry

	e.h.RetryAll(bg)
	if len(relay.to(invisible)) != 1 {
		t.Fatalf("an offline peer's message was not queued: %+v", relay.calls)
	}
	e.h.RetryAll(bg)
	if len(relay.to(invisible)) != 1 {
		t.Fatal("queued twice")
	}
}

func TestGroupMessageToOfflineMembersIsRelayed(t *testing.T) {
	e := newEnv(t, 1, "me")
	relay := withRelay(e)
	alice, bob, carol := pid(2), pid(3), pid(4)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	for _, p := range []string{alice, bob, carol} {
		_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, p, "member", models.RoleMember))
	}
	e.net.failFor[bob] = errors.New("offline")
	e.net.failFor[carol] = errors.New("offline")
	relay.errTo[carol] = errors.New("nobody can hold it")

	res, err := e.h.SendGroupMessage(bg, g.ID, "team news")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Queued) != 1 || res.Queued[0] != alice {
		t.Fatalf("queued: %v", res.Queued)
	}
	if len(res.Relayed) != 1 || res.Relayed[0] != bob {
		t.Fatalf("relayed: %v", res.Relayed)
	}
	if res.Failed[carol] == nil || len(res.Failed) != 1 {
		t.Fatalf("failed: %v", res.Failed)
	}
	if len(relay.to(bob)) != 1 || relay.to(bob)[0].text != "team news" {
		t.Fatalf("relay: %+v", relay.calls)
	}

	// If everyone is unreachable but relays took it, that counts as success.
	e.net.failFor[alice] = errors.New("offline")
	delete(relay.errTo, carol)
	if res, err := e.h.SendGroupMessage(bg, g.ID, "again"); err != nil || len(res.Relayed) != 3 {
		t.Fatalf("all relayed: %+v %v", res, err)
	}
}

// ---- Receiving relayed messages ------------------------------------------------

func relayedPlain(id, to, text string, ts time.Time) []byte {
	b, _ := json.Marshal(map[string]any{"id": id, "to": to, "message": text, "type": "direct", "timestamp": ts})
	return b
}

func TestRelayedMessageIsStoredLikeALiveOneButKeepsItsOriginalTime(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2)
	e.net.names[alice] = "Alice"
	sent := time.Now().Add(-3 * time.Hour).Truncate(time.Second)

	id, ok := e.h.AcceptRelayed(bg, alice, relayedPlain("m1", e.self, "sorry I missed you", sent))
	if !ok || id != "m1" {
		t.Fatalf("got %q %v", id, ok)
	}
	msgs := e.stored(t)
	if len(msgs) != 1 || msgs[0].From != alice || msgs[0].Delivered != true || msgs[0].Read {
		t.Fatalf("stored: %+v", msgs)
	}
	if !msgs[0].Timestamp.Equal(sent) {
		t.Fatalf("the original send time was lost: %v vs %v", msgs[0].Timestamp, sent)
	}
	if out := e.out.all(); !strings.Contains(out, "Alice (00000000): sorry I missed you") || !strings.Contains(out, sent.Format("2006-01-02")) {
		t.Fatalf("display: %q", out)
	}
	if len(e.note.calls) != 1 {
		t.Fatalf("notifications: %v", e.note.calls)
	}

	// A second copy (several relays) is accepted for its receipt but shown once.
	if id, ok := e.h.AcceptRelayed(bg, alice, relayedPlain("m1", e.self, "sorry I missed you", sent)); !ok || id != "m1" {
		t.Fatal("a duplicate must still be reported as accepted")
	}
	if len(e.stored(t)) != 1 || strings.Count(e.out.all(), "sorry I missed you") != 1 {
		t.Fatal("the duplicate was stored or shown again")
	}
}

func TestRelayedTimestampsAreClamped(t *testing.T) {
	e := newEnv(t, 1, "me")
	for id, ts := range map[string]time.Time{
		"future":  time.Now().Add(24 * time.Hour),
		"ancient": time.Now().Add(-30 * 24 * time.Hour),
		"zero":    {},
	} {
		if _, ok := e.h.AcceptRelayed(bg, pid(2), relayedPlain(id, e.self, id, ts)); !ok {
			t.Fatalf("%s: rejected", id)
		}
	}
	for _, m := range e.stored(t) {
		if age := time.Since(m.Timestamp); age < -time.Minute || age > time.Minute {
			t.Errorf("%s: an implausible timestamp was trusted: %v", m.ID, m.Timestamp)
		}
	}
}

func TestSendersNameTravelsWithARelayedMessage(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice := pid(2) // never seen online: no live name known
	plain := []byte(`{"id":"m1","to":"` + e.self + `","message":"hi","type":"direct","sender_name":"Alice\u001b[2J\n"}`)
	if _, ok := e.h.AcceptRelayed(bg, alice, plain); !ok {
		t.Fatal("rejected")
	}
	out := e.out.all()
	if !strings.Contains(out, "Alice") || strings.Contains(out, "unknown") || strings.ContainsAny(out, "") {
		t.Fatalf("the sender should be shown by their (sanitised) name: %q", out)
	}
}

func TestOutgoingRelayedPayloadCarriesOurName(t *testing.T) {
	e := newEnv(t, 1, "Me Myself")
	var payload []byte
	e.h.Relay = relayFunc(func(_ context.Context, _ string, p []byte) (int, error) { payload = p; return 1, nil })
	bob := pid(2)
	e.net.failFor[bob] = errors.New("offline")
	if !IsQueued(e.h.SendMessage(bg, bob, "hi")) {
		t.Fatal("not queued")
	}
	if !strings.Contains(string(payload), `"sender_name":"Me Myself"`) {
		t.Fatalf("payload: %s", payload)
	}
}

type relayFunc func(context.Context, string, []byte) (int, error)

func (f relayFunc) Dispatch(ctx context.Context, to string, p []byte) (int, error) {
	return f(ctx, to, p)
}

// Relayed messages get no shortcut around validation.
func TestRelayedMessagesAreValidatedLikeLiveOnes(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice, outsider := pid(2), pid(3)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, alice, "Alice", models.RoleMember))

	bad := map[string][]byte{
		"not json":          []byte("garbage"),
		"empty text":        relayedPlain("a1", e.self, "  ", time.Now()),
		"too long":          relayedPlain("a2", e.self, strings.Repeat("x", MaxMessageBytes+1), time.Now()),
		"bad id":            relayedPlain("../x", e.self, "hi", time.Now()),
		"addressed to bob":  relayedPlain("a3", pid(9), "hi", time.Now()),
		"system message":    []byte(`{"id":"a4","to":"` + e.self + `","message":"hi","type":"system"}`),
		"group, non-member": []byte(`{"id":"a5","group_id":"` + g.ID + `","message":"hi","type":"group"}`),
	}
	for name, plain := range bad {
		from := alice
		if name == "group, non-member" {
			from = outsider
		}
		if _, ok := e.h.AcceptRelayed(bg, from, plain); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := len(e.stored(t)); n != 0 {
		t.Fatalf("%d invalid relayed messages were stored", n)
	}

	// A member's group message through a relay is fine and names the group.
	good := []byte(`{"id":"g1","group_id":"` + g.ID + `","message":"team news","type":"group"}`)
	if _, ok := e.h.AcceptRelayed(bg, alice, good); !ok {
		t.Fatal("a member's relayed group message was rejected")
	}
	if !strings.Contains(e.out.all(), "[Crew] Alice") {
		t.Fatalf("output %q", e.out.all())
	}
}

func TestTheSenderIsTheAuthenticatedOneNotTheOneInThePayload(t *testing.T) {
	e := newEnv(t, 1, "me")
	alice, mallory := pid(2), pid(3)
	// Mallory's message claims to be from Alice; the authenticated sender wins.
	plain := []byte(`{"id":"m1","from":"` + alice + `","to":"` + e.self + `","message":"pay me","type":"direct"}`)
	if _, ok := e.h.AcceptRelayed(bg, mallory, plain); !ok {
		t.Fatal("rejected")
	}
	if got := e.stored(t); len(got) != 1 || got[0].From != mallory {
		t.Fatalf("stored sender: %+v", got)
	}
}

// ---- Receipts -------------------------------------------------------------------

func TestReceiptsMarkDeliveryOnlyWhenSignedByTheRecipient(t *testing.T) {
	e := newEnv(t, 1, "me")
	withRelay(e)
	bob, mallory := pid(2), pid(3)
	e.net.failFor[bob] = errors.New("offline")
	_ = e.h.SendMessage(bg, bob, "for bob")
	msgs := e.stored(t)
	id := msgs[0].ID

	e.h.ApplyReceipt(bg, id, mallory) // a valid receipt, but from the wrong person
	if e.stored(t)[0].Delivered {
		t.Fatal("a receipt from someone other than the recipient marked the message delivered")
	}
	e.h.ApplyReceipt(bg, "unknown-id", bob) // unknown message: ignored
	e.h.ApplyReceipt(bg, id, bob)
	if !e.stored(t)[0].Delivered {
		t.Fatal("the recipient's receipt was not applied")
	}
	// Once delivered, it is no longer retried or relayed.
	if und, _ := e.db.GetUndeliveredDirect(bg, e.self, bob, time.Now().Add(-time.Hour), 10); len(und) != 0 {
		t.Fatal("a delivered message is still queued for retry")
	}
}

func TestGroupReceiptsMustComeFromMembers(t *testing.T) {
	e := newEnv(t, 1, "me")
	withRelay(e)
	bob, outsider := pid(2), pid(3)
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	_ = e.db.AddGroupMember(bg, models.NewGroupMember(g.ID, bob, "Bob", models.RoleMember))
	e.net.failFor[bob] = errors.New("offline")
	if _, err := e.h.SendGroupMessage(bg, g.ID, "team news"); err != nil {
		t.Fatal(err)
	}
	id := e.stored(t)[0].ID

	e.h.ApplyReceipt(bg, id, outsider)
	if e.stored(t)[0].Delivered {
		t.Fatal("a non-member's receipt counted")
	}
	e.h.ApplyReceipt(bg, id, bob)
	if !e.stored(t)[0].Delivered {
		t.Fatal("a member's receipt was ignored")
	}
}
