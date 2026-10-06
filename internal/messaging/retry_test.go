package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/protocol"
)

func sentIDs(e *env, to string) []string {
	var ids []string
	for _, f := range e.net.framesTo(to, protocol.KindMessage) {
		var m models.ChatMessage
		_ = json.Unmarshal(f.payload, &m)
		ids = append(ids, m.ID)
	}
	return ids
}

// queue stores n undelivered messages for peer (as if it had been offline).
func queue(t *testing.T, e *env, peer string, texts ...string) {
	t.Helper()
	e.net.failFor[peer] = errors.New("offline")
	for _, text := range texts {
		if err := e.h.SendMessage(bg, peer, text); err == nil {
			t.Fatal("send to an offline peer should report failure")
		}
	}
	delete(e.net.failFor, peer)
}

func TestUndeliveredMessagesAreResentOnConnect(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob := pid(2)
	queue(t, e, bob, "one", "two", "three")
	if n := len(sentIDs(e, bob)); n != 0 {
		t.Fatalf("%d frames sent while offline", n)
	}
	stored := e.stored(t) // newest first
	oldestFirst := []string{stored[2].ID, stored[1].ID, stored[0].ID}

	e.h.PeerConnected(bob, "Bob")
	e.settle()
	got := sentIDs(e, bob)
	if strings.Join(got, ",") != strings.Join(oldestFirst, ",") {
		t.Fatalf("resent %v, want %v (oldest first, same IDs so the receiver can deduplicate)", got, oldestFirst)
	}
	if !strings.Contains(e.out.all(), "Resent 3 undelivered message(s) to Bob") {
		t.Fatalf("user not told: %q", e.out.all())
	}

	// Acknowledgements stop further retries.
	for _, id := range got {
		e.net.handlers[protocol.KindAck](bob, wireMsg(map[string]any{"message_id": id}))
	}
	n, err := e.h.RetryUndelivered(bg, bob)
	if err != nil || n != 0 || len(sentIDs(e, bob)) != 3 {
		t.Fatalf("retried acknowledged messages: n=%d err=%v frames=%d", n, err, len(sentIDs(e, bob)))
	}
}

func TestOnlyOurRecentDirectMessagesAreRetried(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob, carol := pid(2), pid(3)

	old := models.NewChatMessage("old", e.self, bob, "stale")
	old.Timestamp = time.Now().Add(-10 * 24 * time.Hour)
	mustSaveMsg(t, e, old)
	mustSaveMsg(t, e, models.NewChatMessage("incoming", bob, e.self, "theirs")) // received, not ours
	mustSaveMsg(t, e, models.NewChatMessage("other", e.self, carol, "for carol"))
	g, _ := e.h.Groups.CreateGroup(bg, "Crew", "")
	mustSaveMsg(t, e, models.NewGroupMessage("grp", e.self, g.ID, "group msg"))
	queue(t, e, bob, "fresh")

	n, err := e.h.RetryUndelivered(bg, bob)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var wire models.ChatMessage
	_ = json.Unmarshal(e.net.framesTo(bob, protocol.KindMessage)[0].payload, &wire)
	if wire.Message != "fresh" || wire.To != bob {
		t.Fatalf("resent the wrong message: %+v", wire)
	}
}

func mustSaveMsg(t *testing.T, e *env, m *models.ChatMessage) {
	t.Helper()
	if ok, err := e.db.SaveMessage(bg, m); err != nil || !ok {
		t.Fatalf("save: %v %v", ok, err)
	}
}

func TestRetryStopsAtTheFirstFailure(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob := pid(2)
	queue(t, e, bob, "a", "b", "c")

	flaky := &failAfter{fakeNet: e.net, ok: 1}
	e.h.Net = flaky
	n, err := e.h.RetryUndelivered(bg, bob)
	if err == nil || n != 1 || flaky.calls != 2 {
		t.Fatalf("n=%d err=%v calls=%d: want one sent, stop at the failure, never try the third", n, err, flaky.calls)
	}
	if strings.Contains(e.out.all(), "Resent") {
		t.Fatalf("claimed success after a failure: %q", e.out.all())
	}
}

// failAfter lets `ok` sends through and then fails.
type failAfter struct {
	*fakeNet
	ok, calls int
}

func (f *failAfter) SendJSON(ctx context.Context, to string, k protocol.Kind, v any) error {
	f.calls++
	if f.calls > f.ok {
		return errors.New("link dropped")
	}
	return f.fakeNet.SendJSON(ctx, to, k, v)
}

func TestRetryAllSkipsPeersWeCannotSee(t *testing.T) {
	e := newEnv(t, 1, "me")
	seen, hidden, connected := pid(2), pid(3), pid(4)
	queue(t, e, seen, "to seen")
	queue(t, e, hidden, "to hidden")
	queue(t, e, connected, "to connected")
	e.peers.AddPeer(&models.Peer{ID: seen, Username: "Seen", Address: "10.0.0.2", Port: 1, LastSeen: time.Now()})
	e.net.offline[seen], e.net.offline[hidden] = true, true // only `connected` has a live connection

	e.h.RetryAll(bg)
	if len(sentIDs(e, seen)) != 1 {
		t.Fatal("a recently announced peer was not retried")
	}
	if len(sentIDs(e, connected)) != 1 {
		t.Fatal("a connected peer was not retried")
	}
	if len(sentIDs(e, hidden)) != 0 {
		t.Fatal("a peer nobody has seen was contacted")
	}
}

func TestOneRetryPerPeerAtATime(t *testing.T) {
	e := newEnv(t, 1, "me")
	bob := pid(2)
	queue(t, e, bob, "x")
	e.h.retrying.Store(bob, struct{}{}) // a retry is already running
	if n, err := e.h.RetryUndelivered(bg, bob); n != 0 || err != nil || len(sentIDs(e, bob)) != 0 {
		t.Fatalf("concurrent retry was not suppressed: n=%d err=%v", n, err)
	}
	e.h.retrying.Delete(bob)
	if n, _ := e.h.RetryUndelivered(bg, bob); n != 1 {
		t.Fatalf("n=%d after the first retry finished", n)
	}
}
