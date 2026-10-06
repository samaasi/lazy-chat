package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

var ctx = context.Background()

func openDB(t *testing.T) *SQLiteDB {
	t.Helper()
	return openAt(t, filepath.Join(t.TempDir(), "chat.db"))
}

func openAt(t *testing.T, path string) *SQLiteDB {
	t.Helper()
	db := NewSQLiteDB(path)
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func direct(id, from, to, text string) *models.ChatMessage {
	return models.NewChatMessage(id, from, to, text)
}

func mustSave(t *testing.T, db *SQLiteDB, m *models.ChatMessage) {
	t.Helper()
	ok, err := db.SaveMessage(ctx, m)
	if err != nil || !ok {
		t.Fatalf("SaveMessage(%s): inserted=%v err=%v", m.ID, ok, err)
	}
}

func TestMigrateIsIdempotentAndVersioned(t *testing.T) {
	db := openDB(t)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var v int
	if err := db.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != len(migrations) {
		t.Fatalf("user_version = %d, %v", v, err)
	}
}

// Databases created by earlier versions (the schema from internal/database)
// must open cleanly, and the new schema must work afterwards.
func TestLegacySchemaIsRetired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE messages (id TEXT PRIMARY KEY, from_peer TEXT NOT NULL, content TEXT NOT NULL)`,
		`CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL)`,
		`CREATE TABLE group_members (group_id TEXT NOT NULL, peer_id TEXT NOT NULL, PRIMARY KEY (group_id, peer_id))`,
		`CREATE TABLE group_invites (id TEXT PRIMARY KEY, group_id TEXT NOT NULL)`,
		`CREATE INDEX idx_messages_from_peer ON messages(from_peer)`,
		`INSERT INTO messages VALUES ('old', 'someone', 'kept')`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	db := openAt(t, path)
	mustSave(t, db, direct("new", "a", "b", "works"))

	var kept string
	if err := db.db.QueryRow(`SELECT content FROM legacy_messages WHERE id = 'old'`).Scan(&kept); err != nil || kept != "kept" {
		t.Fatalf("legacy data not preserved: %q %v", kept, err)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	db := openDB(t)
	if _, err := db.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+1)); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err == nil {
		t.Fatal("must not run against a database from a newer version")
	}
}

func TestMessageRoundTripPreservesTimestampAndFlags(t *testing.T) {
	db := openDB(t)
	m := direct("m1", "alice", "bob", "héllo 👋")
	m.Timestamp = time.Date(2026, 3, 4, 5, 6, 7, 123_000_000, time.FixedZone("X", 5*3600))
	m.Read = true
	mustSave(t, db, m)

	got, err := db.GetMessages(ctx, Page{})
	if err != nil || len(got) != 1 {
		t.Fatalf("GetMessages: %v %v", got, err)
	}
	g := got[0]
	if !g.Timestamp.Equal(m.Timestamp) {
		t.Errorf("timestamp %v != %v", g.Timestamp, m.Timestamp)
	}
	if g.From != "alice" || g.To != "bob" || g.Message != "héllo 👋" || g.Type != models.MessageTypeDirect || !g.Read || g.Delivered || g.Seq == 0 {
		t.Errorf("unexpected row: %+v", g)
	}
}

func TestDuplicateAndIDCollisionHandling(t *testing.T) {
	db := openDB(t)
	mustSave(t, db, direct("same", "alice", "bob", "first"))

	ok, err := db.SaveMessage(ctx, direct("same", "alice", "bob", "replay"))
	if err != nil || ok {
		t.Fatalf("replay should be ignored: inserted=%v err=%v", ok, err)
	}
	// Another peer reusing alice's message ID must not block or overwrite it.
	mustSave(t, db, direct("same", "mallory", "bob", "squatting"))

	msgs, _ := db.GetMessages(ctx, Page{})
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	var firstText string
	for _, m := range msgs {
		if m.From == "alice" {
			firstText = m.Message
		}
	}
	if firstText != "first" {
		t.Fatalf("alice's message was altered: %q", firstText)
	}
}

func TestSchemaRejectsInconsistentMessages(t *testing.T) {
	db := openDB(t)
	bad := models.NewChatMessage("x", "a", "", "no recipient")
	if _, err := db.SaveMessage(ctx, bad); err == nil {
		t.Fatal("a direct message without a recipient must be rejected, not silently dropped")
	}
	both := models.NewChatMessage("y", "a", "b", "both")
	both.GroupID = "g"
	if _, err := db.SaveMessage(ctx, both); err == nil {
		t.Fatal("a direct message with a group must be rejected")
	}
}

func TestKeysetPagination(t *testing.T) {
	db := openDB(t)
	for i := range 120 {
		mustSave(t, db, direct(fmt.Sprintf("m%03d", i), "a", "b", fmt.Sprintf("msg %d", i)))
	}
	var seen []string
	page := Page{Limit: 50}
	for {
		batch, err := db.GetMessages(ctx, page)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) == 0 {
			break
		}
		for _, m := range batch {
			seen = append(seen, m.ID)
		}
		page.Before = batch[len(batch)-1].Seq
	}
	if len(seen) != 120 {
		t.Fatalf("saw %d messages, want 120", len(seen))
	}
	if seen[0] != "m119" || seen[119] != "m000" {
		t.Fatalf("not newest-first: %s ... %s", seen[0], seen[119])
	}
	dup := map[string]bool{}
	for _, id := range seen {
		if dup[id] {
			t.Fatalf("duplicate across pages: %s", id)
		}
		dup[id] = true
	}

	// New arrivals must not shift an in-progress walk (the OFFSET problem).
	first, _ := db.GetMessages(ctx, Page{Limit: 10})
	mustSave(t, db, direct("late", "a", "b", "late"))
	next, _ := db.GetMessages(ctx, Page{Limit: 10, Before: first[len(first)-1].Seq})
	if next[0].ID != "m109" {
		t.Fatalf("page shifted after insert: got %s", next[0].ID)
	}
	if got, _ := db.GetMessages(ctx, Page{Limit: 100000}); len(got) > maxPageSize {
		t.Fatalf("limit not capped: %d", len(got))
	}
}

func TestDirectConversationIsSymmetricAndIsolated(t *testing.T) {
	db := openDB(t)
	mustSave(t, db, direct("1", "alice", "bob", "hi bob"))
	mustSave(t, db, direct("2", "bob", "alice", "hi alice"))
	mustSave(t, db, direct("3", "alice", "carol", "secret"))
	mustSave(t, db, models.NewGroupMessage("4", "alice", "g1", "group"))

	for _, pair := range [][2]string{{"alice", "bob"}, {"bob", "alice"}} {
		got, err := db.GetDirectMessages(ctx, pair[0], pair[1], Page{})
		if err != nil || len(got) != 2 {
			t.Fatalf("%v: got %d, %v", pair, len(got), err)
		}
	}
	grp, _ := db.GetGroupMessages(ctx, "g1", Page{})
	if len(grp) != 1 || grp[0].ID != "4" {
		t.Fatalf("group messages: %+v", grp)
	}
}

func TestTimeRangeIgnoresTimeZones(t *testing.T) {
	db := openDB(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, loc := range []*time.Location{time.UTC, time.FixedZone("p", 9*3600), time.FixedZone("m", -8*3600)} {
		m := direct(fmt.Sprintf("t%d", i), "a", "b", "x")
		m.Timestamp = base.Add(time.Duration(i) * time.Hour).In(loc)
		mustSave(t, db, m)
	}
	got, err := db.GetMessagesByTimeRange(ctx, base.Add(30*time.Minute), base.Add(3*time.Hour), Page{})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %d messages, %v (want the two later ones)", len(got), err)
	}
}

func TestSearchTreatsWildcardsLiterally(t *testing.T) {
	db := openDB(t)
	mustSave(t, db, direct("1", "a", "b", "100% done"))
	mustSave(t, db, direct("2", "a", "b", "snake_case"))
	mustSave(t, db, direct("3", "a", "b", "nothing here"))
	mustSave(t, db, direct("4", "a", "b", `back\slash`))

	for query, want := range map[string]int{"100%": 1, "%": 1, "_": 1, "e_c": 1, `\`: 1, "NOTHING": 1, "zzz": 0} {
		got, err := db.SearchMessages(ctx, query, Page{})
		if err != nil || len(got) != want {
			t.Errorf("search %q: got %d, want %d (%v)", query, len(got), want, err)
		}
	}
}

func TestDeliveredReadDeleteAreScoped(t *testing.T) {
	db := openDB(t)
	mustSave(t, db, direct("d1", "alice", "bob", "hi"))
	if _, err := db.SaveMessage(ctx, models.NewGroupMessage("g1", "alice", "grp", "hello")); err != nil {
		t.Fatal(err)
	}
	creator := models.NewGroup("grp", "G", "", "alice")
	creator.AddMember("alice", "Alice")
	creator.AddMember("bob", "Bob")
	if err := db.CreateGroup(ctx, creator); err != nil {
		t.Fatal(err)
	}

	if err := db.MarkMessageAsDelivered(ctx, "alice", "d1"); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkMessageAsDelivered(ctx, "mallory", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("only the sender's own copy can be marked delivered, got %v", err)
	}

	if err := db.MarkMessageAsRead(ctx, "mallory", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger marked a message read: %v", err)
	}
	if err := db.MarkMessageAsRead(ctx, "alice", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sender should not mark own message as read-by-recipient: %v", err)
	}
	if err := db.MarkMessageAsRead(ctx, "bob", "d1"); err != nil {
		t.Fatalf("recipient: %v", err)
	}
	if err := db.MarkMessageAsRead(ctx, "bob", "g1"); err != nil {
		t.Fatalf("group member: %v", err)
	}

	if err := db.DeleteMessage(ctx, "mallory", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger deleted a message: %v", err)
	}
	if err := db.DeleteMessage(ctx, "bob", "d1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetDirectMessages(ctx, "alice", "bob", Page{}); len(got) != 0 {
		t.Fatal("deleted message still visible")
	}
	if err := db.DeleteMessage(ctx, "bob", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
}

func newGroup(id, creator string, members ...string) *models.Group {
	g := models.NewGroup(id, "Group "+id, "desc", creator)
	g.AddMember(creator, "name-"+creator)
	for _, m := range members {
		g.AddMember(m, "name-"+m)
	}
	return g
}

func TestGroupLifecycle(t *testing.T) {
	db := openDB(t)
	if err := db.CreateGroup(ctx, newGroup("g1", "alice", "bob")); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateGroup(ctx, models.NewGroup("g2", "x", "", "alice")); err == nil {
		t.Fatal("creator-less group accepted")
	}

	members, err := db.GetGroupMembers(ctx, "g1")
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %v %v", members, err)
	}
	roles := map[string]string{}
	for _, m := range members {
		roles[m.PeerID] = m.Role
	}
	if roles["alice"] != models.RoleAdmin || roles["bob"] != models.RoleMember {
		t.Fatalf("roles: %v", roles)
	}

	g, err := db.GetGroup(ctx, "g1")
	if err != nil || g.Members["bob"] != "name-bob" || g.CreatedBy != "alice" {
		t.Fatalf("GetGroup: %+v %v", g, err)
	}
	if _, err := db.GetGroup(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing group: %v", err)
	}

	if err := db.RemoveGroupMember(ctx, "g1", "bob"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.IsGroupMember(ctx, "g1", "bob"); ok {
		t.Fatal("removed member still counts as a member")
	}
	if members, _ := db.GetGroupMembers(ctx, "g1"); len(members) != 1 {
		t.Fatalf("removed member listed: %d", len(members))
	}
	if groups, _ := db.GetGroupsByMember(ctx, "bob"); len(groups) != 0 {
		t.Fatal("removed member still sees the group")
	}
	if err := db.RemoveGroupMember(ctx, "g1", "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal: %v", err)
	}

	if err := db.AddGroupMember(ctx, models.NewGroupMember("g1", "bob", "Bob2", models.RoleMember)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.IsGroupMember(ctx, "g1", "bob"); !ok {
		t.Fatal("re-added member not active")
	}

	if err := db.DeleteGroup(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.IsGroupMember(ctx, "g1", "alice"); ok {
		t.Fatal("membership of a deleted group must not authorise anything")
	}
}

func invite(id, group, inviter, invitee string, expires time.Time, members ...models.MemberRef) *models.GroupInvite {
	return &models.GroupInvite{
		ID: id, GroupID: group, GroupName: "Remote Group", GroupDescription: "d", GroupCreator: inviter,
		InviterID: inviter, InviteeID: invitee, CreatedAt: time.Now(), ExpiresAt: expires,
		Status: models.InviteStatusPending, Members: members,
	}
}

func TestAcceptInviteCreatesGroupAtomically(t *testing.T) {
	db := openDB(t)
	inv := invite("i1", "rg", "alice", "me", time.Now().Add(time.Hour),
		models.MemberRef{PeerID: "alice", Username: "Alice"}, models.MemberRef{PeerID: "carol", Username: "Carol"})
	if err := db.CreateInvite(ctx, inv); err != nil {
		t.Fatal(err)
	}

	if _, err := db.AcceptInvite(ctx, "i1", "someone-else", "x", time.Now()); !errors.Is(err, ErrInviteUnusable) {
		t.Fatalf("wrong invitee: %v", err)
	}
	g, err := db.AcceptInvite(ctx, "i1", "me", "My Name", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "Remote Group" || g.CreatedBy != "alice" || len(g.Members) != 3 || g.Members["me"] != "My Name" {
		t.Fatalf("group: %+v", g)
	}
	members, _ := db.GetGroupMembers(ctx, "rg")
	for _, m := range members {
		if (m.PeerID == "alice") != (m.Role == models.RoleAdmin) {
			t.Errorf("role of %s = %s", m.PeerID, m.Role)
		}
	}
	got, _ := db.GetInvite(ctx, "i1")
	if got.Status != models.InviteStatusAccepted || len(got.Members) != 2 {
		t.Fatalf("invite after accept: %+v", got)
	}
	if _, err := db.AcceptInvite(ctx, "i1", "me", "My Name", time.Now()); !errors.Is(err, ErrInviteUnusable) {
		t.Fatalf("an invite can only be used once: %v", err)
	}
	if _, err := db.AcceptInvite(ctx, "missing", "me", "x", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing invite: %v", err)
	}
}

func TestAcceptExpiredInviteFailsAndLeavesNoGroup(t *testing.T) {
	db := openDB(t)
	_ = db.CreateInvite(ctx, invite("old", "rg2", "alice", "me", time.Now().Add(-time.Minute),
		models.MemberRef{PeerID: "alice", Username: "Alice"}))
	if _, err := db.AcceptInvite(ctx, "old", "me", "x", time.Now()); !errors.Is(err, ErrInviteUnusable) {
		t.Fatalf("got %v", err)
	}
	if _, err := db.GetGroup(ctx, "rg2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a failed accept must not leave a group behind")
	}

	n, err := db.CleanupExpiredInvites(ctx, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("cleanup: %d %v", n, err)
	}
	if got, _ := db.GetInvite(ctx, "old"); got.Status != models.InviteStatusExpired {
		t.Fatalf("status %s", got.Status)
	}
}

func TestReinviteAfterLeavingResetsMembership(t *testing.T) {
	db := openDB(t)
	_ = db.CreateInvite(ctx, invite("a", "rg", "alice", "me", time.Now().Add(time.Hour),
		models.MemberRef{PeerID: "alice", Username: "Alice"}, models.MemberRef{PeerID: "gone", Username: "Gone"}))
	if _, err := db.AcceptInvite(ctx, "a", "me", "Me", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveGroupMember(ctx, "rg", "me"); err != nil {
		t.Fatal(err)
	}
	_ = db.CreateInvite(ctx, invite("b", "rg", "alice", "me", time.Now().Add(time.Hour),
		models.MemberRef{PeerID: "alice", Username: "Alice"}))
	g, err := db.AcceptInvite(ctx, "b", "me", "Me", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if g.HasMember("gone") || !g.HasMember("me") || !g.HasMember("alice") {
		t.Fatalf("stale members after rejoin: %v", g.Members)
	}
}

func TestPendingInviteCount(t *testing.T) {
	db := openDB(t)
	for i := range 3 {
		_ = db.CreateInvite(ctx, invite(fmt.Sprintf("p%d", i), fmt.Sprintf("g%d", i), "spammer", "me", time.Now().Add(time.Hour)))
	}
	_ = db.CreateInvite(ctx, invite("exp", "gx", "spammer", "me", time.Now().Add(-time.Hour)))
	n, err := db.CountPendingInvitesFrom(ctx, "spammer", "me", time.Now())
	if err != nil || n != 3 {
		t.Fatalf("count = %d, %v", n, err)
	}
}

func TestOddPathsAndPermissions(t *testing.T) {
	odd := "a#b%c d"
	if runtime.GOOS != "windows" {
		odd += "?e" // '?' is not a legal file name character on Windows
	}
	dir := filepath.Join(t.TempDir(), "with space", odd)
	db := openAt(t, filepath.Join(dir, "chat.db"))
	mustSave(t, db, direct("1", "a", "b", "x"))

	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, "chat.db"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("db perms: %v %v", st.Mode().Perm(), err)
		}
	}
}

func TestConcurrentWritersDoNotHitLockErrors(t *testing.T) {
	db := openDB(t)
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				if _, err := db.SaveMessage(ctx, direct(fmt.Sprintf("w%d-%d", w, i), fmt.Sprintf("p%d", w), "me", "x")); err != nil {
					errs <- err
				}
				if _, err := db.GetMessages(ctx, Page{Limit: 5}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got, _ := db.GetMessages(ctx, Page{Limit: 500}); len(got) != 400 {
		t.Fatalf("saved %d, want 400", len(got))
	}
}
