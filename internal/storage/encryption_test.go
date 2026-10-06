package storage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/vault"
)

func testVault(t *testing.T, b byte) *vault.Vault {
	t.Helper()
	v, err := vault.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func openWith(t *testing.T, path string, v Sealer) (*SQLiteDB, error) {
	t.Helper()
	var opts []Option
	if v != nil {
		opts = append(opts, WithVault(v))
	}
	db := NewSQLiteDB(path, opts...)
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, db.Migrate(ctx)
}

// diskBytes returns everything SQLite has written for the database: the main
// file and any write-ahead log / shared-memory files.
func diskBytes(t *testing.T, path string) []byte {
	t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if b, err := os.ReadFile(path + suffix); err == nil {
			all = append(all, b...)
		}
	}
	return all
}

var secrets = []string{
	"SECRET-MESSAGE-TEXT", "SECRET-GROUP-NAME", "SECRET-GROUP-DESCRIPTION",
	"SECRET-MEMBER-NAME", "SECRET-INVITE-GROUP", "SECRET-INVITE-DESC", "SECRET-INVITER-NAME",
}

// populate writes at least one value into every sensitive column.
func populate(t *testing.T, db *SQLiteDB) {
	t.Helper()
	mustSave(t, db, direct("m1", "alice", "bob", "SECRET-MESSAGE-TEXT one"))
	mustSave(t, db, direct("m2", "bob", "alice", "another message"))
	if _, err := db.SaveMessage(ctx, models.NewGroupMessage("g1", "alice", "grp", "SECRET-MESSAGE-TEXT in a group")); err != nil {
		t.Fatal(err)
	}

	g := models.NewGroup("grp", "SECRET-GROUP-NAME", "SECRET-GROUP-DESCRIPTION", "alice")
	g.AddMember("alice", "Alice")
	g.AddMember("bob", "SECRET-MEMBER-NAME")
	if err := db.CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}

	inv := invite("inv1", "other-grp", "carol", "me", time.Now().Add(time.Hour),
		models.MemberRef{PeerID: "carol", Username: "SECRET-INVITER-NAME"})
	inv.GroupName, inv.GroupDescription = "SECRET-INVITE-GROUP", "SECRET-INVITE-DESC"
	if err := db.CreateInvite(ctx, inv); err != nil {
		t.Fatal(err)
	}
}

func assertNoSecretsOnDisk(t *testing.T, path string) {
	t.Helper()
	disk := diskBytes(t, path)
	for _, s := range secrets {
		if bytes.Contains(disk, []byte(s)) {
			t.Errorf("plaintext %q found on disk", s)
		}
	}
	if len(disk) == 0 {
		t.Fatal("nothing on disk to inspect")
	}
}

func TestEncryptedDatabaseHoldsNoPlaintextOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc.db")
	db, err := openWith(t, path, testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	populate(t, db)
	db.Close()

	assertNoSecretsOnDisk(t, path)
	// Identifiers stay readable so they can be indexed.
	if !bytes.Contains(diskBytes(t, path), []byte("alice")) {
		t.Log("(peer IDs are expected to be visible; not an error)")
	}
}

func TestEncryptedDatabaseRoundTripsEverything(t *testing.T) {
	db, err := openWith(t, filepath.Join(t.TempDir(), "enc.db"), testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	populate(t, db)

	msgs, err := db.GetDirectMessages(ctx, "alice", "bob", Page{})
	if err != nil || len(msgs) != 2 || msgs[1].Message != "SECRET-MESSAGE-TEXT one" {
		t.Fatalf("direct: %+v %v", msgs, err)
	}
	if grp, _ := db.GetGroupMessages(ctx, "grp", Page{}); len(grp) != 1 || !strings.Contains(grp[0].Message, "in a group") {
		t.Fatalf("group messages: %+v", grp)
	}
	g, err := db.GetGroup(ctx, "grp")
	if err != nil || g.Name != "SECRET-GROUP-NAME" || g.Description != "SECRET-GROUP-DESCRIPTION" || g.Members["bob"] != "SECRET-MEMBER-NAME" {
		t.Fatalf("group: %+v %v", g, err)
	}
	if byMember, _ := db.GetGroupsByMember(ctx, "alice"); len(byMember) != 1 || byMember[0].Name != "SECRET-GROUP-NAME" {
		t.Fatalf("groups by member: %+v", byMember)
	}
	if err := db.UpdateGroup(ctx, &models.Group{ID: "grp", Name: "Renamed", Description: "new desc"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := db.GetGroup(ctx, "grp"); g.Name != "Renamed" || g.Description != "new desc" {
		t.Fatalf("update: %+v", g)
	}
	if err := db.AddGroupMember(ctx, models.NewGroupMember("grp", "dave", "Dave", models.RoleMember)); err != nil {
		t.Fatal(err)
	}

	// Invitations, and accepting one (which copies sealed data between tables).
	got, err := db.GetInvite(ctx, "inv1")
	if err != nil || got.GroupName != "SECRET-INVITE-GROUP" || got.GroupDescription != "SECRET-INVITE-DESC" || got.Members[0].Username != "SECRET-INVITER-NAME" {
		t.Fatalf("invite: %+v %v", got, err)
	}
	joined, err := db.AcceptInvite(ctx, "inv1", "me", "My Name", time.Now())
	if err != nil || joined.Name != "SECRET-INVITE-GROUP" || joined.Members["carol"] != "SECRET-INVITER-NAME" || joined.Members["me"] != "My Name" {
		t.Fatalf("accept: %+v %v", joined, err)
	}
	if list, _ := db.GetInvitesByInvitee(ctx, "me"); len(list) != 1 || list[0].GroupName != "SECRET-INVITE-GROUP" {
		t.Fatalf("invite list: %+v", list)
	}
	if members, _ := db.GetGroupMembers(ctx, "other-grp"); len(members) != 2 {
		t.Fatalf("members: %+v", members)
	}
}

// The encrypted search must return exactly what the SQL search returns.
func TestEncryptedSearchMatchesPlainSearch(t *testing.T) {
	plain, _ := openWith(t, filepath.Join(t.TempDir(), "p.db"), nil)
	enc, err := openWith(t, filepath.Join(t.TempDir(), "e.db"), testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{"Hello World", "hello there", "100% sure", "snake_case", "back\\slash", "unrelated", "HELLO again", "héllo"}
	for i := range 120 {
		text := texts[i%len(texts)] + fmt.Sprintf(" #%d", i)
		for _, db := range []*SQLiteDB{plain, enc} {
			mustSave(t, db, direct(fmt.Sprintf("m%d", i), "a", "b", text))
		}
	}
	for _, q := range []string{"hello", "HELLO", "100%", "e_c", "\\", "zzz", "#7", "world"} {
		want, err1 := plain.SearchMessages(ctx, q, Page{Limit: 200})
		got, err2 := enc.SearchMessages(ctx, q, Page{Limit: 200})
		if err1 != nil || err2 != nil {
			t.Fatalf("%q: %v %v", q, err1, err2)
		}
		if len(want) != len(got) {
			t.Errorf("search %q: plain found %d, encrypted found %d", q, len(want), len(got))
			continue
		}
		for i := range want {
			if want[i].ID != got[i].ID {
				t.Errorf("search %q result %d: %s vs %s", q, i, want[i].ID, got[i].ID)
			}
		}
	}

	// Limits and cursors work the same way.
	page1, _ := enc.SearchMessages(ctx, "hello", Page{Limit: 5})
	page2, _ := enc.SearchMessages(ctx, "hello", Page{Limit: 5, Before: page1[4].Seq})
	if len(page1) != 5 || len(page2) != 5 || page2[0].Seq >= page1[4].Seq {
		t.Fatalf("paging: %d %d", len(page1), len(page2))
	}
}

func TestEnablingEncryptionOnAnExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "was-plain.db")
	plain, err := openWith(t, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	populate(t, plain)
	for i := range 1200 { // more than one internal batch
		mustSave(t, plain, direct(fmt.Sprintf("bulk%d", i), "alice", "bob", fmt.Sprintf("SECRET-MESSAGE-TEXT bulk %d", i)))
	}
	plain.Close()

	// Sanity: it really was plaintext.
	if !bytes.Contains(diskBytes(t, path), []byte("SECRET-GROUP-NAME")) {
		t.Fatal("test setup: expected plaintext on disk before encryption")
	}

	enc, err := openWith(t, path, testVault(t, 9))
	if err != nil {
		t.Fatalf("encrypting in place: %v", err)
	}
	// Nothing readable is left, not even in freed pages or the WAL.
	enc.Close()
	assertNoSecretsOnDisk(t, path)

	// And everything is still there.
	again, err := openWith(t, path, testVault(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	if msgs, _ := again.GetDirectMessages(ctx, "alice", "bob", Page{Limit: 500}); len(msgs) != 500 {
		t.Fatalf("messages after encryption: %d", len(msgs))
	}
	found, err := again.SearchMessages(ctx, "bulk 1199", Page{})
	if err != nil || len(found) != 1 {
		t.Fatalf("search after encryption: %d %v", len(found), err)
	}
	if g, err := again.GetGroup(ctx, "grp"); err != nil || g.Name != "SECRET-GROUP-NAME" || g.Members["bob"] != "SECRET-MEMBER-NAME" {
		t.Fatalf("group after encryption: %+v %v", g, err)
	}
	if inv, err := again.GetInvite(ctx, "inv1"); err != nil || inv.GroupName != "SECRET-INVITE-GROUP" {
		t.Fatalf("invite after encryption: %+v %v", inv, err)
	}
}

func TestWrongKeyAndMissingKeyAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc.db")
	db, err := openWith(t, path, testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	populate(t, db)
	db.Close()

	if _, err := openWith(t, path, testVault(t, 2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: got %v", err)
	}
	// Without a key the program must refuse, not show ciphertext as chat text
	// or quietly start a second, empty history.
	if _, err := openWith(t, path, nil); !errors.Is(err, ErrEncrypted) {
		t.Fatalf("no key: got %v", err)
	}
	if _, err := openWith(t, path, testVault(t, 1)); err != nil {
		t.Fatalf("the right key must still work: %v", err)
	}
}

func TestCiphertextCannotBeMovedBetweenRowsOrFields(t *testing.T) {
	db, err := openWith(t, filepath.Join(t.TempDir(), "enc.db"), testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	mustSave(t, db, direct("m1", "alice", "bob", "first message"))
	mustSave(t, db, direct("m2", "alice", "bob", "second message"))

	// An attacker with write access to the file copies m1's ciphertext over m2.
	if _, err := db.db.Exec(`UPDATE messages SET content = (SELECT content FROM messages WHERE id = 'm1') WHERE id = 'm2'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetMessages(ctx, Page{}); err == nil {
		t.Fatal("a ciphertext moved to another row was accepted")
	}
}

func TestTamperedCiphertextIsAnErrorNotGarbage(t *testing.T) {
	db, err := openWith(t, filepath.Join(t.TempDir(), "enc.db"), testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	mustSave(t, db, direct("m1", "alice", "bob", "authentic"))
	if _, err := db.db.Exec(`UPDATE messages SET content = 'e1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE id = 'm1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetMessages(ctx, Page{}); err == nil {
		t.Fatal("forged ciphertext accepted")
	}
	if _, err := db.db.Exec(`UPDATE messages SET content = 'plain text planted in the file' WHERE id = 'm1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetMessages(ctx, Page{}); err == nil {
		t.Fatal("plaintext planted in an encrypted database was accepted")
	}
}

func TestEmptyLegacyTablesAreDroppedWhenEncrypting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw := NewSQLiteDB(path)
	if err := raw.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE messages (id TEXT PRIMARY KEY, from_peer TEXT NOT NULL, content TEXT NOT NULL)`,
		`CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL)`,
	} {
		if _, err := raw.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	db, err := openWith(t, path, testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'legacy_%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d empty legacy tables survived", n)
	}
}
