package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

func TestUndeliveredQueue(t *testing.T) {
	db := openDB(t)
	old := direct("old", "me", "bob", "ancient")
	old.Timestamp = time.Now().Add(-30 * 24 * time.Hour)
	mustSave(t, db, old)
	mustSave(t, db, direct("u1", "me", "bob", "first"))
	mustSave(t, db, direct("u2", "me", "bob", "second"))
	mustSave(t, db, direct("u3", "me", "carol", "for carol"))
	mustSave(t, db, direct("in", "bob", "me", "incoming")) // not ours to retry
	mustSave(t, db, direct("ok", "me", "bob", "acked"))
	if err := db.MarkMessageAsDelivered(ctx, "me", "ok"); err != nil {
		t.Fatal(err)
	}
	mustSave(t, db, direct("del", "me", "bob", "deleted"))
	if err := db.DeleteMessage(ctx, "me", "del"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveMessage(ctx, models.NewGroupMessage("g", "me", "grp", "group")); err != nil {
		t.Fatal(err)
	}

	since := time.Now().Add(-7 * 24 * time.Hour)
	got, err := db.GetUndeliveredDirect(ctx, "me", "bob", since, 10)
	if err != nil || len(got) != 2 || got[0].ID != "u1" || got[1].ID != "u2" {
		t.Fatalf("got %+v err=%v (want u1,u2 oldest first)", got, err)
	}
	if limited, _ := db.GetUndeliveredDirect(ctx, "me", "bob", since, 1); len(limited) != 1 || limited[0].ID != "u1" {
		t.Fatalf("limit not applied: %+v", limited)
	}
	peers, err := db.PeersWithUndelivered(ctx, "me", since)
	if err != nil || len(peers) != 2 {
		t.Fatalf("peers: %v %v", peers, err)
	}
}

func TestVerification(t *testing.T) {
	db := openDB(t)
	if ok, err := db.IsVerified(ctx, "bob"); err != nil || ok {
		t.Fatalf("fresh peer verified: %v %v", ok, err)
	}
	for range 2 { // idempotent
		if err := db.SetVerified(ctx, "bob", true); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := db.IsVerified(ctx, "bob"); !ok {
		t.Fatal("not verified")
	}
	_ = db.SetVerified(ctx, "carol", true)
	if all, _ := db.ListVerified(ctx); len(all) != 2 {
		t.Fatalf("list: %v", all)
	}
	if err := db.SetVerified(ctx, "bob", false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.IsVerified(ctx, "bob"); ok {
		t.Fatal("still verified")
	}
}

// A database created with the first schema version must upgrade in place.
func TestUpgradeFromSchemaV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db := NewSQLiteDB(path)
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range migrations[0] {
		if _, err := tx.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	mustSave(t, db, direct("keep", "a", "b", "kept across upgrade"))
	db.Close()

	up := openAt(t, path)
	if got, _ := up.GetMessages(ctx, Page{}); len(got) != 1 || got[0].ID != "keep" {
		t.Fatalf("data lost in upgrade: %+v", got)
	}
	if err := up.SetVerified(ctx, "x", true); err != nil {
		t.Fatalf("v2 table missing: %v", err)
	}
}
