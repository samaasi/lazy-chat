package storage

import (
	"testing"
	"time"
)

func TestPeerBook(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	put := func(id, name, addr string, port int, age time.Duration) {
		t.Helper()
		if err := db.RememberPeer(ctx, KnownPeer{ID: id, Username: name, Address: addr, Port: port, LastConnected: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	put("aaa", "gilead", "192.168.1.36", 8080, 2*time.Hour)
	put("bbb", "carol", "192.168.1.52", 8080, time.Hour)
	put("old", "gone", "10.0.0.9", 8080, 90*24*time.Hour)
	put("aaa", "Gilead", "192.168.1.40", 9000, time.Minute) // moved: updated in place

	got, err := db.KnownPeers(ctx, now.Add(-30*24*time.Hour), 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("known: %+v %v", got, err)
	}
	if g := got[0]; g.ID != "aaa" || g.Username != "Gilead" || g.Address != "192.168.1.40" || g.Port != 9000 {
		t.Fatalf("most recent first, with the new address: %+v", g)
	}
	if lim, _ := db.KnownPeers(ctx, time.Time{}, 1); len(lim) != 1 {
		t.Fatal("limit ignored")
	}
	if ok, err := db.ForgetPeer(ctx, "bbb"); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if ok, _ := db.ForgetPeer(ctx, "bbb"); ok {
		t.Fatal("forgot twice")
	}
	if err := db.ForgetAllPeers(ctx); err != nil {
		t.Fatal(err)
	}
	if all, _ := db.KnownPeers(ctx, time.Time{}, 10); len(all) != 0 {
		t.Fatalf("left: %+v", all)
	}
}
