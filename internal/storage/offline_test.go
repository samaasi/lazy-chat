package storage

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSignedPrekeyLifecycle(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	old, err := db.SaveSPK(ctx, SPKRecord{Pub: key(1), Priv: key(11), Created: now.Add(-40 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := db.SaveSPK(ctx, SPKRecord{Pub: key(2), Priv: key(22), Created: now})
	if cur <= old {
		t.Fatalf("IDs must increase: %d then %d", old, cur)
	}
	if err := db.UpdateSPKSignature(ctx, cur, []byte("sig")); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetSPK(ctx, cur)
	if err != nil || !bytes.Equal(got.Priv, key(22)) || !bytes.Equal(got.Pub, key(2)) || string(got.Sig) != "sig" {
		t.Fatalf("GetSPK: %+v %v", got, err)
	}
	if _, err := db.GetSPK(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	recent, _ := db.ListSPKs(ctx, now.Add(-24*time.Hour))
	if len(recent) != 1 || recent[0].ID != cur {
		t.Fatalf("recent: %+v", recent)
	}
	all, _ := db.ListSPKs(ctx, now.Add(-100*24*time.Hour))
	if len(all) != 2 || all[0].ID != cur {
		t.Fatalf("newest must come first: %+v", all)
	}

	n, err := db.DeleteSPKsBefore(ctx, now.Add(-21*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("delete old: %d %v", n, err)
	}
	// Even if everything is old, the newest is kept so we can always be reached.
	if n, _ := db.DeleteSPKsBefore(ctx, now.Add(time.Hour)); n != 0 {
		t.Fatalf("the newest signed prekey was deleted (%d)", n)
	}
	if _, err := db.GetSPK(ctx, cur); err != nil {
		t.Fatal(err)
	}
}

func TestOneTimePrekeys(t *testing.T) {
	db := openDB(t)
	ids, err := db.CreateOPKs(ctx, []OPKRecord{
		{Pub: key(1), Priv: key(11), ReservedFor: "alice", Created: time.Now()},
		{Pub: key(2), Priv: key(22), ReservedFor: "alice", Created: time.Now()},
		{Pub: key(3), Priv: key(33), ReservedFor: "bob", Created: time.Now().Add(-90 * 24 * time.Hour)},
	})
	if err != nil || len(ids) != 3 {
		t.Fatalf("create: %v %v", ids, err)
	}
	if n, _ := db.CountOPKs(ctx); n != 3 {
		t.Fatalf("count %d", n)
	}
	list, _ := db.UnusedOPKs(ctx, "alice")
	if len(list) != 2 || list[0].ID != ids[0] || !bytes.Equal(list[0].Pub, key(1)) || list[0].Priv != nil {
		t.Fatalf("listing must show public halves only: %+v", list)
	}

	got, err := db.GetOPK(ctx, ids[0], "alice")
	if err != nil || !bytes.Equal(got.Priv, key(11)) {
		t.Fatalf("GetOPK: %+v %v", got, err)
	}
	// Reserved for Alice means nobody else can use it.
	if _, err := db.GetOPK(ctx, ids[0], "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another peer obtained Alice's prekey: %v", err)
	}

	if err := db.DeleteOPK(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetOPK(ctx, ids[0], "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a used prekey must be gone: %v", err)
	}
	if n, err := db.DeleteOPKsBefore(ctx, time.Now().Add(-60*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	if n, _ := db.CountOPKs(ctx); n != 1 {
		t.Fatalf("count after cleanup %d", n)
	}
}

func TestBundleCache(t *testing.T) {
	db := openDB(t)
	if _, _, err := db.GetBundle(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	t0 := time.Now().Add(-time.Hour)
	if err := db.SaveBundle(ctx, "bob", []byte(`{"v":1}`), t0); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveBundle(ctx, "bob", []byte(`{"v":2}`), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	data, when, err := db.GetBundle(ctx, "bob")
	if err != nil || string(data) != `{"v":2}` || !when.After(t0) {
		t.Fatalf("got %q %v %v", data, when, err)
	}
	for i := range 5 {
		_ = db.SaveBundle(ctx, fmt.Sprintf("p%d", i), []byte("x"), time.Now().Add(time.Duration(i)*time.Second))
	}
	if n, err := db.PruneBundles(ctx, 3); err != nil || n != 3 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, _, err := db.GetBundle(ctx, "p4"); err != nil {
		t.Fatal("the most recent bundles must survive pruning")
	}
}

func TestPrivatePrekeysAndBundlesAreEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc.db")
	secretKey := []byte("PRIVATE-PREKEY-MATERIAL-0123456789")[:32]
	db, err := openWith(t, path, testVault(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveSPK(ctx, SPKRecord{Pub: key(5), Priv: secretKey, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ids, _ := db.CreateOPKs(ctx, []OPKRecord{{Pub: key(6), Priv: secretKey, ReservedFor: "alice", Created: time.Now()}})
	_ = db.SaveBundle(ctx, "bob", []byte("BUNDLE-FOR-SECRET-PEER"), time.Now())

	// Readable through the API...
	if got, err := db.GetOPK(ctx, ids[0], "alice"); err != nil || !bytes.Equal(got.Priv, secretKey) {
		t.Fatalf("round trip: %v", err)
	}
	if data, _, _ := db.GetBundle(ctx, "bob"); string(data) != "BUNDLE-FOR-SECRET-PEER" {
		t.Fatalf("bundle round trip: %q", data)
	}
	db.Close()

	// ...but not on disk, neither raw nor base64-encoded.
	disk := diskBytes(t, path)
	for name, needle := range map[string][]byte{
		"raw private key": secretKey, "base64 private key": []byte(base64.StdEncoding.EncodeToString(secretKey)), "bundle": []byte("BUNDLE-FOR-SECRET-PEER"),
	} {
		if bytes.Contains(disk, needle) {
			t.Errorf("%s found in plaintext on disk", name)
		}
	}
}

func TestEnablingEncryptionAlsoCoversPrekeysAndBundles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	plain, err := openWith(t, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("ANOTHER-PRIVATE-KEY-PATTERN-XYZ!")
	ids, _ := plain.CreateOPKs(ctx, []OPKRecord{{Pub: key(6), Priv: secret, ReservedFor: "alice", Created: time.Now()}})
	_ = plain.SaveBundle(ctx, "bob", []byte("PLAIN-BUNDLE-MARKER"), time.Now())
	plain.Close()
	if !bytes.Contains(diskBytes(t, path), []byte("PLAIN-BUNDLE-MARKER")) {
		t.Fatal("setup: expected plaintext before encryption")
	}

	enc, err := openWith(t, path, testVault(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := enc.GetOPK(ctx, ids[0], "alice"); err != nil || !bytes.Equal(got.Priv, secret) {
		t.Fatalf("private prekey lost across encryption: %v", err)
	}
	if data, _, _ := enc.GetBundle(ctx, "bob"); string(data) != "PLAIN-BUNDLE-MARKER" {
		t.Fatalf("bundle lost: %q", data)
	}
	enc.Close()
	disk := diskBytes(t, path)
	if bytes.Contains(disk, []byte("PLAIN-BUNDLE-MARKER")) {
		t.Fatal("plaintext bundle survived on disk")
	}
}

// ---- Relay -------------------------------------------------------------------

func env(id, submitter, to string, size int, now time.Time) RelayEnvelope {
	return RelayEnvelope{ID: id, Submitter: submitter, To: to, Blob: bytes.Repeat([]byte("x"), size), Created: now, Expires: now.Add(time.Hour)}
}

var generous = RelayLimits{MaxTotalBytes: 1 << 20, MaxPerSender: 100, MaxBytesPerSender: 1 << 20, MaxPerRecipient: 100, MaxReceipts: 100}

func TestRelayStoresAndHandsOverToTheRecipientOnly(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	for i := range 3 {
		if err := db.PutEnvelope(ctx, env(fmt.Sprintf("e%d", i), "alice", "bob", 100, now.Add(time.Duration(i)*time.Second)), generous); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.PutEnvelope(ctx, env("other", "alice", "carol", 100, now), generous)

	got, err := db.EnvelopesFor(ctx, "bob", now, 10)
	if err != nil || len(got) != 3 || got[0].ID != "e0" || got[2].ID != "e2" {
		t.Fatalf("for bob (oldest first): %+v %v", got, err)
	}
	if lim, _ := db.EnvelopesFor(ctx, "bob", now, 2); len(lim) != 2 {
		t.Fatal("limit not applied")
	}

	// Only the recipient can take (and thereby acknowledge) an envelope.
	if _, err := db.TakeEnvelope(ctx, "e0", "carol"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("someone else took Bob's envelope: %v", err)
	}
	taken, err := db.TakeEnvelope(ctx, "e0", "bob")
	if err != nil || taken.Submitter != "alice" || len(taken.Blob) != 100 {
		t.Fatalf("take: %+v %v", taken, err)
	}
	if _, err := db.TakeEnvelope(ctx, "e0", "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("taken twice: %v", err)
	}
	if n, bytes, _ := db.RelayUsage(ctx); n != 3 || bytes != 300 {
		t.Fatalf("usage %d envelopes, %d bytes", n, bytes)
	}
}

func TestRelayIsIdempotentPerEnvelopeID(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	e := env("same", "alice", "bob", 50, now)
	for range 3 {
		if err := db.PutEnvelope(ctx, e, generous); err != nil {
			t.Fatal(err)
		}
	}
	if n, _, _ := db.RelayUsage(ctx); n != 1 {
		t.Fatalf("%d copies stored", n)
	}
	// A retry must not trip the quota, even when the sender is at the limit.
	tight := generous
	tight.MaxPerSender = 1
	if err := db.PutEnvelope(ctx, e, tight); err != nil {
		t.Fatalf("idempotent retry refused: %v", err)
	}
}

func TestRelayQuotas(t *testing.T) {
	now := time.Now()
	var q *QuotaError
	cases := map[string]struct {
		lim  RelayLimits
		fill func(db *SQLiteDB)
		put  RelayEnvelope
	}{
		"per sender count": {
			lim: RelayLimits{MaxPerSender: 2},
			fill: func(db *SQLiteDB) {
				db.PutEnvelope(ctx, env("a", "mallory", "x", 10, now), RelayLimits{})
				db.PutEnvelope(ctx, env("b", "mallory", "y", 10, now), RelayLimits{})
			},
			put: env("c", "mallory", "z", 10, now),
		},
		"per sender bytes": {
			lim:  RelayLimits{MaxBytesPerSender: 100},
			fill: func(db *SQLiteDB) { db.PutEnvelope(ctx, env("a", "mallory", "x", 90, now), RelayLimits{}) },
			put:  env("c", "mallory", "z", 20, now),
		},
		"per recipient": {
			lim: RelayLimits{MaxPerRecipient: 2},
			fill: func(db *SQLiteDB) {
				db.PutEnvelope(ctx, env("a", "m1", "victim", 10, now), RelayLimits{})
				db.PutEnvelope(ctx, env("b", "m2", "victim", 10, now), RelayLimits{})
			},
			put: env("c", "m3", "victim", 10, now),
		},
		"total bytes": {
			lim:  RelayLimits{MaxTotalBytes: 100},
			fill: func(db *SQLiteDB) { db.PutEnvelope(ctx, env("a", "m1", "x", 80, now), RelayLimits{}) },
			put:  env("c", "m2", "y", 30, now),
		},
	}
	for name, c := range cases {
		db := openDB(t)
		c.fill(db)
		if err := db.PutEnvelope(ctx, c.put, c.lim); !errors.As(err, &q) {
			t.Errorf("%s: want a QuotaError, got %v", name, err)
		}
		if n, _, _ := db.RelayUsage(ctx); n > 2 {
			t.Errorf("%s: refused envelope was stored anyway", name)
		}
	}

	// One abusive sender does not lock out others.
	db := openDB(t)
	lim := RelayLimits{MaxPerSender: 1}
	_ = db.PutEnvelope(ctx, env("a", "mallory", "x", 10, now), lim)
	if err := db.PutEnvelope(ctx, env("b", "alice", "x", 10, now), lim); err != nil {
		t.Fatalf("an unrelated sender was refused: %v", err)
	}
}

func TestRelayExpiry(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	live, dead := env("live", "a", "bob", 10, now), env("dead", "a", "bob", 10, now.Add(-2*time.Hour))
	dead.Expires = now.Add(-time.Hour)
	_ = db.PutEnvelope(ctx, live, generous)
	_ = db.PutEnvelope(ctx, dead, generous)
	_ = db.PutReceipt(ctx, RelayReceipt{Tag: "t1", MsgID: "m", Signer: "bob", EdPub: key(1), Sig: key(2), Expires: now.Add(-time.Minute)}, generous)
	_ = db.PutReceipt(ctx, RelayReceipt{Tag: "t2", MsgID: "n", Signer: "bob", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}, generous)

	if got, _ := db.EnvelopesFor(ctx, "bob", now, 10); len(got) != 1 || got[0].ID != "live" {
		t.Fatalf("expired envelopes must not be delivered: %+v", got)
	}
	if got, _ := db.ReceiptsForTags(ctx, []string{"t1", "t2"}, now, 10); len(got) != 1 || got[0].MsgID != "n" {
		t.Fatalf("expired receipts must not be delivered: %+v", got)
	}
	e, r, err := db.PurgeRelay(ctx, now)
	if err != nil || e != 1 || r != 1 {
		t.Fatalf("purge: %d %d %v", e, r, err)
	}
}

func TestRelayReceiptsAreAddressedByTagNotByIdentity(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	r := RelayReceipt{Tag: "tag-1", MsgID: "m1", Signer: "bob", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}
	for range 2 { // duplicates collapse
		if err := db.PutReceipt(ctx, r, generous); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ReceiptsForTags(ctx, []string{"tag-1"}, now, 10)
	if err != nil || len(got) != 1 || got[0].Signer != "bob" || !bytes.Equal(got[0].Sig, key(2)) {
		t.Fatalf("receipts: %+v %v", got, err)
	}
	// Asking with the wrong tag, or no tags, learns nothing.
	if other, _ := db.ReceiptsForTags(ctx, []string{"guess", "tag-2"}, now, 10); len(other) != 0 {
		t.Fatal("receipt visible under a tag that is not its own")
	}
	if none, err := db.ReceiptsForTags(ctx, nil, now, 10); err != nil || len(none) != 0 {
		t.Fatalf("no tags: %v %v", none, err)
	}
	// Several tags at once.
	_ = db.PutReceipt(ctx, RelayReceipt{Tag: "tag-2", MsgID: "m2", Signer: "carol", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}, generous)
	if both, _ := db.ReceiptsForTags(ctx, []string{"tag-1", "tag-2", "x"}, now, 10); len(both) != 2 {
		t.Fatalf("got %d receipts for two tags", len(both))
	}

	// The cap is per signer, so one recipient cannot fill the table.
	cap2 := RelayLimits{MaxReceipts: 2}
	for i := range 2 {
		_ = db.PutReceipt(ctx, RelayReceipt{Tag: fmt.Sprintf("d%d", i), MsgID: "m", Signer: "dave", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}, cap2)
	}
	var q *QuotaError
	if err := db.PutReceipt(ctx, RelayReceipt{Tag: "over", MsgID: "m", Signer: "dave", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}, cap2); !errors.As(err, &q) {
		t.Fatalf("receipt cap: %v", err)
	}
	if err := db.PutReceipt(ctx, RelayReceipt{Tag: "fine", MsgID: "m", Signer: "erin", EdPub: key(1), Sig: key(2), Expires: now.Add(time.Hour)}, cap2); err != nil {
		t.Fatalf("another signer was blocked: %v", err)
	}
}

func TestOutbox(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	add := func(msg, relay, to, tag string, age time.Duration) {
		t.Helper()
		if err := db.AddOutbox(ctx, OutboxEntry{MsgID: msg, RelayID: relay, To: to, Tag: tag, Created: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	add("m1", "relayA", "bob", "t1", time.Minute)
	add("m1", "relayA", "bob", "t1", time.Minute) // idempotent
	add("m1", "relayB", "bob", "t1", time.Minute)
	add("m2", "relayA", "carol", "t2", time.Minute)
	add("old", "relayA", "bob", "t3", 10*24*time.Hour)

	got, err := db.Outbox(ctx, now.Add(-7*24*time.Hour))
	if err != nil || len(got) != 3 {
		t.Fatalf("outbox: %d %v", len(got), err)
	}
	if err := db.DeleteOutbox(ctx, "m1", "bob"); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.Outbox(ctx, now.Add(-7*24*time.Hour)); len(got) != 1 || got[0].MsgID != "m2" {
		t.Fatalf("after receipt: %+v", got)
	}
	if n, err := db.PurgeOutbox(ctx, now.Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
}

// A database at schema v4 (relay holding messages under the old column name)
// upgrades in place to v5 and keeps what it was holding.
func TestUpgradeFromSchemaV4KeepsHeldMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.db")
	db := NewSQLiteDB(path)
	if err := db.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	tx, _ := db.db.Begin()
	for i := range 4 {
		for _, stmt := range migrations[i] {
			if _, err := tx.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _ = tx.Exec(`PRAGMA user_version = 4`)
	_, err := tx.Exec(`INSERT INTO relay_envelopes (id, from_peer, to_peer, blob, created, expires) VALUES ('e1', 'old-sender', 'bob', x'0102', 1, 99999999999999)`)
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit()
	db.Close()

	up := openAt(t, path)
	got, err := up.EnvelopesFor(ctx, "bob", time.Now(), 10)
	if err != nil || len(got) != 1 || got[0].ID != "e1" || got[0].Submitter != "old-sender" {
		t.Fatalf("held message lost or misread in the upgrade: %+v %v", got, err)
	}
	if err := up.AddOutbox(ctx, OutboxEntry{MsgID: "m", RelayID: "r", To: "t", Tag: "x", Created: time.Now()}); err != nil {
		t.Fatalf("v5 tables missing: %v", err)
	}
}

func TestRelayedFlagOnOwnMessages(t *testing.T) {
	db := openDB(t)
	mustSave(t, db, direct("m1", "me", "bob", "one"))
	mustSave(t, db, direct("m2", "me", "bob", "two"))
	mustSave(t, db, direct("m3", "me", "carol", "three"))
	since := time.Now().Add(-time.Hour)

	if got, err := db.GetMessage(ctx, "me", "m1"); err != nil || got.Message != "one" {
		t.Fatalf("GetMessage: %+v %v", got, err)
	}
	if _, err := db.GetMessage(ctx, "me", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if got, _ := db.GetUnrelayedDirect(ctx, "me", "bob", since, 10); len(got) != 2 {
		t.Fatalf("unrelayed: %d", len(got))
	}
	if err := db.MarkMessageRelayed(ctx, "me", "m1"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetUnrelayedDirect(ctx, "me", "bob", since, 10)
	if len(got) != 1 || got[0].ID != "m2" {
		t.Fatalf("a relayed message must not be relayed again: %+v", got)
	}
	// Still undelivered (relaying is not delivery), so direct retry continues.
	if und, _ := db.GetUndeliveredDirect(ctx, "me", "bob", since, 10); len(und) != 2 {
		t.Fatalf("relayed messages must stay undelivered until a receipt: %d", len(und))
	}
	if peers, _ := db.PeersWithUnrelayed(ctx, "me", since); len(peers) != 2 {
		t.Fatalf("peers: %v", peers)
	}
	_ = db.MarkMessageRelayed(ctx, "me", "m2")
	if peers, _ := db.PeersWithUnrelayed(ctx, "me", since); len(peers) != 1 || peers[0] != "carol" {
		t.Fatalf("peers after relaying: %v", peers)
	}
}
