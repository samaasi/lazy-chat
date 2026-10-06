package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

// ---- Prekeys -----------------------------------------------------------------

// SPKRecord is one of our signed prekeys, with its private half.
type SPKRecord struct {
	ID             uint32
	Pub, Priv, Sig []byte
	Created        time.Time
}

// OPKRecord is a one-time prekey reserved for one peer. Priv is only filled in
// by GetOPK; listings return public keys alone.
type OPKRecord struct {
	ID          uint32
	Pub, Priv   []byte
	ReservedFor string
	Created     time.Time
}

// PrekeyStorage persists our prekeys and the bundles of other peers.
type PrekeyStorage interface {
	SaveSPK(ctx context.Context, r SPKRecord) (uint32, error)
	// UpdateSPKSignature attaches the signature once the ID is known.
	UpdateSPKSignature(ctx context.Context, id uint32, sig []byte) error
	ListSPKs(ctx context.Context, since time.Time) ([]SPKRecord, error)
	GetSPK(ctx context.Context, id uint32) (*SPKRecord, error)
	// DeleteSPKsBefore removes old signed prekeys but always keeps the newest.
	DeleteSPKsBefore(ctx context.Context, t time.Time) (int64, error)

	CreateOPKs(ctx context.Context, recs []OPKRecord) ([]uint32, error)
	UnusedOPKs(ctx context.Context, reservedFor string) ([]OPKRecord, error)
	GetOPK(ctx context.Context, id uint32, reservedFor string) (*OPKRecord, error)
	DeleteOPK(ctx context.Context, id uint32) error
	DeleteOPKsBefore(ctx context.Context, t time.Time) (int64, error)
	CountOPKs(ctx context.Context) (int, error)

	SaveBundle(ctx context.Context, peerID string, data []byte, updated time.Time) error
	GetBundle(ctx context.Context, peerID string) ([]byte, time.Time, error)
	// PruneBundles keeps only the max most recently updated bundles.
	PruneBundles(ctx context.Context, max int) (int64, error)
}

func aadPrekey(pub []byte) string    { return "prekeys.priv|" + hex.EncodeToString(pub) }
func aadBundle(peerID string) string { return "peer_bundles.bundle|" + peerID }

func (s *SQLiteDB) sealKey(pub, priv []byte) string {
	return s.seal(aadPrekey(pub), base64.StdEncoding.EncodeToString(priv))
}

func (s *SQLiteDB) openKey(pub []byte, stored string) ([]byte, error) {
	b64, err := s.open(aadPrekey(pub), stored)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(b64)
}

func idFromRow(v int64) (uint32, error) {
	if v <= 0 || v > 1<<32-1 {
		return 0, fmt.Errorf("prekey id %d out of range", v)
	}
	return uint32(v), nil
}

// SaveSPK stores a signed prekey and returns its assigned ID. The signature
// covers the ID, so callers sign after learning it (see offline.Service).
func (s *SQLiteDB) SaveSPK(ctx context.Context, r SPKRecord) (uint32, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO prekeys (kind, pub, priv, sig, created) VALUES ('spk', ?, ?, ?, ?)`,
		r.Pub, s.sealKey(r.Pub, r.Priv), r.Sig, ms(r.Created))
	if err != nil {
		return 0, fmt.Errorf("failed to save signed prekey: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return idFromRow(id)
}

// UpdateSPKSignature attaches the signature once the ID is known.
func (s *SQLiteDB) UpdateSPKSignature(ctx context.Context, id uint32, sig []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE prekeys SET sig = ? WHERE id = ? AND kind = 'spk'`, sig, id)
	if err != nil {
		return fmt.Errorf("failed to update signed prekey: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

func (s *SQLiteDB) scanSPK(sc interface{ Scan(...any) error }) (*SPKRecord, error) {
	var r SPKRecord
	var id, created int64
	var priv string
	if err := sc.Scan(&id, &r.Pub, &priv, &r.Sig, &created); err != nil {
		return nil, err
	}
	var err error
	if r.ID, err = idFromRow(id); err != nil {
		return nil, err
	}
	if r.Priv, err = s.openKey(r.Pub, priv); err != nil {
		return nil, err
	}
	r.Created = fromMs(created)
	return &r, nil
}

// ListSPKs returns signed prekeys created at or after since, newest first.
func (s *SQLiteDB) ListSPKs(ctx context.Context, since time.Time) ([]SPKRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, pub, priv, COALESCE(sig, x''), created FROM prekeys
		WHERE kind = 'spk' AND created >= ? ORDER BY id DESC`, ms(since))
	if err != nil {
		return nil, fmt.Errorf("failed to list signed prekeys: %w", err)
	}
	defer rows.Close()
	var out []SPKRecord
	for rows.Next() {
		r, err := s.scanSPK(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// GetSPK returns one signed prekey, or ErrNotFound.
func (s *SQLiteDB) GetSPK(ctx context.Context, id uint32) (*SPKRecord, error) {
	r, err := s.scanSPK(s.db.QueryRowContext(ctx, `SELECT id, pub, priv, COALESCE(sig, x''), created FROM prekeys
		WHERE kind = 'spk' AND id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// DeleteSPKsBefore removes signed prekeys older than t, always keeping the newest.
func (s *SQLiteDB) DeleteSPKsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM prekeys WHERE kind = 'spk' AND created < ?
		AND id <> (SELECT MAX(id) FROM prekeys WHERE kind = 'spk')`, ms(t))
	if err != nil {
		return 0, fmt.Errorf("failed to delete old signed prekeys: %w", err)
	}
	return res.RowsAffected()
}

// CreateOPKs stores one-time prekeys and returns their assigned IDs, in order.
func (s *SQLiteDB) CreateOPKs(ctx context.Context, recs []OPKRecord) ([]uint32, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	ids := make([]uint32, 0, len(recs))
	for _, r := range recs {
		res, err := tx.ExecContext(ctx, `INSERT INTO prekeys (kind, pub, priv, reserved_for, created) VALUES ('opk', ?, ?, ?, ?)`,
			r.Pub, s.sealKey(r.Pub, r.Priv), r.ReservedFor, ms(r.Created))
		if err != nil {
			return nil, fmt.Errorf("failed to save one-time prekey: %w", err)
		}
		rowID, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		id, err := idFromRow(rowID)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, tx.Commit()
}

// UnusedOPKs lists the public halves of the one-time prekeys reserved for a peer.
func (s *SQLiteDB) UnusedOPKs(ctx context.Context, reservedFor string) ([]OPKRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, pub, created FROM prekeys
		WHERE kind = 'opk' AND reserved_for = ? ORDER BY id`, reservedFor)
	if err != nil {
		return nil, fmt.Errorf("failed to list one-time prekeys: %w", err)
	}
	defer rows.Close()
	var out []OPKRecord
	for rows.Next() {
		var r OPKRecord
		var id, created int64
		if err := rows.Scan(&id, &r.Pub, &created); err != nil {
			return nil, err
		}
		if r.ID, err = idFromRow(id); err != nil {
			return nil, err
		}
		r.ReservedFor, r.Created = reservedFor, fromMs(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetOPK returns a one-time prekey (with its private half) if it was reserved
// for reservedFor and has not been used.
func (s *SQLiteDB) GetOPK(ctx context.Context, id uint32, reservedFor string) (*OPKRecord, error) {
	var r OPKRecord
	var rowID, created int64
	var priv string
	err := s.db.QueryRowContext(ctx, `SELECT id, pub, priv, created FROM prekeys
		WHERE kind = 'opk' AND id = ? AND reserved_for = ?`, id, reservedFor).Scan(&rowID, &r.Pub, &priv, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if r.ID, err = idFromRow(rowID); err != nil {
		return nil, err
	}
	if r.Priv, err = s.openKey(r.Pub, priv); err != nil {
		return nil, err
	}
	r.ReservedFor, r.Created = reservedFor, fromMs(created)
	return &r, nil
}

// DeleteOPK destroys a one-time prekey.
func (s *SQLiteDB) DeleteOPK(ctx context.Context, id uint32) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM prekeys WHERE kind = 'opk' AND id = ?`, id)
	return err
}

// DeleteOPKsBefore destroys one-time prekeys older than t.
func (s *SQLiteDB) DeleteOPKsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM prekeys WHERE kind = 'opk' AND created < ?`, ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountOPKs returns how many one-time prekeys exist.
func (s *SQLiteDB) CountOPKs(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prekeys WHERE kind = 'opk'`).Scan(&n)
	return n, err
}

// SaveBundle stores (or replaces) the last bundle seen for a peer.
func (s *SQLiteDB) SaveBundle(ctx context.Context, peerID string, data []byte, updated time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO peer_bundles (peer_id, bundle, updated) VALUES (?, ?, ?)
		ON CONFLICT (peer_id) DO UPDATE SET bundle = excluded.bundle, updated = excluded.updated`,
		peerID, s.seal(aadBundle(peerID), string(data)), ms(updated))
	if err != nil {
		return fmt.Errorf("failed to save bundle: %w", err)
	}
	return nil
}

// GetBundle returns the stored bundle for a peer, or ErrNotFound.
func (s *SQLiteDB) GetBundle(ctx context.Context, peerID string) ([]byte, time.Time, error) {
	var stored string
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT bundle, updated FROM peer_bundles WHERE peer_id = ?`, peerID).Scan(&stored, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	plain, err := s.open(aadBundle(peerID), stored)
	return []byte(plain), fromMs(updated), err
}

// PruneBundles keeps only the max most recently updated bundles.
func (s *SQLiteDB) PruneBundles(ctx context.Context, max int) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM peer_bundles WHERE peer_id NOT IN
		(SELECT peer_id FROM peer_bundles ORDER BY updated DESC LIMIT ?)`, max)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- Relay -------------------------------------------------------------------

// RelayEnvelope is an opaque end-to-end encrypted message we are holding for
// someone else. The relay sees who it is from and for, never what it says.
type RelayEnvelope struct {
	ID, From, To     string
	Blob             []byte
	Created, Expires time.Time
}

// RelayReceipt is a recipient-signed proof of delivery, held until the
// original sender next connects.
type RelayReceipt struct {
	To, MsgID, Signer string
	EdPub, Sig        []byte
	Expires           time.Time
}

// RelayLimits bounds what a relay stores so nobody can fill its disk.
type RelayLimits struct {
	MaxTotalBytes     int64
	MaxPerSender      int
	MaxBytesPerSender int64
	MaxPerRecipient   int
	MaxReceipts       int
}

// QuotaError reports why a relay refused to store something.
type QuotaError struct{ Reason string }

func (e *QuotaError) Error() string { return "relay quota exceeded: " + e.Reason }

// RelayStorage is the relay's database.
type RelayStorage interface {
	PutEnvelope(ctx context.Context, e RelayEnvelope, lim RelayLimits) error
	EnvelopesFor(ctx context.Context, to string, now time.Time, limit int) ([]RelayEnvelope, error)
	// TakeEnvelope removes and returns an envelope, but only for its recipient.
	TakeEnvelope(ctx context.Context, id, to string) (*RelayEnvelope, error)
	PutReceipt(ctx context.Context, r RelayReceipt, lim RelayLimits) error
	ReceiptsFor(ctx context.Context, to string, now time.Time, limit int) ([]RelayReceipt, error)
	DeleteReceipt(ctx context.Context, to, msgID, signer string) error
	PurgeRelay(ctx context.Context, now time.Time) (envelopes, receipts int64, err error)
	RelayUsage(ctx context.Context) (envelopes int, bytes int64, err error)
}

// PutEnvelope stores an envelope if quotas allow. Storing the same ID twice is
// a no-op, so a sender may safely retry.
func (s *SQLiteDB) PutEnvelope(ctx context.Context, e RelayEnvelope, lim RelayLimits) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM relay_envelopes WHERE id = ?`, e.ID).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}

	var total, senderN, senderBytes, recipientN int64
	if err := tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(LENGTH(blob)), 0),
		COALESCE(SUM(from_peer = ?), 0),
		COALESCE(SUM(CASE WHEN from_peer = ? THEN LENGTH(blob) ELSE 0 END), 0),
		COALESCE(SUM(to_peer = ?), 0)
		FROM relay_envelopes`, e.From, e.From, e.To).Scan(&total, &senderN, &senderBytes, &recipientN); err != nil {
		return fmt.Errorf("failed to read relay usage: %w", err)
	}
	size := int64(len(e.Blob))
	switch {
	case lim.MaxTotalBytes > 0 && total+size > lim.MaxTotalBytes:
		return &QuotaError{"relay storage is full"}
	case lim.MaxPerSender > 0 && senderN >= int64(lim.MaxPerSender):
		return &QuotaError{"too many messages queued from you"}
	case lim.MaxBytesPerSender > 0 && senderBytes+size > lim.MaxBytesPerSender:
		return &QuotaError{"too much data queued from you"}
	case lim.MaxPerRecipient > 0 && recipientN >= int64(lim.MaxPerRecipient):
		return &QuotaError{"too many messages queued for that recipient"}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO relay_envelopes (id, from_peer, to_peer, blob, created, expires)
		VALUES (?, ?, ?, ?, ?, ?)`, e.ID, e.From, e.To, e.Blob, ms(e.Created), ms(e.Expires)); err != nil {
		return fmt.Errorf("failed to store envelope: %w", err)
	}
	return tx.Commit()
}

// EnvelopesFor lists unexpired envelopes for a recipient, oldest first.
func (s *SQLiteDB) EnvelopesFor(ctx context.Context, to string, now time.Time, limit int) ([]RelayEnvelope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, from_peer, to_peer, blob, created, expires FROM relay_envelopes
		WHERE to_peer = ? AND expires > ? ORDER BY created, id LIMIT ?`, to, ms(now), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list envelopes: %w", err)
	}
	defer rows.Close()
	var out []RelayEnvelope
	for rows.Next() {
		var e RelayEnvelope
		var created, expires int64
		if err := rows.Scan(&e.ID, &e.From, &e.To, &e.Blob, &created, &expires); err != nil {
			return nil, err
		}
		e.Created, e.Expires = fromMs(created), fromMs(expires)
		out = append(out, e)
	}
	return out, rows.Err()
}

// TakeEnvelope removes an envelope and returns it; only its recipient can.
func (s *SQLiteDB) TakeEnvelope(ctx context.Context, id, to string) (*RelayEnvelope, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var e RelayEnvelope
	var created, expires int64
	err = tx.QueryRowContext(ctx, `SELECT id, from_peer, to_peer, blob, created, expires FROM relay_envelopes
		WHERE id = ? AND to_peer = ?`, id, to).Scan(&e.ID, &e.From, &e.To, &e.Blob, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM relay_envelopes WHERE id = ?`, id); err != nil {
		return nil, err
	}
	e.Created, e.Expires = fromMs(created), fromMs(expires)
	return &e, tx.Commit()
}

// PutReceipt stores a receipt for later delivery to its addressee.
func (s *SQLiteDB) PutReceipt(ctx context.Context, r RelayReceipt, lim RelayLimits) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if lim.MaxReceipts > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM relay_receipts WHERE to_peer = ?`, r.To).Scan(&n); err != nil {
			return err
		}
		if n >= lim.MaxReceipts {
			return &QuotaError{"too many receipts waiting for that sender"}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO relay_receipts (to_peer, msg_id, signer, ed_pub, sig, expires)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, r.To, r.MsgID, r.Signer, r.EdPub, r.Sig, ms(r.Expires)); err != nil {
		return fmt.Errorf("failed to store receipt: %w", err)
	}
	return tx.Commit()
}

// ReceiptsFor lists unexpired receipts addressed to a peer.
func (s *SQLiteDB) ReceiptsFor(ctx context.Context, to string, now time.Time, limit int) ([]RelayReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT to_peer, msg_id, signer, ed_pub, sig, expires FROM relay_receipts
		WHERE to_peer = ? AND expires > ? LIMIT ?`, to, ms(now), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list receipts: %w", err)
	}
	defer rows.Close()
	var out []RelayReceipt
	for rows.Next() {
		var r RelayReceipt
		var expires int64
		if err := rows.Scan(&r.To, &r.MsgID, &r.Signer, &r.EdPub, &r.Sig, &expires); err != nil {
			return nil, err
		}
		r.Expires = fromMs(expires)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteReceipt removes a receipt once it has been handed over.
func (s *SQLiteDB) DeleteReceipt(ctx context.Context, to, msgID, signer string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM relay_receipts WHERE to_peer = ? AND msg_id = ? AND signer = ?`, to, msgID, signer)
	return err
}

// PurgeRelay deletes expired envelopes and receipts.
func (s *SQLiteDB) PurgeRelay(ctx context.Context, now time.Time) (int64, int64, error) {
	e, err := s.db.ExecContext(ctx, `DELETE FROM relay_envelopes WHERE expires <= ?`, ms(now))
	if err != nil {
		return 0, 0, err
	}
	r, err := s.db.ExecContext(ctx, `DELETE FROM relay_receipts WHERE expires <= ?`, ms(now))
	if err != nil {
		return 0, 0, err
	}
	en, _ := e.RowsAffected()
	rn, _ := r.RowsAffected()
	return en, rn, nil
}

// RelayUsage reports how much the relay is holding.
func (s *SQLiteDB) RelayUsage(ctx context.Context) (int, int64, error) {
	var n int
	var b int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(blob)), 0) FROM relay_envelopes`).Scan(&n, &b)
	return n, b, err
}

// ---- Relay flag on our own messages --------------------------------------------

// GetMessage returns one message by sender and ID, or ErrNotFound.
func (s *SQLiteDB) GetMessage(ctx context.Context, from, id string) (*models.ChatMessage, error) {
	msgs, err := s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE from_peer_id = ? AND id = ? AND deleted_at IS NULL`, from, id)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, ErrNotFound
	}
	return msgs[0], nil
}

// MarkMessageRelayed records that an encrypted copy was handed to relays.
func (s *SQLiteDB) MarkMessageRelayed(ctx context.Context, from, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE messages SET relayed_at = ? WHERE from_peer_id = ? AND id = ?`, ms(time.Now()), from, id)
	return err
}

// GetUnrelayedDirect returns our undelivered direct messages to a peer that
// have not yet been handed to any relay, oldest first.
func (s *SQLiteDB) GetUnrelayedDirect(ctx context.Context, from, to string, since time.Time, limit int) ([]*models.ChatMessage, error) {
	p := Page{Limit: limit}.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE message_type = 'direct' AND delivered = 0 AND relayed_at IS NULL AND deleted_at IS NULL
		  AND from_peer_id = ? AND to_peer_id = ? AND created_at >= ?
		ORDER BY seq ASC LIMIT ?`, from, to, ms(since), p.Limit)
}

// PeersWithUnrelayed lists recipients that have undelivered, unrelayed messages.
func (s *SQLiteDB) PeersWithUnrelayed(ctx context.Context, from string, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT to_peer_id FROM messages
		WHERE message_type = 'direct' AND delivered = 0 AND relayed_at IS NULL AND deleted_at IS NULL
		  AND from_peer_id = ? AND created_at >= ?`, from, ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
