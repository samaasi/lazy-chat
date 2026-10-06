package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
)

// ---- Retry queue -------------------------------------------------------------

// GetUndeliveredDirect returns direct messages sent by fromPeerID to toPeerID
// that have not been acknowledged, oldest first, no older than since.
func (s *SQLiteDB) GetUndeliveredDirect(ctx context.Context, fromPeerID, toPeerID string, since time.Time, limit int) ([]*models.ChatMessage, error) {
	p := Page{Limit: limit}.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE message_type = 'direct' AND delivered = 0 AND deleted_at IS NULL
		  AND from_peer_id = ? AND to_peer_id = ? AND created_at >= ?
		ORDER BY seq ASC LIMIT ?`, fromPeerID, toPeerID, ms(since), p.Limit)
}

// PeersWithUndelivered lists the peers fromPeerID has unacknowledged direct
// messages for (recent ones only).
func (s *SQLiteDB) PeersWithUndelivered(ctx context.Context, fromPeerID string, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT to_peer_id FROM messages
		WHERE message_type = 'direct' AND delivered = 0 AND deleted_at IS NULL
		  AND from_peer_id = ? AND created_at >= ?`, fromPeerID, ms(since))
	if err != nil {
		return nil, fmt.Errorf("failed to list undelivered recipients: %w", err)
	}
	defer rows.Close()
	var peers []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		peers = append(peers, id)
	}
	return peers, rows.Err()
}

// ---- Verification ------------------------------------------------------------

// SetVerified records (or clears) that the user compared safety numbers with a peer.
func (s *SQLiteDB) SetVerified(ctx context.Context, peerID string, verified bool) error {
	var err error
	if verified {
		_, err = s.db.ExecContext(ctx, `INSERT INTO verified_peers (peer_id, verified_at) VALUES (?, ?)
			ON CONFLICT (peer_id) DO UPDATE SET verified_at = excluded.verified_at`, peerID, ms(time.Now()))
	} else {
		_, err = s.db.ExecContext(ctx, `DELETE FROM verified_peers WHERE peer_id = ?`, peerID)
	}
	if err != nil {
		return fmt.Errorf("failed to update verification: %w", err)
	}
	return nil
}

// IsVerified reports whether a peer has been verified.
func (s *SQLiteDB) IsVerified(ctx context.Context, peerID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM verified_peers WHERE peer_id = ?`, peerID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read verification: %w", err)
	}
	return true, nil
}

// ListVerified returns the verified peer IDs and when each was verified.
func (s *SQLiteDB) ListVerified(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, verified_at FROM verified_peers`)
	if err != nil {
		return nil, fmt.Errorf("failed to list verified peers: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at int64
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = fromMs(at)
	}
	return out, rows.Err()
}
