package storage

import (
	"context"
	"fmt"
	"time"
)

// KnownPeer is a peer we have been connected to, and where it was reachable.
type KnownPeer struct {
	ID, Username, Address string
	Port                  int
	LastConnected         time.Time
}

// PeerBook remembers where peers were reachable, so they can be found again
// on networks where discovery does not work.
type PeerBook interface {
	RememberPeer(ctx context.Context, p KnownPeer) error
	// KnownPeers returns peers connected since `since`, most recent first.
	KnownPeers(ctx context.Context, since time.Time, limit int) ([]KnownPeer, error)
	ForgetPeer(ctx context.Context, id string) (bool, error)
	ForgetAllPeers(ctx context.Context) error
}

var _ PeerBook = (*SQLiteDB)(nil)

// RememberPeer records or updates where a peer was reachable.
func (s *SQLiteDB) RememberPeer(ctx context.Context, p KnownPeer) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO known_peers (id, username, address, port, last_connected)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET username = excluded.username, address = excluded.address,
			port = excluded.port, last_connected = excluded.last_connected`,
		p.ID, p.Username, p.Address, p.Port, ms(p.LastConnected))
	if err != nil {
		return fmt.Errorf("failed to remember peer: %w", err)
	}
	return nil
}

// KnownPeers lists remembered peers, most recently connected first.
func (s *SQLiteDB) KnownPeers(ctx context.Context, since time.Time, limit int) ([]KnownPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, address, port, last_connected FROM known_peers
		WHERE last_connected >= ? ORDER BY last_connected DESC LIMIT ?`, ms(since), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list known peers: %w", err)
	}
	defer rows.Close()
	var out []KnownPeer
	for rows.Next() {
		var p KnownPeer
		var last int64
		if err := rows.Scan(&p.ID, &p.Username, &p.Address, &p.Port, &last); err != nil {
			return nil, err
		}
		p.LastConnected = fromMs(last)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ForgetPeer removes a remembered peer and reports whether it was known.
func (s *SQLiteDB) ForgetPeer(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM known_peers WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ForgetAllPeers removes every remembered peer.
func (s *SQLiteDB) ForgetAllPeers(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM known_peers`)
	return err
}
