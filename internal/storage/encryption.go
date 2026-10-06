package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Errors reported when the database and the configured key disagree.
var (
	ErrEncrypted = errors.New("the database is encrypted, but encryption is switched off; re-enable it (the key file is in the data directory)")
	ErrWrongKey  = errors.New("the database cannot be unlocked with this key (wrong passphrase, or the database belongs to a different key)")
)

const (
	metaEncrypted = "encrypted"
	metaCanary    = "canary"
	canaryText    = "lazy-chat"
	canaryAAD     = "meta.canary"
	encryptBatch  = 500
)

func (s *SQLiteDB) meta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// initEncryption reconciles the vault with what the database already holds:
//
//   - no vault, plaintext database: nothing to do;
//   - no vault, encrypted database: refuse (never present ciphertext as data);
//   - vault, encrypted database: check the key against the stored canary;
//   - vault, plaintext database: encrypt every sensitive field in one
//     transaction, then purge the old pages so no plaintext remains on disk.
func (s *SQLiteDB) initEncryption(ctx context.Context) error {
	enc, err := s.meta(ctx, metaEncrypted)
	if err != nil {
		return fmt.Errorf("failed to read encryption state: %w", err)
	}
	switch {
	case s.vault == nil && enc == "1":
		return ErrEncrypted
	case s.vault == nil:
		return nil
	case enc == "1":
		canary, err := s.meta(ctx, metaCanary)
		if err != nil {
			return err
		}
		if plain, err := s.open(canaryAAD, canary); err != nil || plain != canaryText {
			return ErrWrongKey
		}
		return nil
	default:
		return s.encryptExisting(ctx)
	}
}

type fieldUpdate struct {
	query string
	args  []any
}

// encryptExisting encrypts a database that was created without a vault.
func (s *SQLiteDB) encryptExisting(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin encryption: %w", err)
	}
	defer tx.Rollback()

	apply := func(ups []fieldUpdate) error {
		for _, u := range ups {
			if _, err := tx.ExecContext(ctx, u.query, u.args...); err != nil {
				return err
			}
		}
		return nil
	}

	// Messages, in batches so memory stays flat on large histories. Rows are
	// read completely (and closed) before they are rewritten.
	for last := int64(0); ; {
		rows, err := tx.QueryContext(ctx, `SELECT seq, from_peer_id, id, content FROM messages
			WHERE seq > ? ORDER BY seq LIMIT ?`, last, encryptBatch)
		if err != nil {
			return fmt.Errorf("failed to read messages: %w", err)
		}
		var ups []fieldUpdate
		for rows.Next() {
			var seq int64
			var from, id, content string
			if err := rows.Scan(&seq, &from, &id, &content); err != nil {
				rows.Close()
				return err
			}
			last = seq
			ups = append(ups, fieldUpdate{`UPDATE messages SET content = ? WHERE seq = ?`,
				[]any{s.seal(aadMessage(from, id), content), seq}})
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ups) == 0 {
			break
		}
		if err := apply(ups); err != nil {
			return fmt.Errorf("failed to encrypt messages: %w", err)
		}
	}

	// The remaining tables are small (groups, members, invitations).
	collect := func(query string, scan func(*sql.Rows) (fieldUpdate, error)) error {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		var ups []fieldUpdate
		for rows.Next() {
			u, err := scan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			ups = append(ups, u)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		return apply(ups)
	}

	if err := collect(`SELECT id, name, description FROM groups`, func(r *sql.Rows) (fieldUpdate, error) {
		var id, name, desc string
		err := r.Scan(&id, &name, &desc)
		return fieldUpdate{`UPDATE groups SET name = ?, description = ? WHERE id = ?`,
			[]any{s.seal(aadGroup("name", id), name), s.seal(aadGroup("description", id), desc), id}}, err
	}); err != nil {
		return fmt.Errorf("failed to encrypt groups: %w", err)
	}
	if err := collect(`SELECT group_id, peer_id, username FROM group_members`, func(r *sql.Rows) (fieldUpdate, error) {
		var g, p, name string
		err := r.Scan(&g, &p, &name)
		return fieldUpdate{`UPDATE group_members SET username = ? WHERE group_id = ? AND peer_id = ?`,
			[]any{s.seal(aadMember(g, p), name), g, p}}, err
	}); err != nil {
		return fmt.Errorf("failed to encrypt members: %w", err)
	}
	if err := collect(`SELECT id, group_name, group_description, members FROM group_invites`, func(r *sql.Rows) (fieldUpdate, error) {
		var id, name, desc, members string
		err := r.Scan(&id, &name, &desc, &members)
		return fieldUpdate{`UPDATE group_invites SET group_name = ?, group_description = ?, members = ? WHERE id = ?`,
			[]any{s.seal(aadInvite("group_name", id), name), s.seal(aadInvite("group_description", id), desc),
				s.seal(aadInvite("members", id), members), id}}, err
	}); err != nil {
		return fmt.Errorf("failed to encrypt invitations: %w", err)
	}

	// Old versions' retired tables are plaintext; drop the ones with no data.
	for _, table := range legacyTables {
		name := "legacy_" + table
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil || n == 0 {
			continue
		}
		var rowsInTable int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+name).Scan(&rowsInTable); err == nil && rowsInTable == 0 {
			if _, err := tx.ExecContext(ctx, `DROP TABLE `+name); err != nil {
				return err
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, '1'), (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		metaEncrypted, metaCanary, s.seal(canaryAAD, canaryText)); err != nil {
		return fmt.Errorf("failed to record encryption state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit encryption: %w", err)
	}

	// The plaintext now sits in freed pages and in the write-ahead log.
	// Rewrite the file so none of it survives on disk.
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("failed to checkpoint after encryption: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("failed to purge plaintext after encryption: %w", err)
	}
	_, _ = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return nil
}
