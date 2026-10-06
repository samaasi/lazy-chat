package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	_ "modernc.org/sqlite" // pure-Go driver: works with CGO_ENABLED=0
)

const (
	defaultPageSize = 50
	maxPageSize     = 500
)

// SQLiteDB implements the Database interface using SQLite.
//
// All timestamps are stored as integer Unix milliseconds. That is compact,
// compares correctly in SQL regardless of time zone, and round-trips without
// any text-format parsing.
type SQLiteDB struct {
	db    *sql.DB
	path  string
	vault Sealer // nil: sensitive fields are stored in the clear
}

// Sealer encrypts sensitive fields at rest (implemented by vault.Vault).
type Sealer interface {
	Seal(plaintext []byte, aad string) string
	Open(sealed, aad string) ([]byte, error)
}

// Option customises a SQLiteDB.
type Option func(*SQLiteDB)

// WithVault turns on encryption at rest: message text, group names and
// descriptions, member names and invitation contents are stored encrypted.
// Identifiers, timestamps and delivery flags stay in the clear so they can be
// indexed and queried.
func WithVault(v Sealer) Option { return func(s *SQLiteDB) { s.vault = v } }

// NewSQLiteDB creates a new SQLite database instance
func NewSQLiteDB(path string, opts ...Option) *SQLiteDB {
	s := &SQLiteDB{path: path}
	for _, o := range opts {
		o(s)
	}
	return s
}

// dsn builds a file: URI that applies the pragmas to every pooled connection
// (a plain `PRAGMA` statement would only affect one of them).
func dsn(path string) string {
	escaped := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(filepath.ToSlash(path))
	return "file:" + escaped +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
}

// Connect opens the database, creating it (0600, in a 0700 directory) if needed.
func (s *SQLiteDB) Connect(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}
	// Create the file ourselves so it is never world-readable; SQLite gives
	// the -wal and -shm files the same permissions as the main file.
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	f.Close()

	db, err := sql.Open("sqlite", dsn(s.path))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	// WAL lets readers run beside the single writer; busy_timeout makes
	// writers queue instead of failing with "database is locked".
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	s.db = db
	return nil
}

// Close closes database connection
func (s *SQLiteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Health checks database health
func (s *SQLiteDB) Health(ctx context.Context) error {
	if s.db == nil {
		return errors.New("database not connected")
	}
	return s.db.PingContext(ctx)
}

// ---- Migrations ------------------------------------------------------------

// migrations is the ordered schema history; PRAGMA user_version records how
// many have been applied. Append new entries, never edit applied ones.
var migrations = [][]string{
	{ // 1: initial schema
		`CREATE TABLE messages (
			seq           INTEGER PRIMARY KEY AUTOINCREMENT,
			id            TEXT NOT NULL,
			from_peer_id  TEXT NOT NULL,
			to_peer_id    TEXT,
			group_id      TEXT,
			content       TEXT NOT NULL,
			message_type  TEXT NOT NULL DEFAULT 'direct',
			created_at    INTEGER NOT NULL,
			delivered     INTEGER NOT NULL DEFAULT 0,
			read_status   INTEGER NOT NULL DEFAULT 0,
			deleted_at    INTEGER,
			UNIQUE (from_peer_id, id),
			CHECK (message_type IN ('direct', 'group', 'system')),
			CHECK ((message_type = 'direct' AND to_peer_id IS NOT NULL AND group_id IS NULL) OR
			       (message_type = 'group'  AND group_id IS NOT NULL AND to_peer_id IS NULL) OR
			       (message_type = 'system'))
		)`,
		`CREATE TABLE groups (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_by  TEXT NOT NULL,
			created_at  INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL,
			is_active   INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE group_members (
			group_id  TEXT NOT NULL,
			peer_id   TEXT NOT NULL,
			username  TEXT NOT NULL,
			joined_at INTEGER NOT NULL,
			role      TEXT NOT NULL DEFAULT 'member',
			is_active INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (group_id, peer_id),
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			CHECK (role IN ('admin', 'member'))
		)`,
		// group_id is deliberately not a foreign key: an invitation to a
		// group we have not joined yet refers to a group we do not have.
		`CREATE TABLE group_invites (
			id                TEXT PRIMARY KEY,
			group_id          TEXT NOT NULL,
			group_name        TEXT NOT NULL,
			group_description TEXT NOT NULL DEFAULT '',
			group_creator     TEXT NOT NULL,
			inviter_id        TEXT NOT NULL,
			invitee_id        TEXT NOT NULL,
			created_at        INTEGER NOT NULL,
			expires_at        INTEGER NOT NULL,
			status            TEXT NOT NULL DEFAULT 'pending',
			members           TEXT NOT NULL DEFAULT '[]',
			CHECK (status IN ('pending', 'accepted', 'declined', 'expired'))
		)`,
		// Indexes match the actual access paths. Low-cardinality columns
		// (read/delivered/type/role/active/status) are intentionally not
		// indexed on their own: they slow every write and rarely help reads.
		`CREATE INDEX idx_msg_direct ON messages (from_peer_id, to_peer_id, seq)`,
		`CREATE INDEX idx_msg_group ON messages (group_id, seq) WHERE group_id IS NOT NULL`,
		`CREATE INDEX idx_msg_created ON messages (created_at)`,
		`CREATE INDEX idx_group_members_peer ON group_members (peer_id, group_id)`,
		`CREATE INDEX idx_group_invites_invitee ON group_invites (invitee_id, status, expires_at)`,
		`CREATE INDEX idx_group_invites_group ON group_invites (group_id)`,
	},
	{ // 2: out-of-band verification, and fast lookup of undelivered messages
		`CREATE TABLE verified_peers (
			peer_id     TEXT PRIMARY KEY,
			verified_at INTEGER NOT NULL
		)`,
		`CREATE INDEX idx_msg_undelivered ON messages (to_peer_id, seq)
			WHERE delivered = 0 AND deleted_at IS NULL AND message_type = 'direct'`,
	},
	{ // 3: small key/value table (records whether the data is encrypted)
		`CREATE TABLE meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	},
	{ // 4: offline delivery - prekeys, cached bundles and the relay's queue
		`ALTER TABLE messages ADD COLUMN relayed_at INTEGER`,
		`CREATE INDEX idx_msg_unrelayed ON messages (to_peer_id, seq)
			WHERE delivered = 0 AND relayed_at IS NULL AND deleted_at IS NULL AND message_type = 'direct'`,
		`CREATE TABLE prekeys (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			kind         TEXT NOT NULL CHECK (kind IN ('spk', 'opk')),
			pub          BLOB NOT NULL,
			priv         TEXT NOT NULL,
			sig          BLOB,
			reserved_for TEXT,
			created      INTEGER NOT NULL
		)`,
		`CREATE INDEX idx_prekeys_reserved ON prekeys (kind, reserved_for)`,
		`CREATE TABLE peer_bundles (
			peer_id TEXT PRIMARY KEY,
			bundle  TEXT NOT NULL,
			updated INTEGER NOT NULL
		)`,
		`CREATE TABLE relay_envelopes (
			id        TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL,
			to_peer   TEXT NOT NULL,
			blob      BLOB NOT NULL,
			created   INTEGER NOT NULL,
			expires   INTEGER NOT NULL
		)`,
		`CREATE INDEX idx_relay_to ON relay_envelopes (to_peer, created)`,
		`CREATE INDEX idx_relay_from ON relay_envelopes (from_peer)`,
		`CREATE INDEX idx_relay_expires ON relay_envelopes (expires)`,
		`CREATE TABLE relay_receipts (
			to_peer TEXT NOT NULL,
			msg_id  TEXT NOT NULL,
			signer  TEXT NOT NULL,
			ed_pub  BLOB NOT NULL,
			sig     BLOB NOT NULL,
			expires INTEGER NOT NULL,
			PRIMARY KEY (to_peer, msg_id, signer)
		)`,
		`CREATE INDEX idx_receipts_expires ON relay_receipts (expires)`,
	},
	{ // 5: sealed sender - the relay no longer knows who sent anything
		// An envelope records who handed it over (the sender, or the forwarder
		// that carried it for her), which a relay cannot tell apart.
		`ALTER TABLE relay_envelopes RENAME COLUMN from_peer TO submitter`,
		// Receipts used to be addressed to the sender's ID; they are now
		// addressed to a random mailbox tag that only the sender and the
		// recipient know. (Held receipts are transient, so none are kept.)
		`DROP TABLE relay_receipts`,
		`CREATE TABLE relay_receipts (
			tag     TEXT NOT NULL,
			msg_id  TEXT NOT NULL,
			signer  TEXT NOT NULL,
			ed_pub  BLOB NOT NULL,
			sig     BLOB NOT NULL,
			expires INTEGER NOT NULL,
			PRIMARY KEY (tag, msg_id, signer)
		)`,
		`CREATE INDEX idx_receipts_signer ON relay_receipts (signer)`,
		`CREATE INDEX idx_receipts_expires ON relay_receipts (expires)`,
		// What we have queued with which relay, so we know whom to ask for receipts.
		`CREATE TABLE relay_outbox (
			msg_id   TEXT NOT NULL,
			relay_id TEXT NOT NULL,
			to_peer  TEXT NOT NULL,
			tag      TEXT NOT NULL,
			created  INTEGER NOT NULL,
			PRIMARY KEY (msg_id, relay_id, to_peer)
		)`,
		`CREATE INDEX idx_outbox_created ON relay_outbox (created)`,
	},
}

// legacyTables are the tables of the two incompatible schemas older versions
// could create. They never held usable data (inserts failed against the
// mismatched columns), but are renamed rather than dropped just in case.
var legacyTables = []string{"messages", "groups", "group_members", "group_invites"}

// Migrate brings the schema up to date.
func (s *SQLiteDB) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this program supports (%d)", version, len(migrations))
	}

	if version == 0 {
		if err := retireLegacySchema(ctx, tx); err != nil {
			return err
		}
	}

	for i := version; i < len(migrations); i++ {
		for _, stmt := range migrations[i] {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration %d failed: %w", i+1, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return fmt.Errorf("failed to record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.initEncryption(ctx)
}

// retireLegacySchema renames tables from pre-versioning databases out of the
// way. A database created by this program's earlier versions has a `messages`
// table without the `seq` column.
func retireLegacySchema(ctx context.Context, tx *sql.Tx) error {
	var exists, hasSeq int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'messages'`).Scan(&exists); err != nil {
		return fmt.Errorf("failed to inspect schema: %w", err)
	}
	if exists == 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'seq'`).Scan(&hasSeq); err != nil {
		return fmt.Errorf("failed to inspect schema: %w", err)
	}
	if hasSeq > 0 {
		return nil
	}

	// Old index names would otherwise shadow the new ones.
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL
		AND tbl_name IN ('messages', 'groups', 'group_members', 'group_invites')`)
	if err != nil {
		return fmt.Errorf("failed to list legacy indexes: %w", err)
	}
	var indexes []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		indexes = append(indexes, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range indexes {
		if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS "`+name+`"`); err != nil {
			return fmt.Errorf("failed to drop legacy index %s: %w", name, err)
		}
	}
	for _, table := range legacyTables {
		stmt := fmt.Sprintf(`ALTER TABLE %s RENAME TO legacy_%s`, table, table)
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			// Not every legacy table necessarily exists.
			if strings.Contains(err.Error(), "no such table") {
				continue
			}
			return fmt.Errorf("failed to retire legacy table %s: %w", table, err)
		}
	}
	return nil
}

// ---- Helpers ---------------------------------------------------------------

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v) }
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (p Page) normalized() Page {
	if p.Limit <= 0 {
		p.Limit = defaultPageSize
	}
	if p.Limit > maxPageSize {
		p.Limit = maxPageSize
	}
	if p.Before < 0 {
		p.Before = 0
	}
	return p
}

// ---- Encryption helpers ------------------------------------------------------

// seal encrypts a sensitive value (a no-op without a vault). aad ties the
// ciphertext to its row and column.
func (s *SQLiteDB) seal(aad, value string) string {
	if s.vault == nil {
		return value
	}
	return s.vault.Seal([]byte(value), aad)
}

// open reverses seal.
func (s *SQLiteDB) open(aad, stored string) (string, error) {
	if s.vault == nil {
		return stored, nil
	}
	plain, err := s.vault.Open(stored, aad)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt stored data: %w", err)
	}
	return string(plain), nil
}

func aadMessage(from, id string) string   { return "messages.content|" + from + "|" + id }
func aadGroup(field, id string) string    { return "groups." + field + "|" + id }
func aadMember(group, peer string) string { return "group_members.username|" + group + "|" + peer }
func aadInvite(field, id string) string   { return "group_invites." + field + "|" + id }

// rowsAffectedOrNotFound maps "0 rows changed" to ErrNotFound.
func rowsAffectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Messages --------------------------------------------------------------

const messageColumns = `seq, id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''),
	content, message_type, created_at, delivered, read_status`

// userCanSeeGroupMessage is the shared "is a member of the message's group" predicate.
const userIsGroupMember = `group_id IN (SELECT group_id FROM group_members WHERE peer_id = ? AND is_active = 1)`

// SaveMessage stores a message in the database
func (s *SQLiteDB) SaveMessage(ctx context.Context, msg *models.ChatMessage) (bool, error) {
	// ON CONFLICT ... DO NOTHING only swallows the (sender, id) duplicate;
	// unlike INSERT OR IGNORE it still reports CHECK/NOT NULL violations.
	res, err := s.db.ExecContext(ctx, `INSERT INTO messages
		(id, from_peer_id, to_peer_id, group_id, content, message_type, created_at, delivered, read_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (from_peer_id, id) DO NOTHING`,
		msg.ID, msg.From, nullString(msg.To), nullString(msg.GroupID),
		s.seal(aadMessage(msg.From, msg.ID), msg.Message), string(msg.Type), ms(msg.Timestamp), boolInt(msg.Delivered), boolInt(msg.Read))
	if err != nil {
		return false, fmt.Errorf("failed to save message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to save message: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if seq, err := res.LastInsertId(); err == nil {
		msg.Seq = seq
	}
	return true, nil
}

// GetMessages retrieves messages, newest first
func (s *SQLiteDB) GetMessages(ctx context.Context, p Page) ([]*models.ChatMessage, error) {
	p = p.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE deleted_at IS NULL AND (? = 0 OR seq < ?)
		ORDER BY seq DESC LIMIT ?`, p.Before, p.Before, p.Limit)
}

// GetDirectMessages retrieves direct messages between two peers
func (s *SQLiteDB) GetDirectMessages(ctx context.Context, peerID1, peerID2 string, p Page) ([]*models.ChatMessage, error) {
	p = p.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE deleted_at IS NULL AND message_type = 'direct' AND (? = 0 OR seq < ?)
		  AND ((from_peer_id = ? AND to_peer_id = ?) OR (from_peer_id = ? AND to_peer_id = ?))
		ORDER BY seq DESC LIMIT ?`,
		p.Before, p.Before, peerID1, peerID2, peerID2, peerID1, p.Limit)
}

// GetGroupMessages retrieves messages from a specific group
func (s *SQLiteDB) GetGroupMessages(ctx context.Context, groupID string, p Page) ([]*models.ChatMessage, error) {
	p = p.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE deleted_at IS NULL AND group_id = ? AND (? = 0 OR seq < ?)
		ORDER BY seq DESC LIMIT ?`, groupID, p.Before, p.Before, p.Limit)
}

// GetMessagesByTimeRange retrieves messages within a time range
func (s *SQLiteDB) GetMessagesByTimeRange(ctx context.Context, start, end time.Time, p Page) ([]*models.ChatMessage, error) {
	p = p.normalized()
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE deleted_at IS NULL AND created_at BETWEEN ? AND ? AND (? = 0 OR seq < ?)
		ORDER BY seq DESC LIMIT ?`, ms(start), ms(end), p.Before, p.Before, p.Limit)
}

// likeEscaper neutralises LIKE wildcards in user input.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// SearchMessages searches for messages containing specific text
func (s *SQLiteDB) SearchMessages(ctx context.Context, query string, p Page) ([]*models.ChatMessage, error) {
	p = p.normalized()
	if s.vault != nil {
		return s.searchEncrypted(ctx, query, p)
	}
	return s.queryMessages(ctx, `SELECT `+messageColumns+` FROM messages
		WHERE deleted_at IS NULL AND content LIKE ? ESCAPE '\' AND (? = 0 OR seq < ?)
		ORDER BY seq DESC LIMIT ?`, "%"+likeEscaper.Replace(query)+"%", p.Before, p.Before, p.Limit)
}

// maxSearchScan bounds how many messages an encrypted search will decrypt.
const maxSearchScan = 100_000

// searchEncrypted searches by decrypting newest-first in batches: the database
// cannot match text it cannot read. Results are the same as the LIKE search.
func (s *SQLiteDB) searchEncrypted(ctx context.Context, query string, p Page) ([]*models.ChatMessage, error) {
	needle := strings.ToLower(query)
	var out []*models.ChatMessage
	before, scanned := p.Before, 0
	for scanned < maxSearchScan {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		batch, err := s.GetMessages(ctx, Page{Limit: maxPageSize, Before: before})
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, m := range batch {
			scanned++
			if strings.Contains(strings.ToLower(m.Message), needle) {
				if out = append(out, m); len(out) == p.Limit {
					return out, nil
				}
			}
		}
		before = batch[len(batch)-1].Seq
	}
	return out, nil
}

func (s *SQLiteDB) queryMessages(ctx context.Context, query string, args ...any) ([]*models.ChatMessage, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	var messages []*models.ChatMessage
	for rows.Next() {
		msg := &models.ChatMessage{}
		var msgType string
		var createdAt int64
		var delivered, read int
		if err := rows.Scan(&msg.Seq, &msg.ID, &msg.From, &msg.To, &msg.GroupID, &msg.Message,
			&msgType, &createdAt, &delivered, &read); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		var err error
		if msg.Message, err = s.open(aadMessage(msg.From, msg.ID), msg.Message); err != nil {
			return nil, err
		}
		msg.Type = models.MessageType(msgType)
		msg.Timestamp = fromMs(createdAt)
		msg.Delivered, msg.Read = delivered != 0, read != 0
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating messages: %w", err)
	}
	return messages, nil
}

// MarkMessageAsDelivered marks a message we sent as delivered
func (s *SQLiteDB) MarkMessageAsDelivered(ctx context.Context, fromPeerID, messageID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE messages SET delivered = 1 WHERE from_peer_id = ? AND id = ?`, fromPeerID, messageID)
	if err != nil {
		return fmt.Errorf("failed to mark message as delivered: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// MarkMessageAsRead marks a message as read by its recipient
func (s *SQLiteDB) MarkMessageAsRead(ctx context.Context, userID, messageID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE messages SET read_status = 1
		WHERE id = ? AND deleted_at IS NULL AND from_peer_id <> ?
		  AND (to_peer_id = ? OR `+userIsGroupMember+`)`,
		messageID, userID, userID, userID)
	if err != nil {
		return fmt.Errorf("failed to mark message as read: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// DeleteMessage soft-deletes a message the user sent or may read
func (s *SQLiteDB) DeleteMessage(ctx context.Context, userID, messageID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE messages SET deleted_at = ?
		WHERE id = ? AND deleted_at IS NULL
		  AND (from_peer_id = ? OR to_peer_id = ? OR `+userIsGroupMember+`)`,
		ms(time.Now()), messageID, userID, userID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// ---- Groups ----------------------------------------------------------------

// querier is satisfied by *sql.DB and *sql.Tx so helpers work in both.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const upsertMemberSQL = `INSERT INTO group_members (group_id, peer_id, username, joined_at, role, is_active)
	VALUES (?, ?, ?, ?, ?, 1)
	ON CONFLICT (group_id, peer_id) DO UPDATE SET
		username = excluded.username, joined_at = excluded.joined_at,
		role = excluded.role, is_active = 1`

// upsertMember adds or re-activates a member, sealing the display name.
func (s *SQLiteDB) upsertMember(ctx context.Context, q querier, groupID, peerID, username string, joinedAt int64, role string) error {
	_, err := q.ExecContext(ctx, upsertMemberSQL, groupID, peerID, s.seal(aadMember(groupID, peerID), username), joinedAt, role)
	return err
}

// CreateGroup atomically creates a group with its initial members
func (s *SQLiteDB) CreateGroup(ctx context.Context, group *models.Group) error {
	if !group.HasMember(group.CreatedBy) {
		return errors.New("group creator must be a member")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `INSERT INTO groups (id, name, description, created_by, created_at, updated_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		group.ID, s.seal(aadGroup("name", group.ID), group.Name), s.seal(aadGroup("description", group.ID), group.Description), group.CreatedBy,
		ms(group.CreatedAt), ms(group.UpdatedAt), boolInt(group.IsActive)); err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	for peerID, username := range group.Members {
		role := models.RoleMember
		if peerID == group.CreatedBy {
			role = models.RoleAdmin
		}
		if err := s.upsertMember(ctx, tx, group.ID, peerID, username, ms(group.CreatedAt), role); err != nil {
			return fmt.Errorf("failed to add group member: %w", err)
		}
	}
	return tx.Commit()
}

func (s *SQLiteDB) scanGroup(sc interface{ Scan(...any) error }) (*models.Group, error) {
	g := &models.Group{Members: make(map[string]string)}
	var created, updated int64
	var active int
	if err := sc.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedBy, &created, &updated, &active); err != nil {
		return nil, err
	}
	var err error
	if g.Name, err = s.open(aadGroup("name", g.ID), g.Name); err != nil {
		return nil, err
	}
	if g.Description, err = s.open(aadGroup("description", g.ID), g.Description); err != nil {
		return nil, err
	}
	g.CreatedAt, g.UpdatedAt, g.IsActive = fromMs(created), fromMs(updated), active != 0
	return g, nil
}

const groupColumns = `g.id, g.name, g.description, g.created_by, g.created_at, g.updated_at, g.is_active`

// GetGroup retrieves an active group and its active members
func (s *SQLiteDB) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	return s.getGroup(ctx, s.db, groupID)
}

func (s *SQLiteDB) getGroup(ctx context.Context, q querier, groupID string) (*models.Group, error) {
	g, err := s.scanGroup(q.QueryRowContext(ctx,
		`SELECT `+groupColumns+` FROM groups g WHERE g.id = ? AND g.is_active = 1`, groupID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	members, err := s.getGroupMembers(ctx, q, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to load group members: %w", err)
	}
	for _, m := range members {
		g.Members[m.PeerID] = m.Username
	}
	return g, nil
}

// GetGroupsByMember retrieves all active groups a peer is an active member of.
// The returned groups do not have Members populated; use GetGroup for that.
func (s *SQLiteDB) GetGroupsByMember(ctx context.Context, peerID string) ([]*models.Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupColumns+` FROM groups g
		JOIN group_members gm ON gm.group_id = g.id
		WHERE gm.peer_id = ? AND gm.is_active = 1 AND g.is_active = 1
		ORDER BY g.created_at`, peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query groups by member: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		g, err := s.scanGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}
	return groups, nil
}

// UpdateGroup updates group name and description
func (s *SQLiteDB) UpdateGroup(ctx context.Context, group *models.Group) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ? AND is_active = 1`,
		s.seal(aadGroup("name", group.ID), group.Name), s.seal(aadGroup("description", group.ID), group.Description), ms(time.Now()), group.ID)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// DeleteGroup deletes a group (soft delete)
func (s *SQLiteDB) DeleteGroup(ctx context.Context, groupID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE groups SET is_active = 0, updated_at = ? WHERE id = ?`, ms(time.Now()), groupID)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// AddGroupMember adds (or re-activates) a member
func (s *SQLiteDB) AddGroupMember(ctx context.Context, m *models.GroupMember) error {
	if err := s.upsertMember(ctx, s.db, m.GroupID, m.PeerID, m.Username, ms(m.JoinedAt), m.Role); err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}
	return nil
}

// RemoveGroupMember deactivates a member
func (s *SQLiteDB) RemoveGroupMember(ctx context.Context, groupID, peerID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE group_members SET is_active = 0 WHERE group_id = ? AND peer_id = ? AND is_active = 1`, groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// GetGroupMembers retrieves the active members of a group
func (s *SQLiteDB) GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMember, error) {
	return s.getGroupMembers(ctx, s.db, groupID)
}

func (s *SQLiteDB) getGroupMembers(ctx context.Context, q querier, groupID string) ([]*models.GroupMember, error) {
	rows, err := q.QueryContext(ctx, `SELECT group_id, peer_id, username, joined_at, role, is_active
		FROM group_members WHERE group_id = ? AND is_active = 1 ORDER BY joined_at, peer_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	var members []*models.GroupMember
	for rows.Next() {
		m := &models.GroupMember{}
		var joined int64
		var active int
		if err := rows.Scan(&m.GroupID, &m.PeerID, &m.Username, &joined, &m.Role, &active); err != nil {
			return nil, fmt.Errorf("failed to scan group member: %w", err)
		}
		var err error
		if m.Username, err = s.open(aadMember(m.GroupID, m.PeerID), m.Username); err != nil {
			return nil, err
		}
		m.JoinedAt, m.IsActive = fromMs(joined), active != 0
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group members: %w", err)
	}
	return members, nil
}

// IsGroupMember checks if a peer is an active member of an active group
func (s *SQLiteDB) IsGroupMember(ctx context.Context, groupID, peerID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id
		WHERE gm.group_id = ? AND gm.peer_id = ? AND gm.is_active = 1 AND g.is_active = 1`, groupID, peerID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check group membership: %w", err)
	}
	return true, nil
}

// ---- Invites ---------------------------------------------------------------

const inviteColumns = `id, group_id, group_name, group_description, group_creator, inviter_id, invitee_id,
	created_at, expires_at, status, members`

// CreateInvite creates a new group invitation
func (s *SQLiteDB) CreateInvite(ctx context.Context, inv *models.GroupInvite) error {
	members, err := json.Marshal(inv.Members)
	if err != nil {
		return fmt.Errorf("failed to encode invite members: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO group_invites (`+inviteColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.ID, inv.GroupID, s.seal(aadInvite("group_name", inv.ID), inv.GroupName),
		s.seal(aadInvite("group_description", inv.ID), inv.GroupDescription), inv.GroupCreator, inv.InviterID, inv.InviteeID,
		ms(inv.CreatedAt), ms(inv.ExpiresAt), inv.Status, s.seal(aadInvite("members", inv.ID), string(members)))
	if err != nil {
		return fmt.Errorf("failed to create invite: %w", err)
	}
	return nil
}

func (s *SQLiteDB) scanInvite(sc interface{ Scan(...any) error }) (*models.GroupInvite, error) {
	inv := &models.GroupInvite{}
	var created, expires int64
	var members string
	if err := sc.Scan(&inv.ID, &inv.GroupID, &inv.GroupName, &inv.GroupDescription, &inv.GroupCreator,
		&inv.InviterID, &inv.InviteeID, &created, &expires, &inv.Status, &members); err != nil {
		return nil, err
	}
	var err error
	if inv.GroupName, err = s.open(aadInvite("group_name", inv.ID), inv.GroupName); err != nil {
		return nil, err
	}
	if inv.GroupDescription, err = s.open(aadInvite("group_description", inv.ID), inv.GroupDescription); err != nil {
		return nil, err
	}
	if members, err = s.open(aadInvite("members", inv.ID), members); err != nil {
		return nil, err
	}
	inv.CreatedAt, inv.ExpiresAt = fromMs(created), fromMs(expires)
	if err := json.Unmarshal([]byte(members), &inv.Members); err != nil {
		return nil, fmt.Errorf("corrupt invite members: %w", err)
	}
	return inv, nil
}

// GetInvite retrieves an invitation by ID
func (s *SQLiteDB) GetInvite(ctx context.Context, inviteID string) (*models.GroupInvite, error) {
	inv, err := s.scanInvite(s.db.QueryRowContext(ctx,
		`SELECT `+inviteColumns+` FROM group_invites WHERE id = ?`, inviteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}
	return inv, nil
}

// GetInvitesByInvitee retrieves all invitations for a specific invitee
func (s *SQLiteDB) GetInvitesByInvitee(ctx context.Context, inviteeID string) ([]*models.GroupInvite, error) {
	return s.queryInvites(ctx, `SELECT `+inviteColumns+` FROM group_invites
		WHERE invitee_id = ? ORDER BY created_at DESC`, inviteeID)
}

// GetInvitesByGroup retrieves all invitations for a specific group
func (s *SQLiteDB) GetInvitesByGroup(ctx context.Context, groupID string) ([]*models.GroupInvite, error) {
	return s.queryInvites(ctx, `SELECT `+inviteColumns+` FROM group_invites
		WHERE group_id = ? ORDER BY created_at DESC`, groupID)
}

func (s *SQLiteDB) queryInvites(ctx context.Context, query string, args ...any) ([]*models.GroupInvite, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query invites: %w", err)
	}
	defer rows.Close()

	var invites []*models.GroupInvite
	for rows.Next() {
		inv, err := s.scanInvite(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan invite: %w", err)
		}
		invites = append(invites, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating invites: %w", err)
	}
	return invites, nil
}

// CountPendingInvitesFrom counts unexpired pending invites from inviterID to inviteeID
func (s *SQLiteDB) CountPendingInvitesFrom(ctx context.Context, inviterID, inviteeID string, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_invites
		WHERE inviter_id = ? AND invitee_id = ? AND status = 'pending' AND expires_at > ?`,
		inviterID, inviteeID, ms(now)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count invites: %w", err)
	}
	return n, nil
}

// UpdateInviteStatus updates the status of an invitation
func (s *SQLiteDB) UpdateInviteStatus(ctx context.Context, inviteID, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE group_invites SET status = ? WHERE id = ?`, status, inviteID)
	if err != nil {
		return fmt.Errorf("failed to update invite status: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// DeleteInvite deletes an invitation
func (s *SQLiteDB) DeleteInvite(ctx context.Context, inviteID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM group_invites WHERE id = ?`, inviteID)
	if err != nil {
		return fmt.Errorf("failed to delete invite: %w", err)
	}
	return rowsAffectedOrNotFound(res)
}

// CleanupExpiredInvites marks pending invitations past their expiry as expired
func (s *SQLiteDB) CleanupExpiredInvites(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE group_invites SET status = 'expired' WHERE status = 'pending' AND expires_at < ?`, ms(now))
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired invites: %w", err)
	}
	return res.RowsAffected()
}

// AcceptInvite atomically turns a pending invitation into group membership.
func (s *SQLiteDB) AcceptInvite(ctx context.Context, inviteID, inviteeID, inviteeName string, now time.Time) (*models.Group, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to accept invite: %w", err)
	}
	defer tx.Rollback()

	inv, err := s.scanInvite(tx.QueryRowContext(ctx, `SELECT `+inviteColumns+` FROM group_invites WHERE id = ?`, inviteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load invite: %w", err)
	}
	if inv.InviteeID != inviteeID || inv.Status != models.InviteStatusPending || inv.IsExpired(now) {
		return nil, ErrInviteUnusable
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO groups (id, name, description, created_by, created_at, updated_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, description = excluded.description,
			updated_at = excluded.updated_at, is_active = 1`,
		inv.GroupID, s.seal(aadGroup("name", inv.GroupID), inv.GroupName), s.seal(aadGroup("description", inv.GroupID), inv.GroupDescription),
		inv.GroupCreator, ms(now), ms(now)); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	// Start from a clean slate so members that left while we were away do
	// not linger from a previous membership.
	if _, err := tx.ExecContext(ctx, `UPDATE group_members SET is_active = 0 WHERE group_id = ?`, inv.GroupID); err != nil {
		return nil, fmt.Errorf("failed to reset members: %w", err)
	}
	for _, m := range inv.Members {
		role := models.RoleMember
		if m.PeerID == inv.GroupCreator {
			role = models.RoleAdmin
		}
		if err := s.upsertMember(ctx, tx, inv.GroupID, m.PeerID, m.Username, ms(now), role); err != nil {
			return nil, fmt.Errorf("failed to add member: %w", err)
		}
	}
	// The invitee's own display name is not in the inviter's snapshot.
	if err := s.upsertMember(ctx, tx, inv.GroupID, inviteeID, inviteeName, ms(now), models.RoleMember); err != nil {
		return nil, fmt.Errorf("failed to add invitee: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE group_invites SET status = 'accepted' WHERE id = ?`, inv.ID); err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
	}
	g, err := s.getGroup(ctx, tx, inv.GroupID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to accept invite: %w", err)
	}
	return g, nil
}
