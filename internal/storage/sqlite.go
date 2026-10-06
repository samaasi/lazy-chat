package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"github.com/samaasi/lazy-chat/internal/models"
)

// SQLiteDB implements the Database interface using SQLite
type SQLiteDB struct {
	db   *sql.DB
	path string
}

// NewSQLiteDB creates a new SQLite database instance
func NewSQLiteDB(path string) *SQLiteDB {
	return &SQLiteDB{
		path: path,
	}
}

// Connect establishes database connection
func (s *SQLiteDB) Connect(ctx context.Context) error {
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

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

// Migrate runs database migrations
func (s *SQLiteDB) Migrate(ctx context.Context) error {
	migrations := []string{
		// Messages table
		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			from_peer_id TEXT NOT NULL,
			to_peer_id TEXT,
			group_id TEXT,
			content TEXT NOT NULL,
			message_type TEXT NOT NULL DEFAULT 'direct',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			delivered BOOLEAN NOT NULL DEFAULT FALSE,
			read_status BOOLEAN NOT NULL DEFAULT FALSE,
			deleted_at DATETIME,
			CHECK (message_type IN ('direct', 'group', 'system')),
			CHECK ((message_type = 'direct' AND to_peer_id IS NOT NULL AND group_id IS NULL) OR
			       (message_type = 'group' AND group_id IS NOT NULL AND to_peer_id IS NULL) OR
			       (message_type = 'system'))
		)`,

		// Groups table
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			created_by TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN NOT NULL DEFAULT TRUE
		)`,

		// Group members table
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL,
			peer_id TEXT NOT NULL,
			username TEXT NOT NULL,
			joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			role TEXT NOT NULL DEFAULT 'member',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (group_id, peer_id),
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			CHECK (role IN ('admin', 'member'))
		)`,

		// Group invites table
		`CREATE TABLE IF NOT EXISTS group_invites (
			id TEXT PRIMARY KEY,
			group_id TEXT NOT NULL,
			inviter_id TEXT NOT NULL,
			invitee_id TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			CHECK (status IN ('pending', 'accepted', 'declined', 'expired'))
		)`,
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_messages_from_peer ON messages(from_peer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_to_peer ON messages(to_peer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)`,
		`CREATE INDEX IF NOT EXISTS idx_group_members_peer ON group_members(peer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_invites_invitee ON group_invites(invitee_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_invites_status ON group_invites(status)`,
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Run migrations
	for _, migration := range migrations {
		if _, err := tx.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("failed to run migration: %w", err)
		}
	}

	// Create indexes
	for _, index := range indexes {
		if _, err := tx.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return tx.Commit()
}

// Health checks database health
func (s *SQLiteDB) Health(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}
	return s.db.PingContext(ctx)
}

// SaveMessage stores a message in the database
func (s *SQLiteDB) SaveMessage(ctx context.Context, msg *models.ChatMessage) error {
	query := `INSERT INTO messages (id, from_peer_id, to_peer_id, group_id, content, message_type, created_at, delivered, read_status)
			   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		msg.ID, msg.From, nullString(msg.To), nullString(msg.GroupID),
		msg.Message, string(msg.Type), msg.Timestamp, msg.Delivered, msg.Read)

	if err != nil {
		return fmt.Errorf("failed to save message: %w", err)
	}
	return nil
}

// GetMessages retrieves messages with pagination
func (s *SQLiteDB) GetMessages(ctx context.Context, limit, offset int) ([]*models.ChatMessage, error) {
	query := `SELECT id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''), content, message_type, created_at, delivered, read_status
			   FROM messages WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?`

	return s.queryMessages(ctx, query, limit, offset)
}

// GetDirectMessages retrieves direct messages between two peers
func (s *SQLiteDB) GetDirectMessages(ctx context.Context, peerID1, peerID2 string, limit, offset int) ([]*models.ChatMessage, error) {
	query := `SELECT id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''), content, message_type, created_at, delivered, read_status
			   FROM messages 
			   WHERE deleted_at IS NULL AND message_type = 'direct' AND 
			         ((from_peer_id = ? AND to_peer_id = ?) OR (from_peer_id = ? AND to_peer_id = ?))
			   ORDER BY created_at DESC LIMIT ? OFFSET ?`

	return s.queryMessages(ctx, query, peerID1, peerID2, peerID2, peerID1, limit, offset)
}

// GetGroupMessages retrieves messages from a specific group
func (s *SQLiteDB) GetGroupMessages(ctx context.Context, groupID string, limit, offset int) ([]*models.ChatMessage, error) {
	query := `SELECT id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''), content, message_type, created_at, delivered, read_status
			   FROM messages 
			   WHERE deleted_at IS NULL AND message_type = 'group' AND group_id = ?
			   ORDER BY created_at DESC LIMIT ? OFFSET ?`

	return s.queryMessages(ctx, query, groupID, limit, offset)
}

// GetMessagesByTimeRange retrieves messages within a time range
func (s *SQLiteDB) GetMessagesByTimeRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*models.ChatMessage, error) {
	query := `SELECT id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''), content, message_type, created_at, delivered, read_status
			   FROM messages 
			   WHERE deleted_at IS NULL AND created_at BETWEEN ? AND ?
			   ORDER BY created_at DESC LIMIT ? OFFSET ?`

	return s.queryMessages(ctx, query, start, end, limit, offset)
}

// queryMessages is a helper function to execute message queries
func (s *SQLiteDB) queryMessages(ctx context.Context, query string, args ...interface{}) ([]*models.ChatMessage, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	var messages []*models.ChatMessage
	for rows.Next() {
		msg := &models.ChatMessage{}
		var msgType string
		var timestamp string

		err := rows.Scan(&msg.ID, &msg.From, &msg.To, &msg.GroupID, &msg.Message, &msgType, &timestamp, &msg.Delivered, &msg.Read)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}

		msg.Type = models.MessageType(msgType)
		msg.Timestamp, err = time.Parse("2006-01-02 15:04:05", timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %w", err)
		}

		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating messages: %w", err)
	}

	return messages, nil
}

// MarkMessageAsDelivered marks a message as delivered
func (s *SQLiteDB) MarkMessageAsDelivered(ctx context.Context, messageID string) error {
	query := `UPDATE messages SET delivered = TRUE WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, messageID)
	if err != nil {
		return fmt.Errorf("failed to mark message as delivered: %w", err)
	}
	return nil
}

// MarkMessageAsRead marks a message as read
func (s *SQLiteDB) MarkMessageAsRead(ctx context.Context, messageID string) error {
	query := `UPDATE messages SET read_status = TRUE WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, messageID)
	if err != nil {
		return fmt.Errorf("failed to mark message as read: %w", err)
	}
	return nil
}

// DeleteMessage deletes a message (soft delete)
func (s *SQLiteDB) DeleteMessage(ctx context.Context, messageID string) error {
	query := `UPDATE messages SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, messageID)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}
	return nil
}

// SearchMessages searches for messages containing specific text
func (s *SQLiteDB) SearchMessages(ctx context.Context, query string, limit, offset int) ([]*models.ChatMessage, error) {
	sqlQuery := `SELECT id, from_peer_id, COALESCE(to_peer_id, ''), COALESCE(group_id, ''), content, message_type, created_at, delivered, read_status
				 FROM messages 
				 WHERE deleted_at IS NULL AND content LIKE ?
				 ORDER BY created_at DESC LIMIT ? OFFSET ?`

	searchTerm := "%" + strings.ToLower(query) + "%"
	return s.queryMessages(ctx, sqlQuery, searchTerm, limit, offset)
}

// CreateGroup creates a new group
func (s *SQLiteDB) CreateGroup(ctx context.Context, group *models.Group) error {
	query := `INSERT INTO groups (id, name, description, created_by, created_at, updated_at, is_active)
			   VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		group.ID, group.Name, group.Description, group.CreatedBy,
		group.CreatedAt, group.UpdatedAt, group.IsActive)

	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	return nil
}

// GetGroup retrieves a group by ID
func (s *SQLiteDB) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	query := `SELECT id, name, description, created_by, created_at, updated_at, is_active
			   FROM groups WHERE id = ? AND is_active = TRUE`

	group := &models.Group{}
	var createdAt, updatedAt string

	err := s.db.QueryRowContext(ctx, query, groupID).Scan(
		&group.ID, &group.Name, &group.Description, &group.CreatedBy,
		&createdAt, &updatedAt, &group.IsActive)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("group not found")
		}
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	group.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	group.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	group.Members = make(map[string]string)

	// Load group members
	members, err := s.GetGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to load group members: %w", err)
	}

	for _, member := range members {
		if member.IsActive {
			group.Members[member.PeerID] = member.Username
		}
	}

	return group, nil
}

// GetGroupsByMember retrieves all groups a peer is a member of
func (s *SQLiteDB) GetGroupsByMember(ctx context.Context, peerID string) ([]*models.Group, error) {
	query := `SELECT DISTINCT g.id, g.name, g.description, g.created_by, g.created_at, g.updated_at, g.is_active
			   FROM groups g
			   JOIN group_members gm ON g.id = gm.group_id
			   WHERE gm.peer_id = ? AND gm.is_active = TRUE AND g.is_active = TRUE`

	rows, err := s.db.QueryContext(ctx, query, peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query groups by member: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		var createdAt, updatedAt string

		err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedBy,
			&createdAt, &updatedAt, &group.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}

		group.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		group.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		group.Members = make(map[string]string)

		groups = append(groups, group)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}

	return groups, nil
}

// UpdateGroup updates group information
func (s *SQLiteDB) UpdateGroup(ctx context.Context, group *models.Group) error {
	query := `UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, group.Name, group.Description, time.Now(), group.ID)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	return nil
}

// DeleteGroup deletes a group (soft delete)
func (s *SQLiteDB) DeleteGroup(ctx context.Context, groupID string) error {
	query := `UPDATE groups SET is_active = FALSE WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, groupID)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}

// AddGroupMember adds a member to a group
func (s *SQLiteDB) AddGroupMember(ctx context.Context, member *models.GroupMember) error {
	query := `INSERT OR REPLACE INTO group_members (group_id, peer_id, username, joined_at, role, is_active)
			   VALUES (?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		member.GroupID, member.PeerID, member.Username,
		member.JoinedAt, member.Role, member.IsActive)

	if err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a member from a group
func (s *SQLiteDB) RemoveGroupMember(ctx context.Context, groupID, peerID string) error {
	query := `UPDATE group_members SET is_active = FALSE WHERE group_id = ? AND peer_id = ?`
	_, err := s.db.ExecContext(ctx, query, groupID, peerID)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}
	return nil
}

// GetGroupMembers retrieves all members of a group
func (s *SQLiteDB) GetGroupMembers(ctx context.Context, groupID string) ([]*models.GroupMember, error) {
	query := `SELECT group_id, peer_id, username, joined_at, role, is_active
			   FROM group_members WHERE group_id = ?`

	rows, err := s.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	var members []*models.GroupMember
	for rows.Next() {
		member := &models.GroupMember{}
		var joinedAt string

		err := rows.Scan(&member.GroupID, &member.PeerID, &member.Username,
			&joinedAt, &member.Role, &member.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan group member: %w", err)
		}

		member.JoinedAt, _ = time.Parse("2006-01-02 15:04:05", joinedAt)
		members = append(members, member)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group members: %w", err)
	}

	return members, nil
}

// IsGroupMember checks if a peer is a member of a group
func (s *SQLiteDB) IsGroupMember(ctx context.Context, groupID, peerID string) (bool, error) {
	query := `SELECT COUNT(*) FROM group_members WHERE group_id = ? AND peer_id = ? AND is_active = TRUE`

	var count int
	err := s.db.QueryRowContext(ctx, query, groupID, peerID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check group membership: %w", err)
	}

	return count > 0, nil
}

// CreateInvite creates a new group invitation
func (s *SQLiteDB) CreateInvite(ctx context.Context, invite *models.GroupInvite) error {
	query := `INSERT INTO group_invites (id, group_id, inviter_id, invitee_id, created_at, expires_at, status)
			   VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		invite.ID, invite.GroupID, invite.InviterID, invite.InviteeID,
		invite.CreatedAt, invite.ExpiresAt, invite.Status)

	if err != nil {
		return fmt.Errorf("failed to create invite: %w", err)
	}
	return nil
}

// GetInvite retrieves an invitation by ID
func (s *SQLiteDB) GetInvite(ctx context.Context, inviteID string) (*models.GroupInvite, error) {
	query := `SELECT id, group_id, inviter_id, invitee_id, created_at, expires_at, status
			   FROM group_invites WHERE id = ?`

	invite := &models.GroupInvite{}
	var createdAt, expiresAt string

	err := s.db.QueryRowContext(ctx, query, inviteID).Scan(
		&invite.ID, &invite.GroupID, &invite.InviterID, &invite.InviteeID,
		&createdAt, &expiresAt, &invite.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invite not found")
		}
		return nil, fmt.Errorf("failed to get invite: %w", err)
	}

	invite.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	invite.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)

	return invite, nil
}

// GetInvitesByInvitee retrieves all invitations for a specific invitee
func (s *SQLiteDB) GetInvitesByInvitee(ctx context.Context, inviteeID string) ([]*models.GroupInvite, error) {
	query := `SELECT id, group_id, inviter_id, invitee_id, created_at, expires_at, status
			   FROM group_invites WHERE invitee_id = ? ORDER BY created_at DESC`

	return s.queryInvites(ctx, query, inviteeID)
}

// GetInvitesByGroup retrieves all invitations for a specific group
func (s *SQLiteDB) GetInvitesByGroup(ctx context.Context, groupID string) ([]*models.GroupInvite, error) {
	query := `SELECT id, group_id, inviter_id, invitee_id, created_at, expires_at, status
			   FROM group_invites WHERE group_id = ? ORDER BY created_at DESC`

	return s.queryInvites(ctx, query, groupID)
}

// queryInvites is a helper function to execute invite queries
func (s *SQLiteDB) queryInvites(ctx context.Context, query string, args ...interface{}) ([]*models.GroupInvite, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query invites: %w", err)
	}
	defer rows.Close()

	var invites []*models.GroupInvite
	for rows.Next() {
		invite := &models.GroupInvite{}
		var createdAt, expiresAt string

		err := rows.Scan(&invite.ID, &invite.GroupID, &invite.InviterID, &invite.InviteeID,
			&createdAt, &expiresAt, &invite.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan invite: %w", err)
		}

		invite.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		invite.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)

		invites = append(invites, invite)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating invites: %w", err)
	}

	return invites, nil
}

// UpdateInviteStatus updates the status of an invitation
func (s *SQLiteDB) UpdateInviteStatus(ctx context.Context, inviteID, status string) error {
	query := `UPDATE group_invites SET status = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, status, inviteID)
	if err != nil {
		return fmt.Errorf("failed to update invite status: %w", err)
	}
	return nil
}

// DeleteInvite deletes an invitation
func (s *SQLiteDB) DeleteInvite(ctx context.Context, inviteID string) error {
	query := `DELETE FROM group_invites WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, inviteID)
	if err != nil {
		return fmt.Errorf("failed to delete invite: %w", err)
	}
	return nil
}

// CleanupExpiredInvites removes expired invitations
func (s *SQLiteDB) CleanupExpiredInvites(ctx context.Context) error {
	query := `UPDATE group_invites SET status = 'expired' WHERE expires_at < CURRENT_TIMESTAMP AND status = 'pending'`
	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired invites: %w", err)
	}
	return nil
}

// nullString returns sql.NullString for empty strings
func nullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}
