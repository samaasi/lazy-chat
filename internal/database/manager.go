package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/storage"

	_ "modernc.org/sqlite"
)

// Manager handles database connections and initialization
type Manager struct {
	db     *sql.DB
	config *config.DatabaseConfig
}

// NewManager creates a new database manager
func NewManager(cfg *config.DatabaseConfig) *Manager {
	return &Manager{
		config: cfg,
	}
}

// Initialize initializes the database connection and runs migrations
func (m *Manager) Initialize() error {
	if err := m.config.Validate(); err != nil {
		return fmt.Errorf("invalid database config: %w", err)
	}

	// Open database connection
	db, err := sql.Open(m.config.GetDriverName(), m.config.GetConnectionString())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(m.config.MaxOpenConns)
	db.SetMaxIdleConns(m.config.MaxIdleConns)
	db.SetConnMaxLifetime(m.config.ConnMaxLife)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.db = db

	// Run migrations if enabled
	if m.config.Migrate {
		if err := m.runMigrations(); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	return nil
}

// GetDB returns the database connection
func (m *Manager) GetDB() *sql.DB {
	return m.db
}

// Close closes the database connection
func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// CreateStorageInstances creates storage instances using the database connection
func (m *Manager) CreateStorageInstances() (*storage.SQLiteDB, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	sqliteStorage := storage.NewSQLiteDB(m.config.GetConnectionString())
	return sqliteStorage, nil
}

// runMigrations runs database migrations
func (m *Manager) runMigrations() error {
	migrations := []string{
		createMessagesTable,
		createGroupsTable,
		createGroupMembersTable,
		createGroupInvitesTable,
		createIndexes,
	}

	for i, migration := range migrations {
		if _, err := m.db.Exec(migration); err != nil {
			return fmt.Errorf("failed to run migration %d: %w", i+1, err)
		}
	}

	return nil
}

// Migration SQL statements
const createMessagesTable = `
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_peer TEXT NOT NULL,
    to_peer TEXT,
    group_id TEXT,
    content TEXT NOT NULL,
    message_type INTEGER NOT NULL DEFAULT 0,
    timestamp DATETIME NOT NULL,
    delivered BOOLEAN DEFAULT FALSE,
    read BOOLEAN DEFAULT FALSE,
    deleted BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

const createGroupsTable = `
CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_by TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

const createGroupMembersTable = `
CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    role INTEGER NOT NULL DEFAULT 0,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, peer_id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);
`

const createGroupInvitesTable = `
CREATE TABLE IF NOT EXISTS group_invites (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    inviter_id TEXT NOT NULL,
    invitee_id TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);
`

const createIndexes = `
-- Message indexes
CREATE INDEX IF NOT EXISTS idx_messages_from_peer ON messages(from_peer);
CREATE INDEX IF NOT EXISTS idx_messages_to_peer ON messages(to_peer);
CREATE INDEX IF NOT EXISTS idx_messages_group_id ON messages(group_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type);
CREATE INDEX IF NOT EXISTS idx_messages_read ON messages(read);
CREATE INDEX IF NOT EXISTS idx_messages_delivered ON messages(delivered);

-- Group indexes
CREATE INDEX IF NOT EXISTS idx_groups_created_by ON groups(created_by);
CREATE INDEX IF NOT EXISTS idx_groups_is_active ON groups(is_active);

-- Group member indexes
CREATE INDEX IF NOT EXISTS idx_group_members_peer_id ON group_members(peer_id);
CREATE INDEX IF NOT EXISTS idx_group_members_role ON group_members(role);

-- Group invite indexes
CREATE INDEX IF NOT EXISTS idx_group_invites_invitee_id ON group_invites(invitee_id);
CREATE INDEX IF NOT EXISTS idx_group_invites_status ON group_invites(status);
CREATE INDEX IF NOT EXISTS idx_group_invites_expires_at ON group_invites(expires_at);
`

// HealthCheck performs a health check on the database
func (m *Manager) HealthCheck() error {
	if m.db == nil {
		return fmt.Errorf("database not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.db.PingContext(ctx)
}

// GetStats returns database statistics
func (m *Manager) GetStats() sql.DBStats {
	if m.db == nil {
		return sql.DBStats{}
	}
	return m.db.Stats()
}
