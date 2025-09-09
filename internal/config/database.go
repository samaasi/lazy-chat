package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DatabaseConfig holds database configuration settings
type DatabaseConfig struct {
	Type         string        `json:"type" yaml:"type"`                   // sqlite, postgres, mysql
	Path         string        `json:"path" yaml:"path"`                   // for sqlite
	Host         string        `json:"host" yaml:"host"`                   // for network databases
	Port         int           `json:"port" yaml:"port"`                   // for network databases
	Database     string        `json:"database" yaml:"database"`           // database name
	Username     string        `json:"username" yaml:"username"`           // database username
	Password     string        `json:"password" yaml:"password"`           // database password
	SSLMode      string        `json:"ssl_mode" yaml:"ssl_mode"`           // SSL mode for postgres
	MaxOpenConns int           `json:"max_open_conns" yaml:"max_open_conns"` // maximum open connections
	MaxIdleConns int           `json:"max_idle_conns" yaml:"max_idle_conns"` // maximum idle connections
	ConnMaxLife  time.Duration `json:"conn_max_life" yaml:"conn_max_life"`   // connection maximum lifetime
	Migrate      bool          `json:"migrate" yaml:"migrate"`             // auto-migrate on startup
}

// DefaultDatabaseConfig returns default database configuration
func DefaultDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Type:         "sqlite",
		Path:         getDefaultDBPath(),
		MaxOpenConns: 25,
		MaxIdleConns: 5,
		ConnMaxLife:  5 * time.Minute,
		Migrate:      true,
	}
}

// getDefaultDBPath returns the default database path
func getDefaultDBPath() string {
	// Try to use user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory
		return "./lazy-chat.db"
	}

	// Create .lazy-chat directory in user's home
	configDir := filepath.Join(homeDir, ".lazy-chat")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		// Fallback to current directory
		return "./lazy-chat.db"
	}

	return filepath.Join(configDir, "lazy-chat.db")
}

// GetConnectionString returns the database connection string
func (dc *DatabaseConfig) GetConnectionString() string {
	switch dc.Type {
	case "sqlite":
		return dc.Path
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			dc.Host, dc.Port, dc.Username, dc.Password, dc.Database, dc.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			dc.Username, dc.Password, dc.Host, dc.Port, dc.Database)
	default:
		return dc.Path // fallback to sqlite
	}
}

// Validate validates the database configuration
func (dc *DatabaseConfig) Validate() error {
	switch dc.Type {
	case "sqlite":
		if dc.Path == "" {
			return fmt.Errorf("database path is required for SQLite")
		}
		// Ensure directory exists
		dir := filepath.Dir(dc.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	case "postgres", "mysql":
		if dc.Host == "" {
			return fmt.Errorf("database host is required")
		}
		if dc.Port <= 0 {
			return fmt.Errorf("database port must be positive")
		}
		if dc.Database == "" {
			return fmt.Errorf("database name is required")
		}
		if dc.Username == "" {
			return fmt.Errorf("database username is required")
		}
	default:
		return fmt.Errorf("unsupported database type: %s", dc.Type)
	}

	if dc.MaxOpenConns <= 0 {
		dc.MaxOpenConns = 25
	}
	if dc.MaxIdleConns <= 0 {
		dc.MaxIdleConns = 5
	}
	if dc.ConnMaxLife <= 0 {
		dc.ConnMaxLife = 5 * time.Minute
	}

	return nil
}

// GetDriverName returns the database driver name
func (dc *DatabaseConfig) GetDriverName() string {
	switch dc.Type {
	case "sqlite":
		return "sqlite3"
	case "postgres":
		return "postgres"
	case "mysql":
		return "mysql"
	default:
		return "sqlite3"
	}
}