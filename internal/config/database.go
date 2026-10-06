package config

import (
	"fmt"
	"path/filepath"
)

// DatabaseConfig holds database configuration settings. Only SQLite is
// supported; the path defaults to <data_dir>/lazy-chat.db when left empty.
type DatabaseConfig struct {
	Path string `json:"path"`
}

// Validate checks the database configuration.
func (dc *DatabaseConfig) Validate() error {
	if dc.Path == "" {
		return fmt.Errorf("database path is required")
	}
	return nil
}

func resolveDatabasePath(dataDir, p string) string {
	if p == "" {
		return filepath.Join(dataDir, "lazy-chat.db")
	}
	return p
}
