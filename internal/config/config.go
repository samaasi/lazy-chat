package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/samaasi/lazy-chat/internal/errors"
)

// Config holds all configuration for the P2P chat application
type Config struct {
	Username             string `json:"username"`
	TCPPort              int    `json:"tcp_port"`
	DiscoveryPort        int    `json:"discovery_port"`
	BroadcastAddr        string `json:"broadcast_addr"`
	DiscoveryRange       int    `json:"discovery_range"`
	BroadcastInterval    int    `json:"broadcast_interval"` // seconds
	LogLevel             string `json:"log_level"`
	LogFormat            string `json:"log_format"` // text or json
	LogFile              string `json:"log_file"`   // empty for stdout only
	NotificationsEnabled bool   `json:"notifications_enabled"`
	DownloadDir          string `json:"download_dir"`
	ConfigFile           string `json:"-"` // Not serialized
}

// LoadConfig loads configuration from all sources in priority order:
// 1. Default values
// 2. Configuration file
// 3. Environment variables
// 4. Command line flags
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Load from config file if specified
	if err := cfg.LoadFromFile(); err != nil {
		return nil, err
	}

	cfg.LoadFromEnv()
	cfg.LoadFromFlags()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Username:             "Anonymous",
		TCPPort:              8080,
		DiscoveryPort:        9999,
		BroadcastAddr:        "255.255.255.255",
		DiscoveryRange:       10,
		BroadcastInterval:    5,
		LogLevel:             "info",
		LogFormat:            "text",
		LogFile:              "",
		NotificationsEnabled: true,
		DownloadDir:          "downloads",
		ConfigFile:           "",
	}
}

// LoadFromFlags loads configuration from command line flags
func (c *Config) LoadFromFlags() {
	flag.StringVar(&c.Username, "username", c.Username, "Username for the chat")
	flag.IntVar(&c.TCPPort, "port", c.TCPPort, "TCP port for incoming connections")
	flag.IntVar(&c.DiscoveryPort, "discovery-port", c.DiscoveryPort, "Starting UDP port for discovery")
	flag.StringVar(&c.BroadcastAddr, "broadcast-addr", c.BroadcastAddr, "Broadcast address for discovery")
	flag.IntVar(&c.DiscoveryRange, "discovery-range", c.DiscoveryRange, "Number of ports to try for discovery")
	flag.IntVar(&c.BroadcastInterval, "broadcast-interval", c.BroadcastInterval, "Broadcast interval in seconds")
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Log level (debug, info, warn, error)")
	flag.StringVar(&c.LogFormat, "log-format", c.LogFormat, "Log format (text, json)")
	flag.StringVar(&c.LogFile, "log-file", c.LogFile, "Log file path (empty for stdout only)")
	flag.BoolVar(&c.NotificationsEnabled, "notifications", c.NotificationsEnabled, "Enable OS notifications")
	flag.StringVar(&c.DownloadDir, "download-dir", c.DownloadDir, "Directory for downloaded files")
	flag.StringVar(&c.ConfigFile, "config", c.ConfigFile, "Path to configuration file")
	flag.Parse()
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	envVars := map[string]interface{}{
		"P2P_USERNAME":           &c.Username,
		"P2P_TCP_PORT":           &c.TCPPort,
		"P2P_DISCOVERY_PORT":     &c.DiscoveryPort,
		"P2P_BROADCAST_ADDR":     &c.BroadcastAddr,
		"P2P_DISCOVERY_RANGE":    &c.DiscoveryRange,
		"P2P_BROADCAST_INTERVAL": &c.BroadcastInterval,
		"P2P_LOG_LEVEL":          &c.LogLevel,
		"P2P_LOG_FORMAT":         &c.LogFormat,
		"P2P_LOG_FILE":           &c.LogFile,
		"P2P_NOTIFICATIONS":      &c.NotificationsEnabled,
		"P2P_DOWNLOAD_DIR":       &c.DownloadDir,
		"P2P_CONFIG_FILE":        &c.ConfigFile,
	}

	for envVar, field := range envVars {
		if value := os.Getenv(envVar); value != "" {
			switch ptr := field.(type) {
			case *string:
				*ptr = value
			case *int:
				if intVal, err := strconv.Atoi(value); err == nil {
					*ptr = intVal
				}
			case *bool:
				if boolVal, err := strconv.ParseBool(value); err == nil {
					*ptr = boolVal
				}
			}
		}
	}
}

// LoadFromFile loads configuration from a JSON file
func (c *Config) LoadFromFile() error {
	if c.ConfigFile == "" {
		return nil // No config file specified
	}

	data, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Config file doesn't exist, use defaults
		}
		return errors.ErrConfigInvalid.WithContext("file", c.ConfigFile).WithContext("error", err.Error())
	}

	if err := json.Unmarshal(data, c); err != nil {
		return errors.ErrConfigInvalid.WithContext("file", c.ConfigFile).WithContext("error", err.Error())
	}

	return nil
}

// SaveToFile saves the current configuration to a JSON file
func (c *Config) SaveToFile(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return errors.ErrConfigInvalid.WithContext("error", err.Error())
	}

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.ErrConfigInvalid.WithContext("dir", dir).WithContext("error", err.Error())
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return errors.ErrConfigInvalid.WithContext("file", filename).WithContext("error", err.Error())
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.TCPPort < 1 || c.TCPPort > 65535 {
		return errors.ErrConfigValidation.WithContext("field", "tcp_port").WithContext("value", c.TCPPort)
	}
	if c.DiscoveryPort < 1 || c.DiscoveryPort > 65535 {
		return errors.ErrConfigValidation.WithContext("field", "discovery_port").WithContext("value", c.DiscoveryPort)
	}
	if c.Username == "" {
		return errors.ErrConfigValidation.WithContext("field", "username").WithContext("reason", "empty")
	}
	if c.DiscoveryRange < 1 || c.DiscoveryRange > 100 {
		return errors.ErrConfigValidation.WithContext("field", "discovery_range").WithContext("value", c.DiscoveryRange)
	}
	if c.BroadcastInterval < 1 || c.BroadcastInterval > 300 {
		return errors.ErrConfigValidation.WithContext("field", "broadcast_interval").WithContext("value", c.BroadcastInterval)
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	validLevel := false
	for _, level := range validLogLevels {
		if strings.ToLower(c.LogLevel) == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return errors.ErrConfigValidation.WithContext("field", "log_level").WithContext("value", c.LogLevel)
	}

	// Validate log format
	validLogFormats := []string{"text", "json"}
	validFormat := false
	for _, format := range validLogFormats {
		if strings.ToLower(c.LogFormat) == format {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return errors.ErrConfigValidation.WithContext("field", "log_format").WithContext("value", c.LogFormat)
	}

	// Validate download directory
	if c.DownloadDir == "" {
		return errors.ErrConfigValidation.WithContext("field", "download_dir").WithContext("reason", "empty")
	}

	return nil
}

// String returns a string representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf("Config{Username: %s, TCPPort: %d, DiscoveryPort: %d, LogLevel: %s, DownloadDir: %s}",
		c.Username, c.TCPPort, c.DiscoveryPort, c.LogLevel, c.DownloadDir)
}
