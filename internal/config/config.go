package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
)

// MaxUsernameLen is the longest display name we accept.
const MaxUsernameLen = 32

// DefaultConfigFile is read when --config is not given. It may be absent.
const DefaultConfigFile = "config.json"

// Config holds all configuration for the P2P chat application
type Config struct {
	Username             string          `json:"username"`
	TCPPort              int             `json:"tcp_port"`
	ListenAddr           string          `json:"listen_addr"` // empty = all interfaces
	MaxConnections       int             `json:"max_connections"`
	DiscoveryPort        int             `json:"discovery_port"`
	BroadcastAddr        string          `json:"broadcast_addr"`
	DiscoveryRange       int             `json:"discovery_range"`
	BroadcastInterval    int             `json:"broadcast_interval"` // seconds
	LogLevel             string          `json:"log_level"`
	LogFormat            string          `json:"log_format"` // text or json
	LogFile              string          `json:"log_file"`   // empty for stderr
	NotificationsEnabled bool            `json:"notifications_enabled"`
	DataDir              string          `json:"data_dir"` // identity key and database live here
	DownloadDir          string          `json:"download_dir"`
	MaxFileSize          int64           `json:"max_file_size"`     // bytes accepted per incoming file
	AutoAcceptFiles      bool            `json:"auto_accept_files"` // otherwise /getfile is required
	Database             *DatabaseConfig `json:"database"`
	ConfigFile           string          `json:"-"` // Not serialized
}

// ErrHelp is returned by Load when -h/--help was requested.
var ErrHelp = flag.ErrHelp

// Load builds the configuration from, in increasing priority:
// defaults, the config file, environment variables and command line flags.
// args excludes the program name; getenv is usually os.Getenv.
func Load(args []string, getenv func(string) string) (*Config, error) {
	cfg := DefaultConfig()

	// The config file location must be known before the file is read, so it
	// is resolved from the raw args/env first; flags are fully parsed last so
	// that they win over the file.
	explicit := findConfigPath(args)
	if explicit == "" {
		explicit = getenv("P2P_CONFIG_FILE")
	}
	path, mustExist := explicit, explicit != ""
	if path == "" {
		path = DefaultConfigFile
	}
	if err := cfg.loadFromFile(path, mustExist); err != nil {
		return nil, err
	}
	cfg.ConfigFile = path

	if err := cfg.loadFromEnv(getenv); err != nil {
		return nil, err
	}
	if err := cfg.loadFromFlags(args); err != nil {
		return nil, err
	}

	cfg.finalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadConfig loads configuration from the process arguments and environment.
func LoadConfig() (*Config, error) {
	return Load(os.Args[1:], os.Getenv)
}

// DefaultConfig returns a configuration with sensible defaults. It performs
// no I/O.
func DefaultConfig() *Config {
	return &Config{
		Username:          "Anonymous",
		TCPPort:           8080,
		MaxConnections:    64,
		DiscoveryPort:     9999,
		BroadcastAddr:     "255.255.255.255",
		DiscoveryRange:    10,
		BroadcastInterval: 5,
		LogLevel:          "info",
		LogFormat:         "text",
		DataDir:           defaultDataDir(),
		DownloadDir:       "downloads",
		MaxFileSize:       256 << 20,
		Database:          &DatabaseConfig{},
	}
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".lazy-chat")
	}
	return ".lazy-chat"
}

// finalize fills values derived from other settings.
func (c *Config) finalize() {
	if c.Database == nil {
		c.Database = &DatabaseConfig{}
	}
	c.Database.Path = resolveDatabasePath(c.DataDir, c.Database.Path)
}

// findConfigPath extracts -c/--config from args without parsing the rest.
func findConfigPath(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		trimmed := strings.TrimLeft(arg, "-")
		if dashes := len(arg) - len(trimmed); dashes == 0 || dashes > 2 {
			continue
		}
		name, value, hasValue := strings.Cut(trimmed, "=")
		if name != "config" && name != "c" {
			continue
		}
		if hasValue {
			return value
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (c *Config) loadFromFile(path string, mustExist bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !mustExist {
			return nil
		}
		return apperrors.ErrConfigLoadFailed.WithContext("file", path).WithContext("error", err.Error())
	}
	if err := json.Unmarshal(data, c); err != nil {
		return apperrors.ErrConfigInvalid.WithContext("file", path).WithContext("error", err.Error())
	}
	return nil
}

func (c *Config) loadFromEnv(getenv func(string) string) error {
	if c.Database == nil {
		c.Database = &DatabaseConfig{}
	}
	bindings := []struct {
		name string
		ptr  interface{}
	}{
		{"P2P_USERNAME", &c.Username},
		{"P2P_TCP_PORT", &c.TCPPort},
		{"P2P_LISTEN_ADDR", &c.ListenAddr},
		{"P2P_MAX_CONNECTIONS", &c.MaxConnections},
		{"P2P_DISCOVERY_PORT", &c.DiscoveryPort},
		{"P2P_BROADCAST_ADDR", &c.BroadcastAddr},
		{"P2P_DISCOVERY_RANGE", &c.DiscoveryRange},
		{"P2P_BROADCAST_INTERVAL", &c.BroadcastInterval},
		{"P2P_LOG_LEVEL", &c.LogLevel},
		{"P2P_LOG_FORMAT", &c.LogFormat},
		{"P2P_LOG_FILE", &c.LogFile},
		{"P2P_NOTIFICATIONS", &c.NotificationsEnabled},
		{"P2P_DATA_DIR", &c.DataDir},
		{"P2P_DOWNLOAD_DIR", &c.DownloadDir},
		{"P2P_MAX_FILE_SIZE", &c.MaxFileSize},
		{"P2P_AUTO_ACCEPT_FILES", &c.AutoAcceptFiles},
		{"P2P_DB_PATH", &c.Database.Path},
	}

	for _, b := range bindings {
		value := getenv(b.name)
		if value == "" {
			continue
		}
		var err error
		switch ptr := b.ptr.(type) {
		case *string:
			*ptr = value
		case *int:
			*ptr, err = strconv.Atoi(value)
		case *int64:
			*ptr, err = strconv.ParseInt(value, 10, 64)
		case *bool:
			*ptr, err = strconv.ParseBool(value)
		}
		if err != nil {
			return apperrors.ErrConfigInvalid.WithContext("env", b.name).WithContext("error", err.Error())
		}
	}
	return nil
}

func (c *Config) loadFromFlags(args []string) error {
	if c.Database == nil {
		c.Database = &DatabaseConfig{}
	}
	fs := flag.NewFlagSet("lazy-chat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// Each option may be registered under several comma-separated names.
	str := func(p *string, names, usage string) {
		for _, n := range strings.Split(names, ",") {
			fs.StringVar(p, n, *p, usage)
		}
	}
	num := func(p *int, names, usage string) {
		for _, n := range strings.Split(names, ",") {
			fs.IntVar(p, n, *p, usage)
		}
	}
	str(&c.Username, "username,u", "Display name")
	num(&c.TCPPort, "port,p", "TCP port for incoming connections")
	str(&c.ListenAddr, "listen-addr", "Address to listen on")
	num(&c.MaxConnections, "max-connections", "Maximum simultaneous peer connections")
	num(&c.DiscoveryPort, "discovery-port", "Starting UDP port for discovery")
	str(&c.BroadcastAddr, "broadcast-addr", "Broadcast address for discovery")
	num(&c.DiscoveryRange, "discovery-range", "Number of ports to try for discovery")
	num(&c.BroadcastInterval, "broadcast-interval", "Broadcast interval in seconds")
	str(&c.LogLevel, "log-level", "Log level")
	str(&c.LogFormat, "log-format", "Log format")
	str(&c.LogFile, "log-file", "Log file path")
	fs.BoolVar(&c.NotificationsEnabled, "notifications", c.NotificationsEnabled, "Enable OS notifications")
	str(&c.DataDir, "data-dir", "Directory for the identity key and database")
	str(&c.DownloadDir, "download-dir", "Directory for downloaded files")
	fs.Int64Var(&c.MaxFileSize, "max-file-size", c.MaxFileSize, "Largest incoming file in bytes")
	fs.BoolVar(&c.AutoAcceptFiles, "auto-accept-files", c.AutoAcceptFiles, "Accept incoming files without confirmation")
	str(&c.Database.Path, "db-path", "SQLite database path")
	str(&c.ConfigFile, "config,c", "Path to configuration file")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ErrHelp
		}
		return apperrors.ErrConfigInvalid.WithContext("error", err.Error())
	}
	if fs.NArg() > 0 {
		return apperrors.ErrConfigInvalid.WithContext("error", fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	return nil
}

// Usage is the text shown for --help.
const Usage = `Usage: lazy-chat [options]

Options:
  -u, --username <name>         Display name (default "Anonymous")
  -p, --port <n>                TCP port for incoming connections (default 8080)
      --listen-addr <ip>        Address to listen on (default all interfaces)
      --max-connections <n>     Maximum simultaneous peer connections (default 64)
      --discovery-port <n>      Starting UDP port for discovery (default 9999)
      --discovery-range <n>     Number of discovery ports to try (default 10)
      --broadcast-addr <ip>     Broadcast address (default 255.255.255.255)
      --broadcast-interval <s>  Seconds between announcements (default 5)
      --data-dir <dir>          Identity key and database directory (default ~/.lazy-chat)
      --db-path <file>          SQLite database path (default <data-dir>/lazy-chat.db)
      --download-dir <dir>      Where received files are saved (default downloads)
      --max-file-size <bytes>   Largest incoming file (default 268435456)
      --auto-accept-files       Accept incoming files without confirmation
      --notifications           Enable desktop notifications
      --log-level <level>       debug, info, warn, error (default info)
      --log-format <format>     text or json (default text)
      --log-file <file>         Log to a rotating file instead of stderr
  -c, --config <file>           JSON config file (default ./config.json if present)
  -h, --help                    Show this help

Every option can also be set with a P2P_* environment variable (for example
P2P_USERNAME) or a key in the JSON config file. Precedence, lowest to highest:
defaults, config file, environment, command line.

Running two instances on one machine? Give each its own --data-dir and --port.
`

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	invalid := func(field string, value interface{}, reason string) error {
		e := apperrors.ErrConfigValidation.WithContext("field", field).WithContext("value", value)
		if reason != "" {
			e = e.WithContext("reason", reason)
		}
		return e
	}

	if err := ValidateUsername(c.Username); err != nil {
		return invalid("username", c.Username, err.Error())
	}
	if c.TCPPort < 1 || c.TCPPort > 65535 {
		return invalid("tcp_port", c.TCPPort, "must be 1-65535")
	}
	if c.ListenAddr != "" && net.ParseIP(c.ListenAddr) == nil {
		return invalid("listen_addr", c.ListenAddr, "must be an IP address")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 4096 {
		return invalid("max_connections", c.MaxConnections, "must be 1-4096")
	}
	if c.DiscoveryPort < 1 || c.DiscoveryPort > 65535 {
		return invalid("discovery_port", c.DiscoveryPort, "must be 1-65535")
	}
	if c.DiscoveryRange < 1 || c.DiscoveryRange > 100 || c.DiscoveryPort+c.DiscoveryRange-1 > 65535 {
		return invalid("discovery_range", c.DiscoveryRange, "must be 1-100 and stay within valid ports")
	}
	if net.ParseIP(c.BroadcastAddr) == nil {
		return invalid("broadcast_addr", c.BroadcastAddr, "must be an IP address")
	}
	if c.BroadcastInterval < 1 || c.BroadcastInterval > 300 {
		return invalid("broadcast_interval", c.BroadcastInterval, "must be 1-300 seconds")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return invalid("log_level", c.LogLevel, "")
	}
	switch strings.ToLower(c.LogFormat) {
	case "text", "json":
	default:
		return invalid("log_format", c.LogFormat, "")
	}
	if c.DataDir == "" {
		return invalid("data_dir", c.DataDir, "empty")
	}
	if c.DownloadDir == "" {
		return invalid("download_dir", c.DownloadDir, "empty")
	}
	if c.MaxFileSize < 1 {
		return invalid("max_file_size", c.MaxFileSize, "must be positive")
	}
	if c.Database == nil {
		return invalid("database", nil, "missing")
	}
	if err := c.Database.Validate(); err != nil {
		return invalid("database", c.Database.Path, err.Error())
	}
	return nil
}

// ValidateUsername enforces the display-name rules used locally and on
// every name received from the network.
func ValidateUsername(name string) error {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return errors.New("empty")
	case !utf8.ValidString(name):
		return errors.New("not valid UTF-8")
	case utf8.RuneCountInString(name) > MaxUsernameLen:
		return fmt.Errorf("longer than %d characters", MaxUsernameLen)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("contains control characters")
		}
	}
	return nil
}

// String returns a string representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf("Config{Username: %s, TCPPort: %d, DiscoveryPort: %d, LogLevel: %s, DataDir: %s, DownloadDir: %s}",
		c.Username, c.TCPPort, c.DiscoveryPort, c.LogLevel, c.DataDir, c.DownloadDir)
}
