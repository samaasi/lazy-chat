package config

import (
	"flag"
	"os"
	"strconv"

	"github.com/lazy-chat/internal/errors"
)

// Config holds all configuration for the P2P chat application
type Config struct {
	Username        string
	TCPPort         int
	DiscoveryPort   int
	BroadcastAddr   string
	DiscoveryRange  int
	BroadcastInterval int // seconds
}

// LoadConfig loads configuration from all sources
func LoadConfig() *Config {
	cfg := DefaultConfig()
	cfg.LoadFromEnv()
	cfg.LoadFromFlags()
	return cfg
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Username:        "Anonymous",
		TCPPort:         8080,
		DiscoveryPort:   9999,
		BroadcastAddr:   "255.255.255.255",
		DiscoveryRange:  10,
		BroadcastInterval: 5,
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
	flag.Parse()
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	if username := os.Getenv("P2P_USERNAME"); username != "" {
		c.Username = username
	}
	if port := os.Getenv("P2P_TCP_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.TCPPort = p
		}
	}
	if discoveryPort := os.Getenv("P2P_DISCOVERY_PORT"); discoveryPort != "" {
		if p, err := strconv.Atoi(discoveryPort); err == nil {
			c.DiscoveryPort = p
		}
	}
	if broadcastAddr := os.Getenv("P2P_BROADCAST_ADDR"); broadcastAddr != "" {
		c.BroadcastAddr = broadcastAddr
	}
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
	return nil
}