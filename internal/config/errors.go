package config

import "errors"

// Configuration validation errors
var (
	ErrInvalidPort         = errors.New("invalid TCP port: must be between 1 and 65535")
	ErrInvalidDiscoveryPort = errors.New("invalid discovery port: must be between 1 and 65535")
	ErrEmptyUsername       = errors.New("username cannot be empty")
)