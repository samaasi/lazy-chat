package errors

import (
	"fmt"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeNetwork     ErrorType = "network"
	ErrorTypeDiscovery   ErrorType = "discovery"
	ErrorTypePeer        ErrorType = "peer"
	ErrorTypeMessage     ErrorType = "message"
	ErrorTypeConfig      ErrorType = "config"
	ErrorTypeApplication ErrorType = "application"
)

// AppError represents a structured application error
type AppError struct {
	Type    ErrorType
	Code    string
	Message string
	Cause   error
	Context map[string]interface{}
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s [%s:%s]: %s (caused by: %v)", e.Type, e.Code, e.Message, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s [%s]: %s", e.Type, e.Code, e.Message)
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// WithContext adds context information to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// New creates a new application error
func New(errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// Wrap wraps an existing error with application error context
func Wrap(err error, errorType ErrorType, code, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Cause:   err,
		Context: make(map[string]interface{}),
	}
}

// Network Error Definitions
var (
	ErrNetworkConnectionFailed = New(ErrorTypeNetwork, "NET001", "failed to establish network connection")
	ErrNetworkListenFailed     = New(ErrorTypeNetwork, "NET002", "failed to start network listener")
	ErrNetworkSendFailed       = New(ErrorTypeNetwork, "NET003", "failed to send data over network")
	ErrNetworkReceiveFailed    = New(ErrorTypeNetwork, "NET004", "failed to receive data from network")
	ErrNetworkTimeout          = New(ErrorTypeNetwork, "NET005", "network operation timed out")
)

// Discovery Error Definitions
var (
	ErrDiscoveryStartFailed   = New(ErrorTypeDiscovery, "DISC001", "failed to start discovery service")
	ErrDiscoveryBroadcastFail = New(ErrorTypeDiscovery, "DISC002", "failed to broadcast discovery message")
	ErrDiscoveryListenFailed  = New(ErrorTypeDiscovery, "DISC003", "failed to listen for discovery messages")
	ErrDiscoveryInvalidMsg    = New(ErrorTypeDiscovery, "DISC004", "received invalid discovery message")
)

// Peer Error Definitions
var (
	ErrPeerNotFound       = New(ErrorTypePeer, "PEER001", "peer not found")
	ErrPeerAlreadyExists  = New(ErrorTypePeer, "PEER002", "peer already exists")
	ErrPeerNotConnected   = New(ErrorTypePeer, "PEER003", "peer is not connected")
	ErrPeerAlreadyConnected = New(ErrorTypePeer, "PEER004", "peer is already connected")
	ErrPeerInvalidID      = New(ErrorTypePeer, "PEER005", "invalid peer ID")
)

// Message Error Definitions
var (
	ErrMessageInvalid     = New(ErrorTypeMessage, "MSG001", "invalid message format")
	ErrMessageEmpty       = New(ErrorTypeMessage, "MSG002", "message content is empty")
	ErrMessageTooLarge    = New(ErrorTypeMessage, "MSG003", "message size exceeds limit")
	ErrMessageSendFailed  = New(ErrorTypeMessage, "MSG004", "failed to send message")
	ErrMessageParseFailed = New(ErrorTypeMessage, "MSG005", "failed to parse message")
	ErrMessageValidation  = New(ErrorTypeMessage, "MSG006", "message validation failed")
)

// Configuration Error Definitions
var (
	ErrConfigInvalid     = New(ErrorTypeConfig, "CFG001", "invalid configuration")
	ErrConfigMissing     = New(ErrorTypeConfig, "CFG002", "required configuration missing")
	ErrConfigLoadFailed  = New(ErrorTypeConfig, "CFG003", "failed to load configuration")
	ErrConfigValidation  = New(ErrorTypeConfig, "CFG004", "configuration validation failed")
)

// Application Error Definitions
var (
	ErrAppStartFailed     = New(ErrorTypeApplication, "APP001", "application failed to start")
	ErrAppStopFailed      = New(ErrorTypeApplication, "APP002", "application failed to stop gracefully")
	ErrAppAlreadyRunning  = New(ErrorTypeApplication, "APP003", "application is already running")
	ErrAppNotRunning      = New(ErrorTypeApplication, "APP004", "application is not running")
	ErrAppInitFailed      = New(ErrorTypeApplication, "APP005", "application initialization failed")
)

// File Transfer Error Definitions
var (
	ErrFileTransferFailed = New(ErrorTypeMessage, "FT001", "file transfer operation failed")
)

// NewFileTransferError creates a new file transfer error
func NewFileTransferError(message string, cause error) *AppError {
	if cause != nil {
		return Wrap(cause, ErrorTypeMessage, "FT001", message)
	}
	return New(ErrorTypeMessage, "FT001", message)
}

// Helper functions for common error patterns

// IsNetworkError checks if an error is a network-related error
func IsNetworkError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeNetwork
	}
	return false
}

// IsDiscoveryError checks if an error is a discovery-related error
func IsDiscoveryError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeDiscovery
	}
	return false
}

// IsPeerError checks if an error is a peer-related error
func IsPeerError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypePeer
	}
	return false
}

// IsMessageError checks if an error is a message-related error
func IsMessageError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeMessage
	}
	return false
}

// IsConfigError checks if an error is a configuration-related error
func IsConfigError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeConfig
	}
	return false
}

// IsApplicationError checks if an error is an application-related error
func IsApplicationError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeApplication
	}
	return false
}