package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Level represents the logging level
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

// String returns the string representation of the log level
func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// OutputFormat represents the output format for logs
type OutputFormat int

const (
	TextFormat OutputFormat = iota
	JSONFormat
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger implements the Logger interface
type Logger struct {
	level  Level
	logger *log.Logger
	format OutputFormat
	file   *os.File
}

// New creates a new logger with the specified level
func New(level Level) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", 0), // No default prefix or flags
		format: TextFormat,
	}
}

// NewWithOutput creates a new logger with custom output
func NewWithOutput(level Level, output io.Writer) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(output, "", 0),
		format: TextFormat,
	}
}

// NewWithFile creates a new logger that writes to a file
func NewWithFile(level Level, filename string) (*Logger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &Logger{
		level:  level,
		logger: log.New(file, "", 0),
		format: TextFormat,
		file:   file,
	}, nil
}

// NewWithMultiOutput creates a logger that writes to multiple outputs
func NewWithMultiOutput(level Level, outputs ...io.Writer) *Logger {
	multiWriter := io.MultiWriter(outputs...)
	return &Logger{
		level:  level,
		logger: log.New(multiWriter, "", 0),
		format: TextFormat,
	}
}

// Debug logs a debug message with optional key-value pairs
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	if l.level <= DebugLevel {
		l.log(DebugLevel, msg, keysAndValues...)
	}
}

// Info logs an info message with optional key-value pairs
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	if l.level <= InfoLevel {
		l.log(InfoLevel, msg, keysAndValues...)
	}
}

// Warn logs a warning message with optional key-value pairs
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	if l.level <= WarnLevel {
		l.log(WarnLevel, msg, keysAndValues...)
	}
}

// Error logs an error message with optional key-value pairs
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	if l.level <= ErrorLevel {
		l.log(ErrorLevel, msg, keysAndValues...)
	}
}

// Fatal logs a fatal message with optional key-value pairs and exits
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	l.log(ErrorLevel, msg, keysAndValues...)
	os.Exit(1)
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() Level {
	return l.level
}

// SetFormat sets the output format
func (l *Logger) SetFormat(format OutputFormat) {
	l.format = format
}

// GetFormat returns the current output format
func (l *Logger) GetFormat() OutputFormat {
	return l.format
}

// Close closes the log file if one is open
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// log formats and outputs a log message
func (l *Logger) log(level Level, msg string, keysAndValues ...interface{}) {
	timestamp := time.Now().Format(time.RFC3339)
	levelStr := level.String()

	switch l.format {
	case JSONFormat:
		l.logJSON(timestamp, levelStr, msg, keysAndValues...)
	default:
		l.logText(timestamp, levelStr, msg, keysAndValues...)
	}
}

// logText formats and outputs a text log message
func (l *Logger) logText(timestamp, level, msg string, keysAndValues ...interface{}) {
	// Build the log message
	logMsg := fmt.Sprintf("[%s] %s: %s", timestamp, level, msg)
	
	// Add key-value pairs if provided
	if len(keysAndValues) > 0 {
		logMsg += " |"
		for i := 0; i < len(keysAndValues); i += 2 {
			if i+1 < len(keysAndValues) {
				logMsg += fmt.Sprintf(" %v=%v", keysAndValues[i], keysAndValues[i+1])
			} else {
				logMsg += fmt.Sprintf(" %v=<missing_value>", keysAndValues[i])
			}
		}
	}
	
	l.logger.Println(logMsg)
}

// logJSON formats and outputs a JSON log message
func (l *Logger) logJSON(timestamp, level, msg string, keysAndValues ...interface{}) {
	entry := LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Message:   msg,
	}

	// Add key-value pairs as fields
	if len(keysAndValues) > 0 {
		entry.Fields = make(map[string]interface{})
		for i := 0; i < len(keysAndValues); i += 2 {
			if i+1 < len(keysAndValues) {
				key := fmt.Sprintf("%v", keysAndValues[i])
				entry.Fields[key] = keysAndValues[i+1]
			} else {
				key := fmt.Sprintf("%v", keysAndValues[i])
				entry.Fields[key] = "<missing_value>"
			}
		}
	}

	if jsonData, err := json.Marshal(entry); err == nil {
		l.logger.Println(string(jsonData))
	} else {
		// Fallback to text format if JSON marshaling fails
		l.logText(timestamp, level, fmt.Sprintf("%s (JSON marshal error: %v)", msg, err), keysAndValues...)
	}
}

// ParseLevel parses a string into a log level
func ParseLevel(levelStr string) (Level, error) {
	switch levelStr {
	case "debug", "DEBUG":
		return DebugLevel, nil
	case "info", "INFO":
		return InfoLevel, nil
	case "warn", "WARN", "warning", "WARNING":
		return WarnLevel, nil
	case "error", "ERROR":
		return ErrorLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level: %s", levelStr)
	}
}