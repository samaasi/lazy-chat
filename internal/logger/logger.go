package logger

import (
	"fmt"
	"log"
	"os"
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

// Logger implements the Logger interface
type Logger struct {
	level  Level
	logger *log.Logger
}

// New creates a new logger with the specified level
func New(level Level) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", 0), // No default prefix or flags
	}
}

// NewWithOutput creates a new logger with custom output
func NewWithOutput(level Level, output *os.File) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(output, "", 0),
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

// log formats and outputs a log message
func (l *Logger) log(level Level, msg string, keysAndValues ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := level.String()
	
	// Build the log message
	logMsg := fmt.Sprintf("[%s] %s: %s", timestamp, levelStr, msg)
	
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