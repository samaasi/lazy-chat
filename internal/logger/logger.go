// Package logger is a small wrapper around log/slog that satisfies
// interfaces.Logger. slog quotes and escapes attribute values, so untrusted
// peer-supplied strings cannot forge extra log lines.
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func (l Level) slog() slog.Level {
	switch l {
	case DebugLevel:
		return slog.LevelDebug
	case WarnLevel:
		return slog.LevelWarn
	case ErrorLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// OutputFormat represents the output format for logs
type OutputFormat int

const (
	TextFormat OutputFormat = iota
	JSONFormat
)

// Options configures a Logger.
type Options struct {
	Level  Level
	Format OutputFormat
	// File, when non-empty, sends logs to a rotating file instead of Output.
	File string
	// Output is used when File is empty. Defaults to os.Stderr so log lines
	// do not interleave with the interactive prompt on stdout.
	Output io.Writer
}

// Logger implements interfaces.Logger.
type Logger struct {
	l      *slog.Logger
	level  *slog.LevelVar
	closer io.Closer
}

// New builds a logger from opts.
func New(opts Options) (*Logger, error) {
	var out io.Writer = opts.Output
	var closer io.Closer

	if opts.File != "" {
		w, err := newRotatingFile(opts.File, maxLogSize, maxLogBackups)
		if err != nil {
			return nil, err
		}
		out, closer = w, w
	}
	if out == nil {
		out = os.Stderr
	}

	level := &slog.LevelVar{}
	level.Set(opts.Level.slog())

	handlerOpts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if opts.Format == JSONFormat {
		h = slog.NewJSONHandler(out, handlerOpts)
	} else {
		h = slog.NewTextHandler(out, handlerOpts)
	}
	return &Logger{l: slog.New(h), level: level, closer: closer}, nil
}

// Discard returns a logger that drops everything; handy in tests.
func Discard() *Logger {
	l, _ := New(Options{Level: ErrorLevel + 1, Output: io.Discard})
	return l
}

// Debug logs a debug message with optional key-value pairs
func (l *Logger) Debug(msg string, kv ...any) { l.l.Debug(msg, kv...) }

// Info logs an info message with optional key-value pairs
func (l *Logger) Info(msg string, kv ...any) { l.l.Info(msg, kv...) }

// Warn logs a warning message with optional key-value pairs
func (l *Logger) Warn(msg string, kv ...any) { l.l.Warn(msg, kv...) }

// Error logs an error message with optional key-value pairs
func (l *Logger) Error(msg string, kv ...any) { l.l.Error(msg, kv...) }

// Fatal logs at error level, flushes and exits the process. Prefer returning
// errors; this exists to satisfy interfaces.Logger.
func (l *Logger) Fatal(msg string, kv ...any) {
	l.l.Error(msg, kv...)
	_ = l.Close()
	os.Exit(1)
}

// SetLevel changes the logging level; safe for concurrent use.
func (l *Logger) SetLevel(level Level) { l.level.Set(level.slog()) }

// Close flushes and closes the log file, if any.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// ParseLevel parses a string into a log level
func ParseLevel(levelStr string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return DebugLevel, nil
	case "info":
		return InfoLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "error":
		return ErrorLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level: %s", levelStr)
	}
}

// ParseFormat parses "text" or "json".
func ParseFormat(s string) OutputFormat {
	if strings.EqualFold(strings.TrimSpace(s), "json") {
		return JSONFormat
	}
	return TextFormat
}

const (
	maxLogSize    = 10 << 20 // 10 MiB
	maxLogBackups = 3
)

// rotatingFile is a minimal size-based rotating writer: app.log, app.log.1, ...
type rotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	f       *os.File
	size    int64
}

func newRotatingFile(path string, max int64, backups int) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	r := &rotatingFile{path: path, max: max, backups: backups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	r.f.Close()
	for i := r.backups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
	return r.open()
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
