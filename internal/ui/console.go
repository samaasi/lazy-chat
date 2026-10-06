// Package ui handles terminal output.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
)

// Console is the one place that writes to the terminal. Everything goes
// through a mutex so lines printed by network goroutines (incoming messages)
// cannot interleave with command output, and the input prompt is redrawn
// after asynchronous output.
//
// As a last line of defence it removes control characters (ESC, which begins
// ANSI sequences, among them) and bidirectional overrides from everything it
// prints. Call sites should already have sanitised peer-supplied text; this
// guarantees that a forgotten call site cannot let a remote peer drive the
// user's terminal.
type Console struct {
	mu        sync.Mutex
	out       io.Writer
	prompt    string
	prompting bool
	status    bool // a status line (no trailing newline) is on screen
}

// NewConsole creates a console writing to out.
func NewConsole(out io.Writer) *Console {
	return &Console{out: out}
}

// SetPrompt sets the prompt shown while waiting for input.
func (c *Console) SetPrompt(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prompt = p
}

// ShowPrompt prints the prompt and remembers that input is being awaited, so
// later asynchronous output redraws it.
func (c *Console) ShowPrompt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prompting = true
	_, _ = io.WriteString(c.out, c.prompt)
}

// InputDone records that a line was entered; the prompt is no longer redrawn
// until ShowPrompt is called again.
func (c *Console) InputDone() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prompting = false
}

// Printf prints a formatted line (a newline is appended if missing).
func (c *Console) Printf(format string, args ...any) {
	c.print(fmt.Sprintf(format, args...))
}

// Println prints its operands as a line.
func (c *Console) Println(args ...any) {
	c.print(strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

func (c *Console) print(s string) {
	s = Scrub(s)
	c.mu.Lock()
	defer c.mu.Unlock()

	var b strings.Builder
	if c.prompting || c.status {
		b.WriteString("\r") // overwrite the prompt or status line
		c.status = false
	}
	b.WriteString(s)
	if !strings.HasSuffix(s, "\n") {
		b.WriteString("\n")
	}
	if c.prompting {
		b.WriteString(c.prompt)
	}
	_, _ = io.WriteString(c.out, b.String())
}

// Status draws a single self-overwriting line (for progress bars) without a
// trailing newline. The next Printf or EndStatus replaces/terminates it.
func (c *Console) Status(line string) {
	line = Scrub(strings.ReplaceAll(line, "\n", " "))
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = io.WriteString(c.out, "\r"+line)
	c.status = true
}

// EndStatus finishes the current status line with a newline.
func (c *Console) EndStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status {
		_, _ = io.WriteString(c.out, "\n")
		c.status = false
	}
}

// Scrub removes control characters other than newline and tab, and
// bidirectional text-direction overrides.
func Scrub(s string) string {
	clean := true
	for _, r := range s {
		if isUnsafe(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isUnsafe(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isUnsafe(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	if unicode.IsControl(r) {
		return true
	}
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C:
		return true
	}
	return false
}
