package utils

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeText makes peer-supplied text safe to print on a terminal, write to
// a log, or hand to a notification daemon. It
//   - replaces invalid UTF-8,
//   - turns tabs and line breaks into spaces (so one message is one line),
//   - drops every other control character (ANSI escape sequences start with ESC),
//   - drops bidirectional override/isolate marks used for text spoofing,
//   - truncates to maxRunes runes (0 means unlimited), marking the cut with "…".
func SanitizeText(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "�")

	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ' ':
			r = ' '
		case unicode.IsControl(r), isBidiControl(r):
			continue
		}
		if maxRunes > 0 && count >= maxRunes {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C: // LRM RLM ALM
		return true
	}
	return false
}

// ErrUnsafeFileName is returned when a name cannot be turned into a safe one.
var ErrUnsafeFileName = errors.New("unsafe file name")

const maxFileNameBytes = 200

var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// SafeFileName reduces an untrusted file name to a single path element that
// is safe to create inside a download directory on any supported OS: no
// directory components, no traversal, no control or reserved characters, no
// Windows device names, bounded length.
func SafeFileName(name string) (string, error) {
	name = strings.ToValidUTF8(name, "_")

	// Keep only what follows the last separator of either style, so
	// "..\..\evil.txt" and "../../evil.txt" both reduce to "evil.txt".
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case unicode.IsControl(r), isBidiControl(r):
			continue
		case strings.ContainsRune(`<>:"|?*`, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	name = strings.TrimRight(strings.TrimLeft(b.String(), " "), " .")
	if name == "" {
		return "", ErrUnsafeFileName
	}

	if len(name) > maxFileNameBytes {
		ext := filepath.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		stem := truncateUTF8(strings.TrimSuffix(name, ext), maxFileNameBytes-len(ext))
		name = stem + ext
	}

	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if windowsReserved[strings.ToUpper(stem)] {
		name = "_" + name
	}
	return name, nil
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}
