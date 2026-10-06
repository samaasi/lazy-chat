package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// oldSuffix marks the previous executable on Windows, which cannot delete a
// running program but can rename it.
const oldSuffix = ".old"

// Replace puts the file at staged in place of exe, atomically as far as the
// platform allows: on Unix a rename over the old file; on Windows the running
// executable is renamed aside first. If anything fails the old executable is
// left in (or restored to) its place.
func Replace(exe, staged string) error {
	if runtime.GOOS != "windows" {
		if err := os.Rename(staged, exe); err != nil {
			return permissionHint(filepath.Dir(exe), err)
		}
		return nil
	}
	old := exe + oldSuffix
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return permissionHint(filepath.Dir(exe), err)
	}
	if err := os.Rename(staged, exe); err != nil {
		if rerr := os.Rename(old, exe); rerr != nil {
			return errors.Join(err, fmt.Errorf("and could not restore the old version from %s: %w", old, rerr))
		}
		return permissionHint(filepath.Dir(exe), err)
	}
	return nil
}

func permissionHint(dir string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("cannot write to %s: %w (re-run with the permissions needed to modify it, e.g. sudo)", dir, err)
	}
	return err
}

// CleanupOld removes the executable left behind by a previous Windows update.
func CleanupOld(exe string) { _ = os.Remove(exe + oldSuffix) }

// Executable returns the real path of the running program.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// ManagedBy names the package manager that owns exe, or "" if none seems to.
// Replacing such a file behind its manager's back leaves it confused.
func ManagedBy(exe string) (manager, command string) {
	p := filepath.ToSlash(exe)
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(p, "/Cellar/") || strings.Contains(lower, "/homebrew/") || strings.Contains(lower, "linuxbrew/"):
		return "Homebrew", "brew upgrade lazy-chat"
	case strings.Contains(lower, "/scoop/"):
		return "Scoop", "scoop update lazy-chat"
	case isGoBin(p):
		return "go install", "go install github.com/samaasi/lazy-chat/cmd/lazy-chat@latest"
	}
	return "", ""
}

func isGoBin(slashPath string) bool {
	dir := filepath.ToSlash(filepath.Dir(slashPath))
	if b := os.Getenv("GOBIN"); b != "" && filepath.ToSlash(b) == dir {
		return true
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			gopath = filepath.Join(home, "go")
		}
	}
	for _, p := range filepath.SplitList(gopath) {
		if filepath.ToSlash(filepath.Join(p, "bin")) == dir {
			return true
		}
	}
	return false
}
