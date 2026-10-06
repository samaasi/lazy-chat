package update

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// Command implements `lazy-chat update [--check] [--force]`. It returns the
// process exit code. exe is the path of the running executable.
func Command(ctx context.Context, args []string, out, errOut io.Writer, u *Updater, exe string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(errOut)
	check := fs.Bool("check", false, "only report whether a newer version exists")
	force := fs.Bool("force", false, "update even if a package manager installed this program")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "Usage: lazy-chat update [--check] [--force]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}

	if !IsRelease(u.Current) {
		fmt.Fprintf(errOut, "This is a development build (%s); install a release to use updates.\n", u.Current)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	fmt.Fprintf(out, "Current version: %s\n", u.Current)
	rel, err := u.Check(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "Update check failed:", err)
		return 1
	}
	if rel == nil {
		fmt.Fprintln(out, "You are up to date.")
		return 0
	}
	fmt.Fprintf(out, "New version available: %s\n", rel.Version)
	if rel.URL != "" {
		fmt.Fprintf(out, "Release notes: %s\n", rel.URL)
	}
	if *check {
		fmt.Fprintln(out, `Run "lazy-chat update" to install it.`)
		return 0
	}

	if manager, cmd := ManagedBy(exe); manager != "" && !*force {
		fmt.Fprintf(errOut, "This copy was installed with %s, which should update it:\n  %s\n(use --force to replace it anyway)\n", manager, cmd)
		return 1
	}
	if u.Key == nil {
		fmt.Fprintln(errOut, "Update failed:", ErrNoReleaseKey)
		return 1
	}
	fmt.Fprintf(out, "Downloading and verifying %s ...\n", ArchiveName(rel.Version, u.GOOS, u.GOARCH))
	if err := u.Install(ctx, rel, exe); err != nil {
		fmt.Fprintln(errOut, "Update failed:", err)
		fmt.Fprintln(errOut, "Your existing installation was not changed.")
		return 1
	}
	fmt.Fprintf(out, "Updated to %s. It takes effect the next time you start lazy-chat.\n", strings.TrimSpace(rel.Version))
	return 0
}
