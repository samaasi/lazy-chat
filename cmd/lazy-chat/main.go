package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/samaasi/lazy-chat/internal/app"
	"github.com/samaasi/lazy-chat/internal/config"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/firewall"
	"github.com/samaasi/lazy-chat/internal/update"
	"golang.org/x/term"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
// Builds made with `go install ...@v1.2.3` carry it in the module information
// instead, see currentVersion.
var version = "dev"

// currentVersion is the version this program reports.
func currentVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && update.IsRelease(info.Main.Version) {
		return info.Main.Version
	}
	return version
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ver := currentVersion()
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Println("lazy-chat", ver)
			return 0
		}
	}

	exe, exeErr := update.Executable()
	if exeErr == nil {
		update.CleanupOld(exe) // the previous version, left by a Windows update
	}
	if len(args) > 0 && args[0] == "update" {
		if exeErr != nil {
			fmt.Fprintln(os.Stderr, "Cannot locate this program:", exeErr)
			return 1
		}
		return update.Command(context.Background(), args[1:], os.Stdout, os.Stderr, update.New(ver), exe)
	}

	if len(args) > 0 && args[0] == "firewall" {
		if exeErr != nil {
			fmt.Fprintln(os.Stderr, "Cannot locate this program:", exeErr)
			return 1
		}
		return firewallCommand(args[1:], exe)
	}

	cfg, err := config.Load(args, os.Getenv)
	if err != nil {
		if errors.Is(err, config.ErrHelp) {
			fmt.Print(config.Usage)
			return 0
		}
		fmt.Fprintln(os.Stderr, "Failed to load configuration:", describe(err))
		fmt.Fprintln(os.Stderr, "Run with --help for usage.")
		return 2
	}

	opts := []app.Option{app.WithVersion(ver)}
	if exeErr == nil {
		guard := firewall.New(exe, cfg.TCPPort, cfg.DiscoveryPort, cfg.DiscoveryRange)
		askedBefore := firewall.AlreadyAsked(cfg.DataDir, exe)
		// The first time, ask whether to open Windows Firewall (an interactive
		// terminal only: a service or a pipe cannot answer).
		if term.IsTerminal(int(os.Stdin.Fd())) {
			firewall.FirstRun(context.Background(), guard, cfg.DataDir, os.Stdin, os.Stdout)
		}
		opts = append(opts, app.WithFirewall(guard, askedBefore || !firewall.AlreadyAsked(cfg.DataDir, exe)))
	}
	if cfg.UpdateCheck {
		u := update.New(ver)
		state := filepath.Join(cfg.DataDir, "update-check.json")
		opts = append(opts, app.WithUpdateNotice(func(ctx context.Context) string {
			return u.Available(ctx, state, update.CheckInterval, time.Now())
		}))
	}
	application, err := app.New(cfg, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create application:", describe(err))
		return 1
	}

	// Run starts the services, blocks until /quit or a signal, then shuts down.
	if err := application.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Application error:", describe(err))
		return 1
	}
	return 0
}

// firewallCommand implements `lazy-chat firewall [--status | --remove]`.
func firewallCommand(args []string, exe string) int {
	fs := flag.NewFlagSet("firewall", flag.ContinueOnError)
	status := fs.Bool("status", false, "only report whether peers can reach this program")
	remove := fs.Bool("remove", false, "remove the rule this program added")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: lazy-chat firewall [--status | --remove]")
		fmt.Fprintln(os.Stderr, "Allows lazy-chat through the firewall on private networks (Windows: one administrator prompt).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// Ports come from the usual configuration (file and environment).
	cfg, err := config.Load(nil, os.Getenv)
	if err != nil {
		cfg = config.DefaultConfig()
	}
	g := firewall.New(exe, cfg.TCPPort, cfg.DiscoveryPort, cfg.DiscoveryRange)
	ctx := context.Background()

	if *remove {
		if err := g.Remove(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "Could not remove the rule:", err)
			return 1
		}
		fmt.Println("Removed the lazy-chat firewall rule.")
		return 0
	}
	r := g.Check(ctx)
	if *status {
		fmt.Println("Firewall:", r.Status)
		if r.Advice != "" {
			fmt.Println(r.Advice)
		}
		if r.Status == firewall.Blocked {
			return 1
		}
		return 0
	}
	if r.Status == firewall.Open {
		fmt.Println("Nothing to do: other peers can already reach lazy-chat.")
		if r.PublicNetwork {
			fmt.Println(r.Advice)
		}
		return 0
	}
	switch err := g.Allow(ctx); {
	case err == nil:
		fmt.Println("Done: lazy-chat is allowed on private networks.")
		if r.PublicNetwork {
			fmt.Println(r.Advice)
		}
		return 0
	case errors.Is(err, firewall.ErrManual):
		if r.Advice == "" {
			fmt.Println("No active firewall found that lazy-chat could open.")
			return 0
		}
		fmt.Println(r.Advice)
		return 1
	case errors.Is(err, firewall.ErrDeclined):
		fmt.Fprintln(os.Stderr, "The administrator prompt was declined; nothing was changed.")
		return 1
	default:
		fmt.Fprintln(os.Stderr, "Could not change the firewall:", err)
		return 1
	}
}

// describe renders structured application errors with their context.
func describe(err error) string {
	var appErr *apperrors.AppError
	if errors.As(err, &appErr) {
		msg := fmt.Sprintf("%s (code %s)", appErr.Message, appErr.Code)
		for k, v := range appErr.Context {
			msg += fmt.Sprintf(" %s=%v", k, v)
		}
		if appErr.Cause != nil {
			msg += ": " + appErr.Cause.Error()
		}
		return msg
	}
	return err.Error()
}
