package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/samaasi/lazy-chat/internal/app"
	"github.com/samaasi/lazy-chat/internal/config"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/update"
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
