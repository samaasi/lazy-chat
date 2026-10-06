package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/samaasi/lazy-chat/internal/app"
	"github.com/samaasi/lazy-chat/internal/config"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Println("lazy-chat", version)
			return 0
		}
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

	application, err := app.New(cfg, app.WithVersion(version))
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
