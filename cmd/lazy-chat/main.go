package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/lazy-chat/internal/app"
	"github.com/lazy-chat/internal/cli"
	"github.com/lazy-chat/internal/config"
	"github.com/lazy-chat/internal/errors"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Create application instance
	app, err := app.New(cfg)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			log.Fatalf("Failed to create application: %s (Code: %s, Type: %s)", appErr.Message, appErr.Code, appErr.Type)
		} else {
			log.Fatalf("Failed to create application: %v", err)
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the application services
	if err := app.Start(); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			log.Fatalf("Failed to start application: %s (Code: %s, Type: %s)", appErr.Message, appErr.Code, appErr.Type)
		} else {
			log.Fatalf("Failed to start application: %v", err)
		}
	}

	// Ensure cleanup on exit
	defer func() {
		if err := app.Stop(); err != nil {
			app.GetLogger().Error("Error during application shutdown", "error", err)
		}
	}()

	// Create and start CLI
	cli := cli.New(
		app.GetPeerManager(),
		app.GetNetworkManager(),
		app.GetLogger(),
		app.GetConfig().Username,
	)

	// Run CLI and application concurrently
	var wg sync.WaitGroup

	// Start CLI in a separate goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cli.Start(ctx); err != nil {
			if err != context.Canceled {
				app.GetLogger().Error("CLI error", "error", err)
			}
		}
		cancel() // Signal shutdown when CLI exits
	}()

	// Wait for CLI to finish
	wg.Wait()

	fmt.Println("Application terminated.")
}
