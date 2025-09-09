package main

import (
	"log"

	"github.com/lazy-chat/internal/app"
	"github.com/lazy-chat/internal/config"
	"github.com/lazy-chat/internal/errors"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			log.Fatalf("Failed to load configuration: %s (Code: %s, Type: %s)", appErr.Message, appErr.Code, appErr.Type)
		} else {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	}

	// Create application instance
	app, err := app.New(cfg)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			log.Fatalf("Failed to create application: %s (Code: %s, Type: %s)", appErr.Message, appErr.Code, appErr.Type)
		} else {
			log.Fatalf("Failed to create application: %v", err)
		}
	}

	// Run the application with built-in graceful shutdown
	if err := app.Run(); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			log.Fatalf("Application error: %s (Code: %s, Type: %s)", appErr.Message, appErr.Code, appErr.Type)
		} else {
			log.Fatalf("Application error: %v", err)
		}
	}
}
