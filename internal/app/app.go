package app

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lazy-chat/internal/cli"
	"github.com/lazy-chat/internal/config"
	"github.com/lazy-chat/internal/discovery"
	"github.com/lazy-chat/internal/errors"
	"github.com/lazy-chat/internal/filetransfer"
	"github.com/lazy-chat/internal/interfaces"
	"github.com/lazy-chat/internal/logger"
	"github.com/lazy-chat/internal/messaging"
	"github.com/lazy-chat/internal/network"
	"github.com/lazy-chat/internal/notification"
	"github.com/lazy-chat/internal/peer"
	"github.com/lazy-chat/internal/utils"
)

// App represents the main application
type App struct {
	config          *config.Config
	logger          interfaces.Logger
	idGenerator     interfaces.IDGenerator
	peerManager     interfaces.PeerManager
	msgHandler      interfaces.MessageHandler
	netManager      interfaces.NetworkManager
	discovery       interfaces.PeerDiscovery
	transferManager *filetransfer.TransferManager
	notificationMgr *notification.NotificationManager
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// New creates a new application instance with dependency injection
func New(cfg *config.Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeConfig, "CFG001", "configuration validation failed")
	}

	// Create logger with configured log level and format
	logLevel, err := logger.ParseLevel(cfg.LogLevel)
	if err != nil {
		logLevel = logger.InfoLevel // Fallback to info level
	}

	var log interfaces.Logger
	if cfg.LogFile != "" {
		// Create logger with file output
		fileLogger, err := logger.NewWithFile(logLevel, cfg.LogFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeConfig, "LOG001", "failed to create file logger")
		}
		log = fileLogger
	} else {
		// Create logger with stdout output
		log = logger.New(logLevel)
	}

	// Set log format
	if loggerImpl, ok := log.(*logger.Logger); ok {
		if strings.ToLower(cfg.LogFormat) == "json" {
			loggerImpl.SetFormat(logger.JSONFormat)
		} else {
			loggerImpl.SetFormat(logger.TextFormat)
		}
	}

	// Create ID generator
	idGen := utils.NewIDGenerator()

	// Generate peer ID
	peerID := idGen.GeneratePoeticID()

	// Create peer manager
	peerMgr := peer.NewManager(log)

	// Create message handler
	msgHandler := messaging.NewHandler(log)

	// Create file transfer manager with configured download directory
	downloadDir := cfg.DownloadDir
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		log.Error("Failed to create downloads directory", "error", err, "dir", downloadDir)
	}
	transferMgr := filetransfer.NewTransferManager(downloadDir, log)

	// Create notification manager
	notificationMgr := notification.NewNotificationManager(true) // Enable notifications by default

	// Create network manager
	netMgr := network.NewManager(cfg.TCPPort, cfg.Username, log, peerMgr, msgHandler)

	// Create discovery service
	discSvc := discovery.NewService(cfg, log, peerMgr, peerID, cfg.Username, cfg.TCPPort)

	ctx, cancel := context.WithCancel(context.Background())

	return &App{
		config:          cfg,
		logger:          log,
		idGenerator:     idGen,
		peerManager:     peerMgr,
		msgHandler:      msgHandler,
		netManager:      netMgr,
		discovery:       discSvc,
		transferManager: transferMgr,
		notificationMgr: notificationMgr,
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

// Start starts all application services
func (a *App) Start() error {
	a.logger.Info("Starting P2P Chat Application", "username", a.config.Username, "tcp_port", a.config.TCPPort, "discovery_port", a.config.DiscoveryPort)

	// Start network manager
	if err := a.netManager.Start(a.ctx); err != nil {
		return errors.Wrap(err, errors.ErrorTypeNetwork, "NET004", "failed to start network manager")
	}

	// Start discovery service
	if err := a.discovery.Start(a.ctx); err != nil {
		return errors.Wrap(err, errors.ErrorTypeDiscovery, "DISC002", "failed to start discovery service")
	}

	// Start cleanup routine for stale peers
	a.wg.Add(1)
	go a.cleanupRoutine()

	a.logger.Info("All services started successfully")
	return nil
}

// Stop gracefully stops all application services
func (a *App) Stop() error {
	a.logger.Info("Stopping P2P Chat Application")

	// Cancel context to signal all services to stop
	a.cancel()

	// Stop discovery service
	if err := a.discovery.Stop(); err != nil {
		a.logger.Error("Error stopping discovery service", "error", err)
	}

	// Stop network manager
	if err := a.netManager.Stop(); err != nil {
		a.logger.Error("Error stopping network manager", "error", err)
	}

	// Wait for all goroutines to finish
	a.wg.Wait()

	a.logger.Info("Application stopped successfully")
	return nil
}

// Run starts the application and handles graceful shutdown
func (a *App) Run() error {
	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the application
	if err := a.Start(); err != nil {
		return err
	}

	// Create CLI interface
	cliInterface := cli.New(a.peerManager, a.netManager, a.logger, a.config.Username)

	// Start CLI in a separate goroutine
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		cliInterface.Start(a.ctx)
	}()

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		a.logger.Info("Received shutdown signal", "signal", sig)
	case <-a.ctx.Done():
		a.logger.Info("Application context cancelled")
	}

	// Graceful shutdown
	return a.Stop()
}

// GetPeerManager returns the peer manager
func (a *App) GetPeerManager() interfaces.PeerManager {
	return a.peerManager
}

// GetNetworkManager returns the network manager
func (a *App) GetNetworkManager() interfaces.NetworkManager {
	return a.netManager
}

// GetLogger returns the logger
func (a *App) GetLogger() interfaces.Logger {
	return a.logger
}

// GetConfig returns the configuration
func (a *App) GetConfig() *config.Config {
	return a.config
}

// cleanupRoutine periodically cleans up stale peers
func (a *App) cleanupRoutine() {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second) // Cleanup every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.peerManager.CleanupStalePeers(2 * time.Minute) // Remove peers not seen for 2 minutes
		}
	}
}