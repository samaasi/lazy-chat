package app

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/samaasi/lazy-chat/internal/cli"
	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/database"
	"github.com/samaasi/lazy-chat/internal/discovery"
	"github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/filetransfer"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/messaging"
	"github.com/samaasi/lazy-chat/internal/network"
	"github.com/samaasi/lazy-chat/internal/notification"
	"github.com/samaasi/lazy-chat/internal/peer"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/utils"
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
	dbManager       *database.Manager
	messageStorage  storage.MessageStorage
	groupService    *services.GroupService
	messageHistory  *services.MessageHistoryService
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

	// Create notification manager
	notificationMgr := notification.NewNotificationManager(cfg.NotificationsEnabled)

	// Create database manager and initialize
	dbConfig := &config.DatabaseConfig{}
	dbManager := database.NewManager(dbConfig)
	if err := dbManager.Initialize(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, "DB001", "failed to initialize database")
	}

	// Create storage instances
	sqliteDB, err := dbManager.CreateStorageInstances()
	if err != nil {
		log.Fatal("Failed to create storage instances", "error", err)
	}

	// Connect to database
	if err := sqliteDB.Connect(context.Background()); err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}

	// Run migrations
	if err := sqliteDB.Migrate(context.Background()); err != nil {
		log.Fatal("Failed to run database migrations", "error", err)
	}

	// Create services
	groupService := services.NewGroupService(sqliteDB, sqliteDB, peerID)
	messageHistory := services.NewMessageHistoryService(sqliteDB, sqliteDB)

	// Create file transfer manager with configured download directory
	downloadDir := cfg.DownloadDir
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		log.Error("Failed to create downloads directory", "error", err, "dir", downloadDir)
	}
	transferMgr := filetransfer.NewTransferManager(downloadDir, log)

	// Create network manager first (without message handler)
	netMgr := network.NewManager(cfg.TCPPort, cfg.Username, log, peerMgr, nil, notificationMgr, idGen)

	// Create message handler with storage and network manager
	msgHandler := messaging.NewHandler(log, notificationMgr, sqliteDB, groupService, idGen, netMgr)

	// Set the message handler in network manager
	netMgr.SetMessageHandler(msgHandler)

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
		dbManager:       dbManager,
		messageStorage:  messageStorage,
		groupService:    groupService,
		messageHistory:  messageHistory,
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

	// Create a timeout context for graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Channel to signal when shutdown is complete
	shutdownDone := make(chan struct{})

	go func() {
		defer close(shutdownDone)

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
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-shutdownDone:
		a.logger.Info("Application stopped successfully")
		return nil
	case <-shutdownCtx.Done():
		a.logger.Warn("Graceful shutdown timed out, forcing exit")
		return errors.New(errors.ErrorTypeApplication, "APP006", "shutdown timeout exceeded")
	}
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
	cliInterface := cli.New(a.peerManager, a.netManager, a.logger, a.config.Username, a.groupService, a.messageHistory, a.msgHandler)

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
