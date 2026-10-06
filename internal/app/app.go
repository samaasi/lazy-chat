// Package app wires the application together and manages its lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/samaasi/lazy-chat/internal/cli"
	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/discovery"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/filetransfer"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/messaging"
	"github.com/samaasi/lazy-chat/internal/network"
	"github.com/samaasi/lazy-chat/internal/notification"
	"github.com/samaasi/lazy-chat/internal/offline"
	"github.com/samaasi/lazy-chat/internal/peer"
	"github.com/samaasi/lazy-chat/internal/relay"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/ui"
	"github.com/samaasi/lazy-chat/internal/vault"
	"golang.org/x/term"
)

const (
	shutdownTimeout = 15 * time.Second
	cleanupInterval = 30 * time.Second
	minPeerTTL      = 2 * time.Minute
)

// Option customises an App; used by tests to avoid the real terminal.
type Option func(*options)

type options struct {
	in      io.Reader
	out     io.Writer
	version string

	updateNotice func(ctx context.Context) string
	passphrase   string
}

// WithIO sets the CLI's input and output.
func WithIO(in io.Reader, out io.Writer) Option {
	return func(o *options) { o.in, o.out = in, out }
}

// WithPassphrase supplies the encryption passphrase directly (for tests and
// embedding); normally it is typed, or read from a file or the environment.
func WithPassphrase(p string) Option { return func(o *options) { o.passphrase = p } }

// WithVersion sets the version shown in the banner.
func WithVersion(v string) Option { return func(o *options) { o.version = v } }

// WithUpdateNotice supplies a function that reports a newer version, or "" if
// there is none. It runs once in the background after start-up; the app only
// tells the user, it never updates itself.
func WithUpdateNotice(fn func(ctx context.Context) string) Option {
	return func(o *options) { o.updateNotice = fn }
}

// App represents the main application
type App struct {
	config *config.Config
	logger *logger.Logger

	version      string
	updateNotice func(ctx context.Context) string

	id *identity.Identity

	peers     *peer.Manager
	netMgr    *network.Manager
	discovery *discovery.Service
	handler   *messaging.Handler
	files     *filetransfer.Manager
	notifier  *notification.NotificationManager
	relay     *relay.Manager
	db        *storage.SQLiteDB
	groups    *services.GroupService
	history   *services.MessageHistoryService
	console   *ui.Console
	cli       *cli.CLI

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	started bool
	stopped bool
}

// New creates the application and every component it needs. If any step
// fails, everything created so far is released before returning.
func New(cfg *config.Config, opts ...Option) (_ *App, err error) {
	o := options{in: os.Stdin, out: os.Stdout, version: "dev"}
	for _, f := range opts {
		f(&o)
	}
	if err := cfg.Validate(); err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeConfig, "CFG001", "configuration validation failed")
	}

	// Release partially built state on any error path below.
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()

	level, lerr := logger.ParseLevel(cfg.LogLevel)
	if lerr != nil {
		level = logger.InfoLevel
	}
	log, err := logger.New(logger.Options{Level: level, Format: logger.ParseFormat(cfg.LogFormat), File: cfg.LogFile})
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeConfig, "LOG001", "failed to create logger")
	}
	undo = append(undo, func() { _ = log.Close() })

	// Encryption at rest: unlock (or create) the data key first, because the
	// identity key and the database are both protected by it.
	vopts := vault.Options{
		Mode:           vault.Mode(strings.ToLower(cfg.Encryption)),
		Passphrase:     o.passphrase,
		PassphraseFile: cfg.PassphraseFile,
	}
	if f, ok := o.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		vopts.Prompt = terminalPassphrasePrompt(f, os.Stderr)
	}
	dataVault, err := vault.Open(cfg.DataDir, vopts)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeApplication, "ENC001", "failed to unlock encrypted storage").WithContext("data_dir", cfg.DataDir)
	}
	// A nil *Vault inside an interface would not compare equal to nil.
	var sealer identity.Sealer
	var dbOpts []storage.Option
	if dataVault != nil {
		sealer = dataVault
		dbOpts = append(dbOpts, storage.WithVault(dataVault))
	}

	id, err := identity.LoadOrCreateSealed(cfg.DataDir, sealer)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeApplication, "ID001", "failed to load peer identity").WithContext("data_dir", cfg.DataDir)
	}

	if err := os.MkdirAll(cfg.DownloadDir, 0o755); err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeApplication, "APP007", "failed to create download directory").WithContext("dir", cfg.DownloadDir)
	}

	db := storage.NewSQLiteDB(cfg.Database.Path, dbOpts...)
	if err := db.Connect(context.Background()); err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeDatabase, "DB001", "failed to open database").WithContext("path", cfg.Database.Path)
	}
	undo = append(undo, func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeDatabase, "DB002", "failed to run database migrations")
	}

	console := ui.NewConsole(o.out)
	console.SetPrompt("> ")
	peers := peer.NewManager(log)
	notifier := notification.NewNotificationManager(cfg.NotificationsEnabled, log)
	undo = append(undo, notifier.Close)

	netMgr, err := network.NewManager(network.Options{
		Port:       cfg.TCPPort,
		ListenAddr: cfg.ListenAddr,
		Username:   cfg.Username,
		MaxInbound: cfg.MaxConnections,
	}, id, log, peers)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET005", "failed to set up the network manager")
	}

	groups := services.NewGroupService(db, db, id.ID(), cfg.Username)
	history := services.NewMessageHistoryService(db, db, id.ID())

	relayMgr := relay.NewManager(relay.Options{Enabled: cfg.Relay, MaxStorage: cfg.RelayMaxStorage, RequireAnonymous: cfg.SealedSender == "required"}, relay.Deps{
		Logger: log, Self: id, Net: netMgr, Offline: offline.NewService(id, db), Store: db,
	})
	handler := messaging.NewHandler(messaging.Deps{
		Logger: log, SelfID: id.ID(), SelfName: cfg.Username, Net: netMgr, Store: db,
		Groups: groups, Peers: peers, Notifier: notifier, Out: console, Relay: relayMgr,
	})
	relayMgr.SetHandlers(handler.AcceptRelayed, handler.ApplyReceipt)
	relayMgr.Register()
	undo = append(undo, relayMgr.Close)
	files := filetransfer.NewManager(filetransfer.Options{
		DownloadDir: cfg.DownloadDir,
		MaxFileSize: cfg.MaxFileSize,
		AutoAccept:  cfg.AutoAcceptFiles,
	}, filetransfer.Deps{
		Logger: log, Net: netMgr, Out: console, Display: console, Notifier: notifier, Names: handler.DisplayName,
	})
	handler.Register()
	files.Register()
	undo = append(undo, handler.Close, files.Close)

	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		config: cfg, logger: log, id: id, peers: peers, netMgr: netMgr, handler: handler, files: files, relay: relayMgr,
		notifier: notifier, db: db, groups: groups, history: history, console: console,
		discovery: discovery.NewService(discovery.OptionsFromConfig(cfg), id, log, peers),
		ctx:       ctx, cancel: cancel, version: o.version, updateNotice: o.updateNotice,
	}
	a.cli = cli.New(cli.Deps{
		In: o.in, Console: console, SelfID: id.ID(), SelfName: cfg.Username,
		Peers: peers, Net: netMgr, Handler: handler, Groups: groups, History: history, Files: files, Verify: db, Relay: relayMgr,
		StartedAt: time.Now(), Version: o.version,
	})
	return a, nil
}

// ID returns the local peer ID.
func (a *App) ID() string { return a.id.ID() }

// Port returns the TCP port peers connect to.
func (a *App) Port() int { return a.netMgr.Port() }

// Peers returns the peer registry.
func (a *App) Peers() interfaces.PeerManager { return a.peers }

// Network returns the network manager.
func (a *App) Network() interfaces.NetworkManager { return a.netMgr }

// Handler returns the chat handler.
func (a *App) Handler() *messaging.Handler { return a.handler }

// Files returns the file transfer manager.
func (a *App) Files() *filetransfer.Manager { return a.files }

// Groups returns the group service.
func (a *App) Groups() *services.GroupService { return a.groups }

// CLI returns the command-line interface.
func (a *App) CLI() *cli.CLI { return a.cli }

// Start starts all application services.
func (a *App) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return apperrors.ErrAppAlreadyRunning
	}

	a.logger.Info("Starting Lazy Chat", "username", a.config.Username, "peer_id", a.id.ID(), "tcp_port", a.config.TCPPort)
	if err := a.netMgr.Start(a.ctx); err != nil {
		return apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET004", "failed to start network manager")
	}
	if err := a.discovery.Start(a.ctx); err != nil {
		_ = a.netMgr.Stop()
		return apperrors.Wrap(err, apperrors.ErrorTypeDiscovery, "DISC002", "failed to start discovery service")
	}
	a.started = true

	a.wg.Add(1)
	go a.cleanupRoutine()
	if a.updateNotice != nil {
		a.wg.Add(1)
		go a.announceUpdate()
	}
	return nil
}

// announceUpdate tells the user once if a newer release exists.
func (a *App) announceUpdate() {
	defer a.wg.Done()
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	if v := a.updateNotice(ctx); v != "" {
		a.console.Printf("* A new version is available: %s (you have %s). Run \"lazy-chat update\" to install it.", v, a.version)
	}
}

// Stop shuts everything down in dependency order and releases all resources.
// It is safe to call more than once.
func (a *App) Stop() error {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return nil
	}
	a.stopped = true
	started := a.started
	a.mu.Unlock()

	a.logger.Info("Stopping Lazy Chat")
	a.cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if started {
			_ = a.discovery.Stop()
		}
		// Stop producing work before closing the connections it uses.
		a.handler.Close()
		a.relay.Close()
		a.files.Close()
		if started {
			_ = a.netMgr.Stop()
		}
		a.wg.Wait()
		a.notifier.Close()
		if err := a.db.Close(); err != nil {
			a.logger.Error("Error closing database", "error", err)
		}
	}()

	var err error
	select {
	case <-done:
		a.logger.Info("Application stopped")
	case <-time.After(shutdownTimeout):
		a.logger.Warn("Graceful shutdown timed out")
		err = apperrors.ErrAppShutdownTimeout
	}
	_ = a.logger.Close()
	return err
}

// Run starts the application, runs the CLI and shuts down on /quit, input
// end of file, or SIGINT/SIGTERM.
func (a *App) Run() error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	if err := a.Start(); err != nil {
		_ = a.Stop()
		return err
	}

	cliDone := make(chan error, 1)
	go func() { cliDone <- a.cli.Start(a.ctx) }()

	var runErr error
	select {
	case sig := <-sigs:
		a.logger.Info("Received shutdown signal", "signal", sig.String())
		fmt.Fprintln(os.Stdout)
	case err := <-cliDone:
		// /quit or end of input: this is what used to hang the program.
		if err != nil && !errors.Is(err, context.Canceled) {
			runErr = err
		}
	case <-a.ctx.Done():
	}

	if err := a.Stop(); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

// cleanupRoutine periodically expires stale peers and invitations.
func (a *App) cleanupRoutine() {
	defer a.wg.Done()

	// Announcements arrive once per interval; allow several to be missed.
	peerTTL := max(minPeerTTL, 3*time.Duration(a.config.BroadcastInterval)*time.Second)

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.peers.CleanupStalePeers(peerTTL)
			a.handler.RetryAll(a.ctx)
			mctx, mcancel := context.WithTimeout(a.ctx, 10*time.Second)
			if err := a.relay.Maintain(mctx); err != nil && a.ctx.Err() == nil {
				a.logger.Debug("Relay maintenance failed", "error", err)
			}
			mcancel()
			ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
			if _, err := a.groups.CleanupExpiredInvites(ctx); err != nil && a.ctx.Err() == nil {
				a.logger.Debug("Invite cleanup failed", "error", err)
			}
			cancel()
		}
	}
}
