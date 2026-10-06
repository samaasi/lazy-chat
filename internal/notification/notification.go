// Package notification shows desktop notifications.
//
// Notification text comes from remote peers and must be treated as hostile.
// It is never spliced into a script: the scripts below are constant, and the
// title/body travel out-of-band (environment variables for PowerShell, argv
// for osascript and notify-send), so no quoting or escaping bug can turn
// message text into code.
package notification

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	maxTitleRunes = 64
	maxBodyRunes  = 200
	queueSize     = 16
	commandTimout = 10 * time.Second

	envTitle = "LAZYCHAT_TITLE"
	envBody  = "LAZYCHAT_BODY"
)

// windowsScript reads title and body from the environment and XML-escapes
// them before building the toast. It is a constant: nothing is interpolated.
const windowsScript = `$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$title = [System.Security.SecurityElement]::Escape($env:LAZYCHAT_TITLE)
$body = [System.Security.SecurityElement]::Escape($env:LAZYCHAT_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$title</text><text>$body</text></binding></visual></toast>")
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
`

// command describes a process to run, with untrusted data kept in Env/Args.
type command struct {
	Name string
	Args []string
	Env  []string // extra environment entries, KEY=value
}

type runner func(ctx context.Context, c command) error

// NotificationManager handles OS notifications. Delivery happens on a
// background worker so that a slow or hung notification helper can never
// stall the network read loop that triggered it.
type NotificationManager struct {
	enabled atomic.Bool
	logger  interfaces.Logger
	run     runner
	goos    string

	queue chan command
	wg    sync.WaitGroup
	once  sync.Once
	mu    sync.RWMutex // guards closed vs. sends on queue
	shut  bool
}

// NewNotificationManager creates a notification manager. logger may be nil.
func NewNotificationManager(enabled bool, logger interfaces.Logger) *NotificationManager {
	nm := &NotificationManager{
		logger: logger,
		run:    execRunner,
		goos:   runtime.GOOS,
		queue:  make(chan command, queueSize),
	}
	nm.enabled.Store(enabled)
	nm.wg.Add(1)
	go nm.worker()
	return nm
}

// NotifyMessageReceived sends a notification for received messages
func (nm *NotificationManager) NotifyMessageReceived(sender, message string) error {
	return nm.notify("New message", fmt.Sprintf("%s: %s", sender, message))
}

// NotifyFileReceived sends a notification for received files
func (nm *NotificationManager) NotifyFileReceived(sender, filename string) error {
	return nm.notify("File received", fmt.Sprintf("%s: %s", sender, filename))
}

// NotifyPeerConnected sends a notification when a peer connects
func (nm *NotificationManager) NotifyPeerConnected(peerName string) error {
	return nm.notify("Peer connected", peerName+" is online")
}

// NotifyPeerDisconnected sends a notification when a peer disconnects
func (nm *NotificationManager) NotifyPeerDisconnected(peerName string) error {
	return nm.notify("Peer disconnected", peerName+" went offline")
}

func (nm *NotificationManager) notify(title, body string) error {
	if !nm.enabled.Load() {
		return nil
	}
	cmd, err := buildCommand(nm.goos,
		utils.SanitizeText("Lazy Chat - "+title, maxTitleRunes),
		utils.SanitizeText(body, maxBodyRunes))
	if err != nil {
		return err
	}

	nm.mu.RLock()
	defer nm.mu.RUnlock()
	if nm.shut {
		return nil
	}
	select {
	case nm.queue <- cmd:
	default:
		// A flood of messages must not pile up helper processes; dropping
		// a toast is harmless because the message is also printed.
	}
	return nil
}

func (nm *NotificationManager) worker() {
	defer nm.wg.Done()
	for cmd := range nm.queue {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimout)
		if err := nm.run(ctx, cmd); err != nil && nm.logger != nil {
			nm.logger.Debug("Notification failed", "error", err)
		}
		cancel()
	}
}

// Close stops accepting notifications and waits for queued ones to finish.
func (nm *NotificationManager) Close() {
	nm.once.Do(func() {
		nm.mu.Lock()
		nm.shut = true
		close(nm.queue)
		nm.mu.Unlock()
		nm.wg.Wait()
	})
}

// SetEnabled enables or disables notifications
func (nm *NotificationManager) SetEnabled(enabled bool) { nm.enabled.Store(enabled) }

// IsEnabled returns whether notifications are enabled
func (nm *NotificationManager) IsEnabled() bool { return nm.enabled.Load() }

// buildCommand returns the platform command for a notification.
func buildCommand(goos, title, body string) (command, error) {
	switch goos {
	case "windows":
		return command{
			Name: "powershell.exe",
			Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(windowsScript)},
			Env:  []string{envTitle + "=" + title, envBody + "=" + body},
		}, nil
	case "darwin":
		return command{
			Name: "osascript",
			Args: []string{
				"-e", "on run argv",
				"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
				"-e", "end run",
				"--", body, title,
			},
		}, nil
	case "linux":
		// notify-send renders a Pango-like markup subset; neutralise it.
		return command{
			Name: "notify-send",
			Args: []string{"--app-name=lazy-chat", "--", escapeMarkup(title), escapeMarkup(body)},
		}, nil
	default:
		return command{}, apperrors.New(apperrors.ErrorTypeApplication, "NOTIF001", "unsupported operating system for notifications")
	}
}

// encodePowerShell encodes a script for -EncodedCommand (UTF-16LE, base64).
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func execRunner(ctx context.Context, c command) error {
	if _, err := exec.LookPath(c.Name); err != nil {
		if c.Name == "notify-send" {
			return apperrors.Wrap(err, apperrors.ErrorTypeApplication, "NOTIF002", "notify-send not found - please install libnotify")
		}
		return err
	}
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("%s: %w: %s", c.Name, err, strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}
