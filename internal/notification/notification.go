package notification

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/samaasi/lazy-chat/internal/errors"
)

// NotificationManager handles OS notifications
type NotificationManager struct {
	enabled bool
}

// NewNotificationManager creates a new notification manager
func NewNotificationManager(enabled bool) *NotificationManager {
	return &NotificationManager{
		enabled: enabled,
	}
}

// NotifyMessageReceived sends a notification for received messages
func (nm *NotificationManager) NotifyMessageReceived(sender, message string) error {
	if !nm.enabled {
		return nil
	}

	title := "New Message - Lazy Chat"
	body := fmt.Sprintf("From %s: %s", sender, message)

	// Truncate long messages
	if len(body) > 100 {
		body = body[:97] + "..."
	}

	return nm.sendNotification(title, body)
}

// NotifyFileReceived sends a notification for received files
func (nm *NotificationManager) NotifyFileReceived(sender, filename string) error {
	if !nm.enabled {
		return nil
	}

	title := "File Received - Lazy Chat"
	body := fmt.Sprintf("From %s: %s", sender, filename)

	return nm.sendNotification(title, body)
}

// NotifyPeerConnected sends a notification when a peer connects
func (nm *NotificationManager) NotifyPeerConnected(peerName string) error {
	if !nm.enabled {
		return nil
	}

	title := "Peer Connected - Lazy Chat"
	body := fmt.Sprintf("%s has joined the chat", peerName)

	return nm.sendNotification(title, body)
}

// NotifyPeerDisconnected sends a notification when a peer disconnects
func (nm *NotificationManager) NotifyPeerDisconnected(peerName string) error {
	if !nm.enabled {
		return nil
	}

	title := "Peer Disconnected - Lazy Chat"
	body := fmt.Sprintf("%s has left the chat", peerName)

	return nm.sendNotification(title, body)
}

// sendNotification sends a platform-specific notification
func (nm *NotificationManager) sendNotification(title, body string) error {
	switch runtime.GOOS {
	case "windows":
		return nm.sendWindowsNotification(title, body)
	case "darwin":
		return nm.sendMacNotification(title, body)
	case "linux":
		return nm.sendLinuxNotification(title, body)
	default:
		return errors.New(errors.ErrorTypeApplication, "NOTIF001", "unsupported operating system for notifications")
	}
}

// sendWindowsNotification sends a notification on Windows using PowerShell
func (nm *NotificationManager) sendWindowsNotification(title, body string) error {
	// Escape quotes for PowerShell
	title = strings.ReplaceAll(title, `"`, `""`)
	body = strings.ReplaceAll(body, `"`, `""`)

	// Use PowerShell to show a toast notification
	script := fmt.Sprintf(`
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
		
		$template = @"
		<toast>
			<visual>
				<binding template="ToastGeneric">
					<text>%s</text>
					<text>%s</text>
				</binding>
			</visual>
		</toast>
		"@
		
		$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
		$xml.LoadXml($template)
		$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
		$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Lazy Chat")
		$notifier.Show($toast)
	`, title, body)

	cmd := exec.Command("powershell", "-Command", script)
	err := cmd.Run()
	if err != nil {
		// Fallback to simple message box
		return nm.sendWindowsFallbackNotification(title, body)
	}
	return nil
}

// sendWindowsFallbackNotification sends a simple message box on Windows
func (nm *NotificationManager) sendWindowsFallbackNotification(title, body string) error {
	// Escape quotes for PowerShell
	title = strings.ReplaceAll(title, `"`, `""`)
	body = strings.ReplaceAll(body, `"`, `""`)

	script := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("%s", "%s", "OK", "Information")`, body, title)
	cmd := exec.Command("powershell", "-Command", script)
	return cmd.Run()
}

// sendMacNotification sends a notification on macOS using osascript
func (nm *NotificationManager) sendMacNotification(title, body string) error {
	// Escape quotes for AppleScript
	title = strings.ReplaceAll(title, `"`, `\"`)
	body = strings.ReplaceAll(body, `"`, `\"`)

	script := fmt.Sprintf(`display notification "%s" with title "%s"`, body, title)
	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

// sendLinuxNotification sends a notification on Linux using notify-send
func (nm *NotificationManager) sendLinuxNotification(title, body string) error {
	// Check if notify-send is available
	if _, err := exec.LookPath("notify-send"); err != nil {
		return errors.Wrap(err, errors.ErrorTypeApplication, "NOTIF002", "notify-send not found - please install libnotify")
	}

	cmd := exec.Command("notify-send", title, body)
	return cmd.Run()
}

// SetEnabled enables or disables notifications
func (nm *NotificationManager) SetEnabled(enabled bool) {
	nm.enabled = enabled
}

// IsEnabled returns whether notifications are enabled
func (nm *NotificationManager) IsEnabled() bool {
	return nm.enabled
}
