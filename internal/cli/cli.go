package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lazy-chat/internal/filetransfer"
	"github.com/lazy-chat/internal/interfaces"
)

// CLI handles command line interface interactions
type CLI struct {
	peerManager     interfaces.PeerManager
	netManager      interfaces.NetworkManager
	logger          interfaces.Logger
	scanner         *bufio.Scanner
	username        string
	transferManager *filetransfer.TransferManager
}

// New creates a new CLI instance
func New(peerManager interfaces.PeerManager, netManager interfaces.NetworkManager, logger interfaces.Logger, username string) *CLI {
	// Create downloads directory
	downloadDir := "downloads"
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		logger.Error("Failed to create downloads directory", "error", err)
	}
	
	return &CLI{
		peerManager:     peerManager,
		netManager:      netManager,
		logger:          logger,
		scanner:         bufio.NewScanner(os.Stdin),
		username:        username,
		transferManager: filetransfer.NewTransferManager(downloadDir, logger),
	}
}

// Start begins the CLI interaction loop
func (c *CLI) Start(ctx context.Context) error {
	c.printWelcome()
	c.printHelp()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fmt.Print("> ")
		if !c.scanner.Scan() {
			break
		}

		input := strings.TrimSpace(c.scanner.Text())
		if input == "" {
			continue
		}

		if err := c.handleCommand(ctx, input); err != nil {
			if err.Error() == "exit" {
				return nil
			}
			fmt.Printf("Error: %v\n", err)
		}
	}

	if err := c.scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// handleCommand processes user commands
func (c *CLI) handleCommand(ctx context.Context, input string) error {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	command := strings.ToLower(parts[0])

	switch command {
	case "/help", "/h":
		c.printHelp()

	case "/list", "/l":
		c.listPeers()

	case "/connect", "/c":
		if len(parts) < 2 {
			fmt.Println("Usage: /connect <peer_id>")
			return nil
		}
		return c.connectToPeer(ctx, parts[1])

	case "/send", "/s":
		if len(parts) < 3 {
			fmt.Println("Usage: /send <peer_id> <message>")
			return nil
		}
		peerID := parts[1]
		message := strings.Join(parts[2:], " ")
		return c.sendMessage(peerID, message)

	case "/connections", "/conn":
		c.listConnections()

	case "/status", "/st":
		c.showStatus()

	case "/sendfile", "/sf":
		if len(parts) < 3 {
			fmt.Println("Usage: /sendfile <peer_id> <file_path>")
			return nil
		}
		return c.sendFile(ctx, parts[1], parts[2])

	case "/transfers", "/tf":
		c.showTransfers()

	case "/exit", "/quit", "/q":
		fmt.Println("Goodbye!")
		return fmt.Errorf("exit")

	default:
		fmt.Printf("Unknown command: %s. Type /help for available commands.\n", command)
	}

	return nil
}

// printWelcome displays the welcome message
func (c *CLI) printWelcome() {
	fmt.Println("========================================")
	fmt.Println("    Welcome to P2P Chat Application    ")
	fmt.Printf("         Username: %s\n", c.username)
	fmt.Println("========================================")
	fmt.Println()
}

// printHelp displays available commands
func (c *CLI) printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  /help, /h              - Show this help message")
	fmt.Println("  /list, /l              - List discovered peers")
	fmt.Println("  /connect, /c <id>      - Connect to a peer by ID")
	fmt.Println("  /send, /s <id> <msg>   - Send message to connected peer")
	fmt.Println("  /sendfile, /sf <id> <path> - Send file to connected peer")
	fmt.Println("  /transfers, /tf        - Show active file transfers")
	fmt.Println("  /connections, /conn    - List active connections")
	fmt.Println("  /status, /st           - Show application status")
	fmt.Println("  /exit, /quit, /q       - Exit the application")
	fmt.Println()
}

// listPeers displays all discovered peers
func (c *CLI) listPeers() {
	peers := c.peerManager.GetAllPeers()

	if len(peers) == 0 {
		fmt.Println("No peers discovered yet.")
		return
	}

	fmt.Printf("Discovered peers (%d):\n", len(peers))
	fmt.Println("ID\t\tUsername\t\tAddress\t\t\tLast Seen")
	fmt.Println("--\t\t--------\t\t-------\t\t\t---------")

	for _, peer := range peers {
		lastSeen := time.Since(peer.LastSeen).Truncate(time.Second)
		connected := ""
		if c.netManager.IsConnected(peer.ID) {
			connected = " [CONNECTED]"
		}
		fmt.Printf("%s\t%s\t\t%s\t\t%s ago%s\n",
			peer.ID, peer.Username, peer.NetworkAddress(), lastSeen, connected)
	}
	fmt.Println()
}

// connectToPeer establishes a connection to a peer
func (c *CLI) connectToPeer(ctx context.Context, peerID string) error {
	if c.netManager.IsConnected(peerID) {
		fmt.Printf("Already connected to peer %s\n", peerID)
		return nil
	}

	peer, exists := c.peerManager.GetPeer(peerID)
	if !exists {
		fmt.Printf("Peer %s not found. Use /list to see available peers.\n", peerID)
		return nil
	}

	fmt.Printf("Connecting to %s (%s)...\n", peer.Username, peer.NetworkAddress())

	if err := c.netManager.ConnectToPeer(ctx, peerID); err != nil {
		return fmt.Errorf("failed to connect to peer %s: %w", peerID, err)
	}

	fmt.Printf("Successfully connected to %s!\n", peer.Username)
	return nil
}

// sendMessage sends a message to a connected peer
func (c *CLI) sendMessage(peerID, message string) error {
	if !c.netManager.IsConnected(peerID) {
		fmt.Printf("Not connected to peer %s. Use /connect %s first.\n", peerID, peerID)
		return nil
	}

	peer, exists := c.peerManager.GetPeer(peerID)
	if !exists {
		fmt.Printf("Peer %s not found.\n", peerID)
		return nil
	}

	if err := c.netManager.SendMessage(peerID, message); err != nil {
		return fmt.Errorf("failed to send message to %s: %w", peer.Username, err)
	}

	fmt.Printf("Message sent to %s\n", peer.Username)
	return nil
}

// listConnections displays all active connections
func (c *CLI) listConnections() {
	connections := c.netManager.GetConnections()

	if len(connections) == 0 {
		fmt.Println("No active connections.")
		return
	}

	fmt.Printf("Active connections (%d):\n", len(connections))
	fmt.Println("Peer ID\t\tUsername\t\tAddress")
	fmt.Println("-------\t\t--------\t\t-------")

	for peerID := range connections {
		if peer, exists := c.peerManager.GetPeer(peerID); exists {
			fmt.Printf("%s\t%s\t\t%s\n", peerID, peer.Username, peer.NetworkAddress())
		} else {
			fmt.Printf("%s\t<unknown>\t\t<unknown>\n", peerID)
		}
	}
	fmt.Println()
}

// showStatus displays application status
func (c *CLI) showStatus() {
	peers := c.peerManager.GetAllPeers()
	connections := c.netManager.GetConnections()

	fmt.Println("Application Status:")
	fmt.Printf("  Username: %s\n", c.username)
	fmt.Printf("  Discovered peers: %d\n", len(peers))
	fmt.Printf("  Active connections: %d\n", len(connections))
	fmt.Printf("  Uptime: %s\n", "N/A") // Could track this if needed
	fmt.Println()
}

// sendFile sends a file to a connected peer
func (c *CLI) sendFile(ctx context.Context, peerID, filePath string) error {
	if !c.netManager.IsConnected(peerID) {
		fmt.Printf("Not connected to peer %s. Use /connect %s first.\n", peerID, peerID)
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("File not found: %s\n", filePath)
		return nil
	}

	peer, exists := c.peerManager.GetPeer(peerID)
	if !exists {
		fmt.Printf("Peer %s not found.\n", peerID)
		return nil
	}

	fmt.Printf("Sending file %s to %s...\n", filepath.Base(filePath), peer.Username)

	if err := c.transferManager.SendFile(ctx, peerID, filePath); err != nil {
		return fmt.Errorf("failed to send file to %s: %w", peer.Username, err)
	}

	fmt.Printf("File transfer initiated to %s\n", peer.Username)
	return nil
}

// showTransfers displays active file transfers
func (c *CLI) showTransfers() {
	transfers := c.transferManager.GetActiveTransfers()

	if len(transfers) == 0 {
		fmt.Println("No active file transfers.")
		return
	}

	fmt.Printf("Active file transfers (%d):\n", len(transfers))
	fmt.Println("Transfer ID\t\tFile\t\t\tPeer\t\tStatus\t\tProgress")
	fmt.Println("-----------\t\t----\t\t\t----\t\t------\t\t--------")

	for _, transfer := range transfers {
		peer, exists := c.peerManager.GetPeer(transfer.PeerID)
		peerName := transfer.PeerID
		if exists {
			peerName = peer.Username
		}

		progress := "0%"
		if transfer.FileSize > 0 {
			pct := float64(transfer.BytesTransferred) / float64(transfer.FileSize) * 100
			progress = fmt.Sprintf("%.1f%%", pct)
		}

		fmt.Printf("%s\t%s\t\t%s\t\t%s\t\t%s\n",
			transfer.TransferID[:8], // Show first 8 chars of transfer ID
			filepath.Base(transfer.FileName),
			peerName,
			transfer.Status,
			progress)
	}
	fmt.Println()
}

// parseNumber safely parses a string to integer
func (c *CLI) parseNumber(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", s)
	}
	return n, nil
}