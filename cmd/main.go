package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	LastSeen time.Time `json:"last_seen"`
}

type DiscoveryMessage struct {
	Type     string `json:"type"`
	PeerID   string `json:"peer_id"`
	Username string `json:"username"`
	Port     int    `json:"port"`
}

type ChatMessage struct {
	From      string    `json:"from"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type P2PChat struct {
	ID           string
	Username     string
	Port         int
	Peers        map[string]*Peer
	Connections  map[string]net.Conn
	Mutex        sync.RWMutex
	DiscoveryConn *net.UDPConn
	TCPListener  net.Listener
}

const (
	DISCOVERY_PORT_START = 9999
	BROADCAST_ADDR = "255.255.255.255"
)

func generatePoeticID() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	adjectives := []string{
		"crimson", "azure", "golden", "silver", "emerald", "violet", "amber", "coral",
		"gentle", "swift", "quiet", "bright", "mystic", "serene", "bold", "wise",
		"dancing", "whispering", "glowing", "shimmering", "flowing", "soaring", "dreaming", "wandering",
	}
	
	nouns := []string{
		"moon", "star", "river", "ocean", "mountain", "forest", "meadow", "valley",
		"phoenix", "dragon", "wolf", "eagle", "dove", "butterfly", "tiger", "falcon",
		"breeze", "storm", "flame", "crystal", "shadow", "light", "echo", "dream",
	}
	
	adjective := adjectives[r.Intn(len(adjectives))]
	noun := nouns[r.Intn(len(nouns))]
	
	return adjective + "-" + noun
}

func NewP2PChat(username string, port int) *P2PChat {
	return &P2PChat{
		ID:          generatePoeticID(),
		Username:    username,
		Port:        port,
		Peers:       make(map[string]*Peer),
		Connections: make(map[string]net.Conn),
	}
}

func (p *P2PChat) StartDiscovery() error {
	// Try to find an available discovery port
	var conn *net.UDPConn
	var err error
	var discoveryPort int
	
	for port := DISCOVERY_PORT_START; port < DISCOVERY_PORT_START+10; port++ {
		addr, addrErr := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if addrErr != nil {
			continue
		}
		
		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			discoveryPort = port
			break
		}
	}
	
	if conn == nil {
		return fmt.Errorf("failed to bind to any discovery port (tried %d-%d)", DISCOVERY_PORT_START, DISCOVERY_PORT_START+9)
	}

	p.DiscoveryConn = conn

	// Start listening for discovery messages
	go p.listenForDiscovery()

	// Start broadcasting our presence
	go p.broadcastPresence(discoveryPort)
	
	fmt.Printf("Discovery started on UDP port %d\n", discoveryPort)

	return nil
}

func (p *P2PChat) listenForDiscovery() {
	buffer := make([]byte, 1024)
	for {
		n, addr, err := p.DiscoveryConn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		var msg DiscoveryMessage
		if err := json.Unmarshal(buffer[:n], &msg); err != nil {
			continue
		}

		// Ignore our own messages
		if msg.PeerID == p.ID {
			continue
		}

		p.Mutex.Lock()
		peer := &Peer{
			ID:       msg.PeerID,
			Username: msg.Username,
			Address:  addr.IP.String(),
			Port:     msg.Port,
			LastSeen: time.Now(),
		}
		p.Peers[msg.PeerID] = peer
		p.Mutex.Unlock()
	}
}

func (p *P2PChat) broadcastPresence(discoveryPort int) {
	msg := DiscoveryMessage{
		Type:     "announce",
		PeerID:   p.ID,
		Username: p.Username,
		Port:     p.Port,
	}

	data, _ := json.Marshal(msg)

	for {
		// Broadcast to all ports in the discovery range
		for port := DISCOVERY_PORT_START; port < DISCOVERY_PORT_START+10; port++ {
			broadcastAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", BROADCAST_ADDR, port))
			if err != nil {
				continue
			}
			
			conn, err := net.DialUDP("udp", nil, broadcastAddr)
			if err != nil {
				continue
			}
			
			conn.Write(data)
			conn.Close()
		}
		time.Sleep(5 * time.Second)
	}
}

func (p *P2PChat) StartTCPServer() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
	if err != nil {
		return err
	}

	p.TCPListener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go p.handleIncomingConnection(conn)
		}
	}()

	return nil
}

func (p *P2PChat) handleIncomingConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var msg ChatMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}

		fmt.Printf("\n[%s] %s: %s\n> ", msg.Timestamp.Format("15:04:05"), msg.From, msg.Message)
	}
}

func (p *P2PChat) ConnectToPeer(peerID string) error {
	p.Mutex.RLock()
	peer, exists := p.Peers[peerID]
	p.Mutex.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.Address, peer.Port), 10*time.Second)
	if err != nil {
		return err
	}

	p.Mutex.Lock()
	p.Connections[peerID] = conn
	p.Mutex.Unlock()

	return nil
}

func (p *P2PChat) SendMessage(peerID, message string) error {
	p.Mutex.RLock()
	conn, exists := p.Connections[peerID]
	p.Mutex.RUnlock()

	if !exists {
		return fmt.Errorf("not connected to peer")
	}

	chatMsg := ChatMessage{
		From:      p.Username,
		Message:   message,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(chatMsg)
	if err != nil {
		return err
	}

	_, err = conn.Write(append(data, '\n'))
	return err
}

func (p *P2PChat) ListPeers() {
	p.Mutex.RLock()
	defer p.Mutex.RUnlock()

	if len(p.Peers) == 0 {
		fmt.Println("No peers discovered yet.")
		return
	}

	fmt.Println("\nDiscovered Peers:")
	fmt.Println("ID\t\tUsername\tAddress\t\tLast Seen")
	fmt.Println(strings.Repeat("-", 60))

	for _, peer := range p.Peers {
		fmt.Printf("%s\t\t%s\t\t%s:%d\t%s\n",
			peer.ID,
			peer.Username,
			peer.Address,
			peer.Port,
			peer.LastSeen.Format("15:04:05"))
	}
}

func (p *P2PChat) Cleanup() {
	if p.DiscoveryConn != nil {
		p.DiscoveryConn.Close()
	}
	if p.TCPListener != nil {
		p.TCPListener.Close()
	}
	p.Mutex.Lock()
	for _, conn := range p.Connections {
		conn.Close()
	}
	p.Mutex.Unlock()
}

func main() {
	fmt.Println("P2P CLI Chat Application")
	fmt.Println("========================")

	// Get username
	fmt.Print("Enter your username: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		username = "Anonymous"
	}

	// Get port
	fmt.Print("Enter TCP port (default 8080): ")
	scanner.Scan()
	portStr := strings.TrimSpace(scanner.Text())
	port := 8080
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Create P2P chat instance
	chat := NewP2PChat(username, port)

	// Start services
	if err := chat.StartDiscovery(); err != nil {
		fmt.Printf("Failed to start discovery: %v\n", err)
		return
	}

	if err := chat.StartTCPServer(); err != nil {
		fmt.Printf("Failed to start TCP server: %v\n", err)
		return
	}

	fmt.Printf("\nChat started! Your ID: %s\n", chat.ID)
	fmt.Printf("Listening on port %d for incoming connections\n", port)
	fmt.Printf("Broadcasting presence on UDP port range %d-%d\n\n", DISCOVERY_PORT_START, DISCOVERY_PORT_START+9)

	fmt.Println("Commands:")
	fmt.Println("/list - List discovered peers")
	fmt.Println("/connect <peer_id> - Connect to a peer")
	fmt.Println("/send <peer_id> <message> - Send message to connected peer")
	fmt.Println("/exit - Exit the application")
	fmt.Println()

	// Cleanup on exit
	defer chat.Cleanup()

	// Main command loop
	for {
		fmt.Print("> ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		switch command {
		case "/list":
			chat.ListPeers()

		case "/connect":
			if len(parts) < 2 {
				fmt.Println("Usage: /connect <peer_id>")
				continue
			}
			peerID := parts[1]
			if err := chat.ConnectToPeer(peerID); err != nil {
				fmt.Printf("Failed to connect to peer: %v\n", err)
			} else {
				fmt.Printf("Connected to peer %s\n", peerID)
			}

		case "/send":
			if len(parts) < 3 {
				fmt.Println("Usage: /send <peer_id> <message>")
				continue
			}
			peerID := parts[1]
			message := strings.Join(parts[2:], " ")
			if err := chat.SendMessage(peerID, message); err != nil {
				fmt.Printf("Failed to send message: %v\n", err)
			} else {
				fmt.Printf("Message sent to %s\n", peerID)
			}

		case "/exit":
			fmt.Println("Goodbye!")
			return

		default:
			fmt.Println("Unknown command. Available commands: /list, /connect, /send, /exit")
		}
	}
}
