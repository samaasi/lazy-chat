# Lazy Chat 💬

A modern, peer-to-peer chat application built in Go with real-time messaging, file transfer capabilities, and cross-platform support.

## ✨ Features

- **🔄 Peer-to-Peer Communication**: Direct messaging without central servers
- **🔍 Auto-Discovery**: Automatic peer discovery on local networks
- **📁 File Transfer**: Send files with real-time progress tracking
- **🔔 Desktop Notifications**: Native OS notifications for new messages
- **🎨 Interactive CLI**: Beautiful command-line interface with colors
- **🛡️ Graceful Shutdown**: Proper cleanup and context cancellation
- **📊 Structured Logging**: Comprehensive logging with multiple levels
- **⚙️ Configurable**: JSON configuration with command-line overrides

## 🚀 Quick Start

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases](../../releases) page:

- **Windows**: `lazy-chat-windows-amd64.zip`
- **macOS Intel**: `lazy-chat-darwin-amd64.tar.gz`
- **macOS Apple Silicon**: `lazy-chat-darwin-arm64.tar.gz`
- **Linux x64**: `lazy-chat-linux-amd64.tar.gz`
- **Linux ARM64**: `lazy-chat-linux-arm64.tar.gz`

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/lazy-chat.git
cd lazy-chat

# Build the application
go build -o lazy-chat ./cmd

# Run the application
./lazy-chat --username YourName
```

## 📋 Requirements

- **Go**: 1.24 or later (for building from source)
- **Operating System**: Windows, macOS, or Linux
- **Network**: Local network access for peer discovery

## 🔧 Usage

### Basic Usage

```bash
# Start with default settings
./lazy-chat --username Alice

# Specify custom port and enable notifications
./lazy-chat --username Bob --port 8080 --notifications=true

# Enable debug logging
./lazy-chat --username Charlie --log-level debug
```

### Configuration File

Create a `config.json` file (see `config.example.json`):

```json
{
  "username": "YourName",
  "port": 8080,
  "discovery_port": 8081,
  "notifications": true,
  "log_level": "info",
  "log_file": "logs/app.log"
}
```

### Available Commands

Once the application is running, use these commands:

- **`/help`** - Show available commands
- **`/peers`** - List discovered peers
- **`/connect <peer_id>`** - Connect to a specific peer
- **`/file <path>`** - Send a file to connected peers
- **`/quit`** - Exit the application

### Command Line Options

```
Options:
  --username, -u     Your display name (required)
  --port, -p         TCP port for connections (default: 8080)
  --discovery-port   UDP port for peer discovery (default: 8081)
  --notifications    Enable desktop notifications (default: false)
  --log-level        Logging level: debug, info, warn, error (default: info)
  --log-file         Log file path (default: logs/app.log)
  --config, -c       Configuration file path (default: config.json)
  --help, -h         Show help message
```

## 🏗️ Architecture

The application follows a modular architecture with clean separation of concerns:

```
internal/
├── app/           # Application lifecycle management
├── cli/           # Command-line interface
├── config/        # Configuration management
├── discovery/     # Peer discovery service
├── errors/        # Custom error definitions
├── filetransfer/  # File transfer functionality
├── interfaces/    # Interface definitions
├── logger/        # Structured logging
├── messaging/     # Message handling
├── models/        # Data models
├── network/       # Network management
├── notification/  # Desktop notifications
├── peer/          # Peer management
├── ui/            # User interface components
└── utils/         # Utility functions
```

## 🔨 Development

### Prerequisites

- Go 1.24+
- Git

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/lazy-chat.git
cd lazy-chat

# Download dependencies
go mod download

# Run tests
go test -v ./...

# Build for development
go build -v ./cmd
```

### Cross-Platform Building

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o lazy-chat.exe ./cmd

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o lazy-chat-macos-intel ./cmd

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o lazy-chat-macos-arm ./cmd

# Linux
GOOS=linux GOARCH=amd64 go build -o lazy-chat-linux ./cmd
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Go conventions and best practices
- Use `gofmt` for code formatting
- Add tests for new functionality
- Update documentation as needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Common Issues

**Peer Discovery Not Working**
- Ensure UDP port (default 8081) is not blocked by firewall
- Check that peers are on the same network subnet
- Try different discovery port with `--discovery-port`

**Connection Issues**
- Verify TCP port (default 8080) is available
- Check firewall settings
- Ensure peers can reach each other's IP addresses

**File Transfer Fails**
- Check available disk space
- Verify file permissions
- Ensure stable network connection

**Notifications Not Showing**
- Enable notifications with `--notifications=true`
- Check OS notification permissions
- Verify notification service is running

### Debug Mode

Run with debug logging for detailed information:

```bash
./lazy-chat --username Debug --log-level debug
```

## 📊 Performance

- **Memory Usage**: ~10-20MB typical usage
- **CPU Usage**: Minimal when idle, scales with activity
- **Network**: Efficient P2P protocol with minimal overhead
- **File Transfer**: Supports files up to available system memory

## 🔮 Roadmap

- [ ] Group chat support
- [ ] Message history persistence
- [ ] End-to-end encryption
- [ ] Web interface
- [ ] Mobile applications
- [ ] Plugin system

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](../../issues) page
2. Create a new issue with detailed information
3. Include logs when reporting bugs

---

**Made with ❤️ in Go**