# Lazy Chat

A peer-to-peer chat for your local network, written in Go. No server, no accounts: peers find each other automatically, talk over encrypted, mutually authenticated connections, and keep their history in a local SQLite database.

## Features

- **Direct messages and groups** with delivery receipts and searchable, exportable history
- **Automatic discovery** of peers on the LAN (signed UDP broadcasts)
- **Encrypted and authenticated**: every connection is TLS 1.3 and each peer is identified by its own key, so nobody can impersonate another peer
- **File transfer** that asks first, streams in constant memory and verifies a SHA-256 checksum
- **Desktop notifications** (optional) on Windows, macOS and Linux
- **Single static binary** - pure Go, no C compiler or runtime needed

## Quick start

Download a release for your platform from the [Releases](https://github.com/samaasi/lazy-chat/releases) page (`windows-amd64`, `darwin-amd64`, `darwin-arm64`, `linux-amd64`, `linux-arm64`), or build from source (requires **Go 1.27+**):

```bash
git clone https://github.com/samaasi/lazy-chat.git
cd lazy-chat
go build -o lazy-chat ./cmd
./lazy-chat --username Alice
```

Start it on two machines on the same network and they will find each other:

```
> /list
> /send Bob hello!
```

Trying it on a single machine? Give every instance its own port and data directory:

```bash
./lazy-chat -u Alice -p 8080 --data-dir /tmp/alice
./lazy-chat -u Bob   -p 8081 --data-dir /tmp/bob
```

## Commands

`<peer>` is a peer ID, a unique ID prefix (4+ characters) or a name. `<group>` is a group ID, a prefix or a name. Ambiguous input is an error, never a guess.

| Command | What it does |
| --- | --- |
| `/help` | Show all commands |
| `/whoami` | Show your name and peer ID |
| `/list` | List discovered peers |
| `/connect <peer>`, `/disconnect <peer>`, `/connections` | Manage connections (sending a message connects automatically) |
| `/send <peer> <message>` | Send a message |
| `/sendfile <peer> <path>` | Offer a file |
| `/getfile <id>`, `/rejectfile <id>`, `/cancel <id>`, `/transfers` | Answer and manage transfers |
| `/creategroup <name> [\| description]` | Create a group (you are its admin) |
| `/groups`, `/members <group>` | List groups and members |
| `/invite <group> <peer>` | Invite a peer (creator only) |
| `/invites`, `/accept <group>`, `/decline <group>` | Answer invitations |
| `/groupmsg <group> <message>` | Message a group |
| `/leavegroup <group>`, `/kick <group> <peer>` | Leave, or remove a member (creator only) |
| `/history <peer> [n]`, `/grouphistory <group> [n]`, `/recent [n]` | Read history |
| `/search <text>` | Search all messages |
| `/export <peer\|group> <file> [text\|json]` | Export a conversation to a *new* file |
| `/status`, `/quit` | Status and exit |

## Configuration

Settings are applied in this order, later ones winning: **defaults -> config file -> environment -> command-line flags.**

The config file is `./config.json` if present, or the path given with `-c/--config` (an explicitly named file must exist). See [`config.example.json`](config.example.json).

| Option (flag / JSON key / env) | Default | |
| --- | --- | --- |
| `-u, --username` / `username` / `P2P_USERNAME` | `Anonymous` | Display name (max 32 characters, no control characters) |
| `-p, --port` / `tcp_port` / `P2P_TCP_PORT` | `8080` | TCP port for peer connections |
| `--listen-addr` / `listen_addr` | all interfaces | Address to listen on |
| `--max-connections` / `max_connections` | `64` | Simultaneous inbound connections |
| `--discovery-port`, `--discovery-range` | `9999`, `10` | First UDP port and how many to use |
| `--broadcast-addr`, `--broadcast-interval` | `255.255.255.255`, `5` | Where and how often to announce |
| `--data-dir` / `data_dir` | `~/.lazy-chat` | Identity key and database |
| `--db-path` / `database.path` | `<data-dir>/lazy-chat.db` | SQLite database |
| `--download-dir` / `download_dir` | `downloads` | Where received files go |
| `--max-file-size` / `max_file_size` | `268435456` | Largest incoming file, bytes |
| `--auto-accept-files` / `auto_accept_files` | off | Accept incoming files without asking |
| `--notifications` / `notifications_enabled` | off | Desktop notifications |
| `--log-level`, `--log-format`, `--log-file` | `info`, `text`, stderr | Logging (files rotate at 10 MiB) |

All other `P2P_*` variables follow the same pattern (`P2P_DATA_DIR`, `P2P_DOWNLOAD_DIR`, ...). Run `lazy-chat --help` for the full list.

If peers cannot see each other, set `--broadcast-addr` to your subnet's broadcast address (for example `192.168.1.255`); some systems only send the limited broadcast out of one network adapter.

## Security model

**What is protected**

- **Identity.** On first run a peer generates an Ed25519 key (`<data-dir>/identity.key`, mode 0600). Its **peer ID is the fingerprint of the public key**, so an ID cannot be claimed without the private key. Back this file up; deleting it gives you a new identity.
- **Transport.** All peer traffic is TLS 1.3 with mutual authentication. When you connect to a discovered peer, its key must match the ID it announced. A forged or hijacked discovery announcement can at worst make a connection fail; it cannot redirect your messages to an impostor.
- **Sender attribution.** The sender of a message is the authenticated peer ID of the connection, never a field the sender wrote. Group messages are accepted only from members, checked before anything is stored.
- **Untrusted text.** Names and messages are stripped of terminal escape sequences and bidirectional overrides before display, logging or notifications. Notification text is never placed in a script.
- **Files.** Nothing is written until you accept; file names are reduced to a single safe name inside the download directory; existing files are never overwritten; data is checked against a SHA-256 before it appears under its final name.
- **Limits.** Message and frame sizes, connections (total and per IP), handshake time, message rate, peers per address, pending offers, and file size are all bounded.

**What is not**

- There is no central authority. The first time you talk to someone you trust that the ID you see belongs to them. For high-stakes conversations, compare peer IDs (`/whoami`) over another channel.
- Discovery announcements (username, TCP port) are broadcast in the clear and are visible to the whole LAN.
- The local database, exports and received files are **not encrypted at rest**; they are readable by anyone who can read your user account's files (the database and key are created `0600`).
- Groups are simple: the creator is the only admin, and every member keeps their own copy of the group. A peer you trust enough to accept an invitation from can describe the membership list inaccurately.
- Chat is for trusted local networks. Do not expose the TCP port to the internet.

## Data

| What | Where |
| --- | --- |
| Identity key | `<data-dir>/identity.key` |
| Messages, groups, invitations | SQLite database, schema versioned with `PRAGMA user_version` |
| Received files | `download_dir` (partial files are `.lazychat-*.part` and removed on failure) |
| Logs | stderr, or `log_file` |

Databases written by earlier versions are kept: their tables are renamed `legacy_*` on first start.

## Architecture

```
cmd/                 entry point
internal/
  app/               composition root, lifecycle, ordered shutdown
  cli/               interactive commands
  config/            defaults -> file -> env -> flags
  discovery/         signed UDP announcements
  errors/            structured errors
  filetransfer/      offer / accept / stream / verify
  identity/          Ed25519 identity, TLS certificate
  interfaces/        contracts between packages
  logger/            slog wrapper with rotation
  messaging/         direct messages, groups, group protocol
  models/            data types
  network/           TLS transport, connection management
  notification/      desktop notifications
  peer/              peer registry
  protocol/          wire frames and payloads
  services/          group and history rules
  storage/           SQLite (pure Go driver)
  ui/                console output, progress bars
  utils/             IDs, sanitising, rate limiting
```

Wire format: after the TLS handshake each side sends a `Hello`; then a stream of frames `kind (1 byte) | length (4 bytes) | body`. Control frames are JSON, file chunks are raw bytes. Maximum body size is fixed per kind and checked before any allocation.

## Development

```bash
go vet ./...
go test ./...                 # all packages
go test -race ./...           # needs cgo (a C compiler); CI runs it
CGO_ENABLED=0 go build ./cmd  # the release configuration
```

The test suite includes end-to-end tests that start two complete applications on loopback (real TLS, discovery and SQLite) and drive them through their CLIs. CI builds all five release targets, runs `go vet`, tests with and without the race detector, and scans for known vulnerabilities with `govulncheck`.

Cross-compiling needs no toolchain beyond Go:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lazy-chat-linux-arm64 ./cmd
```

## Troubleshooting

- **Peers don't appear**: allow UDP ports 9999-10008 and your TCP port through the firewall; make sure both machines are on the same subnet; try `--broadcast-addr` with the subnet broadcast address.
- **Address already in use**: pick another `--port`; discovery automatically takes the next free UDP port in its range.
- **`could not connect`**: the peer's firewall, or the peer restarted with a new identity. Wait for its next announcement and retry.
- **Messages show "(not delivered)"**: the peer was unreachable; the message is kept in history but is not re-sent automatically.
- **No notifications**: enable with `--notifications`; Linux needs `notify-send` (libnotify).

## Roadmap

- [x] Group chat (invitations, roster sync)
- [x] Message history persistence
- [x] Encrypted, authenticated transport
- [x] Verified file transfer
- [ ] Offline message queue / automatic retry
- [ ] Encrypted storage at rest
- [ ] Out-of-band peer verification (safety numbers)
- [ ] Web interface
- [ ] Plugin system

## License

MIT, as declared by the project. Note: the repository does not currently contain a `LICENSE` file; add one before distributing.
