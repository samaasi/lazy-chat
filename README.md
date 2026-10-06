# Lazy Chat

A peer-to-peer chat for your local network, written in Go. There is no server and there are no accounts: peers find each other automatically, talk over encrypted and mutually authenticated connections, and keep their history in a local database that is itself encrypted.

- [Features](#features)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Security](#security)
- [Data and files](#data-and-files)
- [How it works](#how-it-works)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- **Direct messages and groups**, with delivery receipts, automatic retry of anything that could not be delivered, and searchable, exportable history
- **Automatic discovery** of peers on the LAN (signed UDP broadcasts)
- **Layered encryption**: TLS 1.3 between peers, a Double Ratchet on top for per-message forward secrecy, and encryption at rest for your database and private key
- **Verifiable identities**: every peer is its own key; compare *safety numbers* to be sure you are talking to the right person
- **File transfer** that asks first, streams in constant memory and verifies a SHA-256 checksum
- **Desktop notifications** (optional) on Windows, macOS and Linux
- **Single static binary**: pure Go, no C compiler or runtime needed

## Quick start

Download a release for your platform from the [Releases](https://github.com/samaasi/lazy-chat/releases) page (`windows-amd64`, `darwin-amd64`, `darwin-arm64`, `linux-amd64`, `linux-arm64`), or build from source (requires **Go 1.27+**):

```bash
git clone https://github.com/samaasi/lazy-chat.git
cd lazy-chat
go build -o lazy-chat ./cmd
./lazy-chat --username Alice
```

On the first run:

- **Windows**: nothing to do. Your data key is protected by your Windows account (DPAPI).
- **macOS / Linux**: you are asked to choose a passphrase (typed twice). It encrypts your messages and keys; **there is no recovery if you forget it**. For unattended use see [Encryption at rest](#encryption-at-rest).

Start it on two machines on the same network and they find each other:

```
> /list
> /send Bob hello!
```

Trying it on one machine? Give each instance its own port and data directory:

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
| `/list`, `/connections` | Peers and connections, with their trust status |
| `/connect <peer>`, `/disconnect <peer>` | Manage connections (sending a message connects automatically) |
| `/send <peer> <message>` | Send a message |
| `/safety <peer>` | Show the safety number to compare with that peer |
| `/verify <peer>`, `/unverify <peer>` | Record that you compared safety numbers |
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

Settings are applied in this order, later ones winning: **defaults, config file, environment, command-line flags.**

The config file is `./config.json` if present, or the path given with `-c/--config` (an explicitly named file must exist). See [`config.example.json`](config.example.json). Run `lazy-chat --help` for every flag; each also has a `P2P_*` environment variable (for example `P2P_USERNAME`).

| Option (flag / JSON key) | Default | |
| --- | --- | --- |
| `-u, --username` / `username` | `Anonymous` | Display name (max 32 characters, no control characters) |
| `-p, --port` / `tcp_port` | `8080` | TCP port for peer connections |
| `--listen-addr` / `listen_addr` | all interfaces | Address to listen on |
| `--max-connections` / `max_connections` | `64` | Simultaneous inbound connections |
| `--discovery-port`, `--discovery-range` | `9999`, `10` | First UDP port and how many to use |
| `--broadcast-addr`, `--broadcast-interval` | `255.255.255.255`, `5` | Where and how often to announce |
| `--data-dir` / `data_dir` | `~/.lazy-chat` | Identity key, key vault and database |
| `--db-path` / `database.path` | `<data-dir>/lazy-chat.db` | SQLite database |
| `--encryption` / `encryption` | `auto` | `auto`, `passphrase`, `os` or `off` |
| `--passphrase-file` / `passphrase_file` | none | File whose first line is the passphrase |
| `--download-dir` / `download_dir` | `downloads` | Where received files go |
| `--max-file-size` / `max_file_size` | `268435456` | Largest incoming file, bytes |
| `--auto-accept-files` / `auto_accept_files` | off | Accept incoming files without asking |
| `--notifications` / `notifications_enabled` | off | Desktop notifications |
| `--log-level`, `--log-format`, `--log-file` | `info`, `text`, stderr | Logging (files rotate at 10 MiB) |

If peers cannot see each other, set `--broadcast-addr` to your subnet's broadcast address (for example `192.168.1.255`); some systems send the limited broadcast out of only one network adapter.

### Encryption at rest

| Mode | How the data key is protected |
| --- | --- |
| `auto` (default) | `os` on Windows, `passphrase` elsewhere |
| `os` | Windows DPAPI: bound to your Windows account, nothing to type |
| `passphrase` | A key derived from your passphrase with Argon2id |
| `off` | Nothing is encrypted at rest. Refused if the data is already encrypted |

The passphrase is asked for at start-up. For services and scripts, put it in a file readable only by you and pass `--passphrase-file`, or set `P2P_PASSPHRASE` (it is removed from the process environment as soon as it is read, so helper processes do not inherit it). Turning encryption on for an existing installation encrypts the database and private key in place; your identity and history are kept.

## Security

Lazy Chat protects a conversation in four independent layers.

| Layer | What it gives you |
| --- | --- |
| **Identity** | Your peer ID *is* the fingerprint of your Ed25519 key. An ID cannot be claimed without the private key. |
| **Transport: TLS 1.3, mutually authenticated** | Confidentiality and integrity on the wire. When you connect to a discovered peer, its key must match the ID it announced, so forged or hijacked discovery data cannot send you to an impostor. |
| **Message layer: Double Ratchet** | Every message has its own key, deleted after use, and keys are renewed by fresh Diffie-Hellman exchanges each time the conversation changes direction. Capturing a session's state reveals nothing sent earlier (**forward secrecy**), and the session closes itself to an attacker after one round trip (**post-compromise security**). Replayed, reordered, tampered or unencrypted frames end the connection. |
| **At rest: AES-256-GCM** | Message text, group and member names, invitations and your private key are stored encrypted. |

Beyond that:

- **Safety numbers.** Run `/safety <peer>` on both sides. If the 60-digit numbers match when compared in person or over a call you trust, run `/verify <peer>`. Because an ID is a key fingerprint, a different key always gives a different number, so there is no separate "key changed" case to miss.
- **Sender attribution.** The sender of a message is the authenticated connection, never a field the sender wrote. Group messages are accepted only from members, checked before anything is stored.
- **Untrusted text.** Names and messages are stripped of terminal escape sequences and bidirectional overrides before display, logging or notifications. Notification text is never placed in a script.
- **Files.** Nothing is written until you accept; names are reduced to a single safe name inside the download directory; existing files are never overwritten; data is checked against a SHA-256 before it appears under its final name.
- **Limits.** Message and frame sizes, connections (total and per IP), handshake time, message rate, peers per address, pending offers and file size are all bounded.
- **Delivery.** Messages that could not be delivered are retried automatically when the peer reconnects and periodically while it is visible (direct messages, up to 7 days). Receivers deduplicate, so a retry is always safe.

**What is not protected**

- *Metadata.* Peer IDs, timestamps, group IDs and delivery flags stay readable in the database (they are needed to query it), and discovery announcements (username, TCP port) are broadcast in clear text to the whole LAN. Anyone on the network can see *that* you are online, though not what you say.
- *Received files and exports* are ordinary files and are not encrypted; keep them on an encrypted disk if that matters.
- *Memory.* Keys and plaintext exist in process memory while the program runs. DPAPI protects against another user or a stolen disk, not against malware running as you.
- *Ratchet scope.* Ratchet sessions live as long as a connection; they are not stored. Retried messages are re-encrypted for the new connection. Group messages are delivered to each member over their pairwise links, and are not retried automatically.
- *Groups are simple.* The creator is the only admin, and every member keeps their own copy of the group. Someone whose invitation you accept can describe the membership list inaccurately.
- *Trust on first use.* Until you compare safety numbers, you trust that the ID you see belongs to the person you think it does.
- Chat is for trusted local networks. Do not expose the TCP port to the internet.

## Data and files

| What | Where |
| --- | --- |
| Identity key | `<data-dir>/identity.key` (encrypted once encryption is on) |
| Wrapped data key | `<data-dir>/vault.key` |
| Messages, groups, invitations, verification marks | SQLite database; schema versioned with `PRAGMA user_version` |
| Received files | `download_dir` (partial files are `.lazychat-*.part` and are removed on failure) |
| Logs | stderr, or `log_file` |

Back up `identity.key` and `vault.key` together with the database; without the key material (and the passphrase, in passphrase mode) the history cannot be read. Databases written by earlier versions are kept: their tables are renamed `legacy_*` on first start, and empty ones are dropped when encryption is enabled.

Searching an encrypted database decrypts messages newest-first, so it considers at most the 100,000 most recent messages.

## How it works

```
cmd/                 entry point
internal/
  app/               composition root, lifecycle, ordered shutdown
  cli/               interactive commands
  config/            defaults -> file -> env -> flags
  discovery/         signed UDP announcements
  filetransfer/      offer / accept / stream / verify
  identity/          Ed25519 identity, TLS certificate, safety numbers
  messaging/         direct messages, groups, retry
  network/           TLS transport, connection management
  protocol/          wire frames and payloads
  ratchet/           Double Ratchet
  services/          group and history rules
  storage/           SQLite (pure Go driver), field-level encryption
  vault/             data-key management (passphrase / DPAPI)
  ui/ utils/ ...     console, sanitising, rate limiting, logging, errors
```

A connection goes through these steps: TCP, TLS 1.3 handshake with mutual authentication (each side learns the other's authentic ID), `Hello` exchange, then a ratchet handshake whose ephemeral keys are signed with each identity key and bound to the TLS session. After that every application frame travels inside a ratchet-sealed `Secure` frame.

Wire format: frames are `kind (1 byte) | length (4 bytes) | body`. Control frames are JSON, file chunks are raw bytes. The maximum body size is fixed per kind and checked before any allocation.

## Development

```bash
go vet ./...
go test ./...                 # all packages
go test -race ./...           # needs cgo (a C compiler); CI runs it
CGO_ENABLED=0 go build ./cmd  # the release configuration
```

The suite includes end-to-end tests that start complete applications on loopback (real TLS, discovery and SQLite) and drive them through their CLIs, and tests that scan the raw database files for plaintext. CI builds all five release targets, runs `go vet`, tests with and without the race detector on Linux, Windows and macOS, and scans for known vulnerabilities with `govulncheck`.

Cross-compiling needs no toolchain beyond Go:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lazy-chat-linux-arm64 ./cmd
```

## Troubleshooting

- **Peers don't appear**: allow UDP ports 9999-10008 and your TCP port through the firewall, make sure both machines are on the same subnet, and try `--broadcast-addr` with the subnet broadcast address.
- **Address already in use**: pick another `--port`; discovery automatically takes the next free UDP port in its range.
- **`wrong passphrase`**: the passphrase does not match this data directory. There is no recovery path; if you have lost it, start with a new `--data-dir`.
- **`a passphrase is required`**: no terminal is attached. Use `--passphrase-file` (or `--encryption off` to opt out).
- **`encryption is switched off`**: the data is already encrypted; remove `--encryption off`.
- **`could not connect`**: the peer's firewall, or the peer restarted with a new identity. Wait for its next announcement and retry.
- **Messages show "(not delivered)"**: the peer was unreachable. They are retried automatically when it reconnects.
- **No notifications**: enable with `--notifications`; Linux needs `notify-send` (libnotify).

## Roadmap

- [x] Group chat (invitations, roster sync)
- [x] Message history persistence
- [x] Encrypted, mutually authenticated transport
- [x] Forward secrecy and post-compromise security (Double Ratchet)
- [x] Encryption at rest
- [x] Out-of-band verification (safety numbers)
- [x] Verified file transfer
- [x] Automatic retry of undelivered direct messages
- [ ] Per-recipient retry of group messages
- [ ] Relay / store-and-forward for peers that are never online together
- [ ] macOS Keychain and Linux Secret Service key storage (today: passphrase)
- [ ] Web interface

## License

[MIT](LICENSE) © 2026 Benson Samaasi
