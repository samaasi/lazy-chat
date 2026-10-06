# Lazy Chat

A peer-to-peer chat for your local network, written in Go. There is no server and there are no accounts: peers find each other automatically, talk over encrypted and mutually authenticated connections, and keep their history in a local database that is itself encrypted. Messages even reach people who are offline: other peers hold an end-to-end encrypted copy until the recipient comes back.

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

- **Direct messages and groups**, with delivery receipts, searchable and exportable history, and automatic retry of anything that could not be delivered
- **Offline delivery**: write to someone who is not online and the message is end-to-end encrypted to them and held by other peers until they return, even if you are offline by then too. The peers holding it do not learn who sent it. You get a signed receipt when it arrives.
- **Automatic discovery** of peers on the LAN (signed UDP broadcasts)
- **Layered encryption**: TLS 1.3 between peers, a Double Ratchet on top for per-message forward secrecy, and encryption at rest for your database and private key
- **Verifiable identities**: every peer is its own key; compare *safety numbers* to be sure you are talking to the right person
- **File transfer** that asks first, streams in constant memory and verifies a SHA-256 checksum
- **Desktop notifications** (optional) on Windows, macOS and Linux
- **Single static binary**: pure Go, no C compiler or runtime needed

## Install

One command, no dependencies. Each installer downloads the release for your machine, checks it against the release's SHA-256 checksums (and its signature, see [Updating](#updating)) and installs nothing if a check fails.

| System | Command |
| --- | --- |
| **macOS, Linux** | `curl -fsSL https://raw.githubusercontent.com/samaasi/lazy-chat/master/scripts/install.sh \| sh` |
| **macOS** (Homebrew) | `brew install --cask samaasi/tap/lazy-chat` |
| **Windows** (PowerShell) | `irm https://raw.githubusercontent.com/samaasi/lazy-chat/master/scripts/install.ps1 \| iex` |
| **Windows** (Scoop) | `scoop bucket add samaasi https://github.com/samaasi/scoop-bucket` then `scoop install lazy-chat` |
| **Go 1.27+** | `go install github.com/samaasi/lazy-chat/cmd/lazy-chat@latest` |

The scripts install to `/usr/local/bin` (or `~/.local/bin` if that is not writable) and `%LOCALAPPDATA%\Programs\lazy-chat` (added to your user `PATH`; no administrator rights needed). Set `LAZYCHAT_VERSION=v1.2.3` to pin a version and `LAZYCHAT_INSTALL_DIR` to choose the folder. On Windows the installer also offers to let lazy-chat through Windows Firewall (one administrator prompt; see [Firewall](#firewall)); `LAZYCHAT_NO_FIREWALL=1` skips that. You can also download an archive from the [Releases](https://github.com/samaasi/lazy-chat/releases) page (Linux, macOS and Windows; amd64 and arm64) or build from source:

```bash
git clone https://github.com/samaasi/lazy-chat.git
cd lazy-chat
go build -o lazy-chat ./cmd/lazy-chat
```

## Quick start

```bash
lazy-chat --username Alice
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
lazy-chat -u Alice -p 8080 --data-dir /tmp/alice
lazy-chat -u Bob   -p 8081 --data-dir /tmp/bob
```

## Commands

`<peer>` is a peer ID, a unique ID prefix (4+ characters) or a name. `<group>` is a group ID, a prefix or a name. Ambiguous input is an error, never a guess.

| Command | What it does |
| --- | --- |
| `/help` | Show all commands |
| `/whoami` | Show your name and peer ID |
| `/list`, `/connections` | Peers and connections, with their trust status |
| `/connect <peer>`, `/disconnect <peer>` | Manage connections (sending a message connects automatically) |
| `/connect <host>[:<port>]`, `/connect <id>@<host>[:<port>]` | Connect by address when discovery cannot find the peer (see [When peers don't appear](#when-peers-dont-appear)) |
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
| `/relay` | Show how many messages you are holding for offline peers |
| `/firewall` | Let other peers find and reach you through the firewall (Windows: one administrator prompt) |
| `/forget <peer>` | Stop remembering a peer's address, so it is not reconnected automatically |
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
| `--remember-peers` / `remember_peers` | on | Remember where connected peers were and reconnect to them; turning it off forgets them all |
| `--peer` / `peers` / `P2P_PEERS` | none | Addresses to connect to at start-up, retried for a few minutes: `host[:port]` or `<peer id>@host[:port]`. Repeat the flag, or comma-separate the variable |
| `--data-dir` / `data_dir` | `~/.lazy-chat` | Identity key, key vault and database |
| `--db-path` / `database.path` | `<data-dir>/lazy-chat.db` | SQLite database |
| `--encryption` / `encryption` | `auto` | `auto`, `passphrase`, `os` or `off` |
| `--passphrase-file` / `passphrase_file` | none | File whose first line is the passphrase |
| `--relay` / `relay` | on | Hold encrypted messages for offline peers (`--relay=false` to opt out) |
| `--relay-max-storage` / `relay_max_storage` | `67108864` | Most bytes of other peers' messages to hold |
| `--sealed-sender` / `sealed_sender` | `auto` | `auto` queues offline messages even if a relay could see you sent them (you are told); `required` only queues them anonymously |
| `--update-check` / `update_check` | on | Look for a new release once a day and say so (`--update-check=false` to disable; see [Updating](#updating)) |
| `--download-dir` / `download_dir` | `downloads` | Where received files go |
| `--max-file-size` / `max_file_size` | `268435456` | Largest incoming file, bytes |
| `--auto-accept-files` / `auto_accept_files` | off | Accept incoming files without asking |
| `--notifications` / `notifications_enabled` | off | Desktop notifications |
| `--log-level`, `--log-format`, `--log-file` | `info`, `text`, stderr | Logging (files rotate at 10 MiB) |

If peers cannot see each other, set `--broadcast-addr` to your subnet's broadcast address (for example `192.168.1.255`); some systems send the limited broadcast out of only one network adapter. If that does not help either, [connect by address](#when-peers-dont-appear).

### Encryption at rest

| Mode | How the data key is protected |
| --- | --- |
| `auto` (default) | `os` where the operating system's keychain works, otherwise `passphrase` (for example a headless Linux server with no Secret Service) |
| `os` | The OS keychain, bound to your user account, nothing to type: **Windows** DPAPI, **macOS** Keychain, **Linux** Secret Service (GNOME Keyring, KWallet, ...) |
| `passphrase` | A key derived from your passphrase with Argon2id |
| `off` | Nothing is encrypted at rest. Refused if the data is already encrypted |

The passphrase is asked for at start-up. For services and scripts, put it in a file readable only by you and pass `--passphrase-file`, or set `P2P_PASSPHRASE` (it is removed from the process environment as soon as it is read, so helper processes do not inherit it). Turning encryption on for an existing installation encrypts the database and private key in place; your identity and history are kept.

With the macOS and Linux keychains, `vault.key` holds your data key wrapped by a random key that lives in the keychain, so a stolen copy of the data directory is useless without your logged-in account. The keychain entry is recorded in `vault.key`, so moving the data directory on the same machine keeps working; restoring it on another machine or account does not (restore from a passphrase-protected backup instead, or start fresh). If the keychain entry is deleted the data cannot be recovered, exactly as with a forgotten passphrase.

## Security

Lazy Chat protects a conversation in independent layers.

| Layer | What it gives you |
| --- | --- |
| **Identity** | Your peer ID *is* the fingerprint of your Ed25519 key. An ID cannot be claimed without the private key. |
| **Transport: TLS 1.3, mutually authenticated** | Confidentiality and integrity on the wire. When you connect to a discovered peer, its key must match the ID it announced, so forged or hijacked discovery data cannot send you to an impostor. |
| **Message layer: Double Ratchet** | Every message has its own key, deleted after use, and keys are renewed by fresh Diffie-Hellman exchanges each time the conversation changes direction. Capturing a session's state reveals nothing sent earlier (**forward secrecy**), and the session closes itself to an attacker after one round trip (**post-compromise security**). Replayed, reordered, tampered or unencrypted frames end the connection. |
| **At rest: AES-256-GCM** | Message text, group and member names, invitations, your private key and your prekeys are stored encrypted. |
| **Offline messages: prekeys (X3DH-style)** | A message to someone who is not online is encrypted to *their* keys before it leaves your machine. Whoever stores it on the way can neither read nor alter it. |

Beyond that:

- **Safety numbers.** Run `/safety <peer>` on both sides. If the 60-digit numbers match when compared in person or over a call you trust, run `/verify <peer>`. Because an ID is a key fingerprint, a different key always gives a different number, so there is no separate "key changed" case to miss.
- **Sender attribution.** The sender of a message is the authenticated connection, never a field the sender wrote. Group messages are accepted only from members, checked before anything is stored.
- **Untrusted text.** Names and messages are stripped of terminal escape sequences and bidirectional overrides before display, logging or notifications. Notification text is never placed in a script.
- **Files.** Nothing is written until you accept; names are reduced to a single safe name inside the download directory; existing files are never overwritten; data is checked against a SHA-256 before it appears under its final name.
- **Limits.** Message and frame sizes, connections (total and per IP), handshake time, message rate, peers per address, pending offers and file size are all bounded.
- **Delivery.** A message that cannot be delivered right away is retried automatically when the peer reconnects and periodically while it is visible (direct messages, up to 7 days), and is also queued with relays so it arrives even if you are offline when the recipient returns. Receivers deduplicate, so a retry or a second copy is always safe.

### Offline delivery and relays

When you write to someone who is offline, your app encrypts the message to the recipient's *prekeys*, hands the ciphertext to a few of the peers you are connected to (**relays**), and keeps the message marked "not delivered". When the recipient next connects to any of those relays they receive it, store it like any other message, and send back a **receipt signed with their identity key**. The relay keeps the receipt for you, even if you were offline when the message was delivered, and you collect it later; only then does the message show as delivered.

Peers exchange prekey bundles whenever they connect, so you can write to anyone you have met once, or whose bundle a mutual peer already holds (it asks on your behalf). The bundle is signed by the owner's identity key, so whoever relays it cannot swap in their own.

**Sealed sender.** A relay does not learn who wrote a message. The sender's identity is inside the end-to-end encryption, and the request to hold it is sealed to the relay and carried by a second peer you are connected to (a *forwarder*): the relay sees only the forwarder, and the forwarder sees only a sealed blob and which relay it is for, never the recipient or the text. Neither can link you to the recipient. Receipts are filed under a random mailbox tag known only to you and the recipient, and you collect them through a forwarder too.

| A relay | |
| --- | --- |
| **can see** | who a message is *for*, when it was stored, and roughly how big it is |
| **cannot** | read it, alter it, forge a receipt, pretend to be the sender, or tell who sent it |
| **can** | delay or drop it, which is why senders use several relays and keep retrying direct delivery |

| A forwarder | |
| --- | --- |
| **can see** | that you asked it to reach a particular relay, and how big the request was |
| **cannot** | read the request or its answer, or learn who the message is for |

Hiding the sender needs three peers: you, a forwarder and a relay. With fewer, the request goes straight to the relay, which then sees that it is from you; the app says so ("N relay(s) could see that this is from you"). `--sealed-sender=required` (`sealed_sender`, `P2P_SEALED_SENDER`) refuses instead and keeps the message undelivered until a forwarder is connected. Forwarding is part of relaying, so `--relay=false` turns it off too.

Relays are bounded: total storage (`--relay-max-storage`), messages and bytes per submitter, messages per recipient, a 7-day expiry, and only the addressee can acknowledge or remove a held message. Turn relaying off with `--relay=false`; you can still send through other peers' relays.

Forward secrecy for offline messages comes from deleting keys. Each message uses a fresh ephemeral key plus, when available, a one-time prekey that is reserved for you alone and destroyed the first time it opens a message. If none are left, protection falls back to the weekly-rotated signed prekey, which is deleted after four weeks, so those messages are protected only until then.

**What is not protected**

- *Metadata.* Peer IDs, remembered peer addresses, timestamps, group IDs and delivery flags stay readable in the database (they are needed to query it), and discovery announcements (username, TCP port) are broadcast in clear text to the whole LAN. Anyone on the network can see *that* you are online, though not what you say. A relay additionally learns who a held message is for, and when; it does not learn who sent it unless you had too few peers connected to use a forwarder (see sealed sender).
- *Received files and exports* are ordinary files and are not encrypted; keep them on an encrypted disk if that matters.
- *Memory.* Keys and plaintext exist in process memory while the program runs. The OS keychain protects against another user or a stolen disk, not against malware running as you.
- *Ratchet scope.* Ratchet sessions live as long as a connection; they are not stored. Retried messages are re-encrypted for the new connection. Offline messages use their own per-message encryption (above) rather than a ratchet, so they have no post-compromise healing.
- *Group messages and offline members.* A group message to a member who is offline is queued with relays at the moment you send it, but unlike direct messages it is not re-queued later if that failed.
- *Relays can delay or drop.* A message queued with relays is a best effort; delivery is proven only by the recipient's receipt.
- *Groups are simple.* The creator is the only admin, and every member keeps their own copy of the group. Someone whose invitation you accept can describe the membership list inaccurately.
- *Trust on first use.* Until you compare safety numbers, you trust that the ID you see belongs to the person you think it does.
- Chat is for trusted local networks. Do not expose the TCP port to the internet.

## Updating

```bash
lazy-chat update            # download, verify and install the latest release
lazy-chat update --check    # only say whether there is one
```

`lazy-chat update` never runs by itself. At start-up the program checks GitHub once a day and prints a line if a newer release exists; that is the only network request it makes outside your LAN, it sends nothing but a standard HTTPS request for the public release information, and `--update-check=false` turns it off.

The update is accepted only if it is authentic:

1. Every release carries `checksums.txt` and `checksums.txt.sig`, a [cosign](https://github.com/sigstore/cosign) signature made in CI with a private key that is not stored in the repository.
2. The matching public key is compiled into the program ([internal/update/release.pub](internal/update/release.pub)). The signature is checked first; the download host and the network in between are not trusted.
3. The archive must match its signed checksum. Then the new program is started once with `--version` and must report the expected version.
4. Only then does it replace the old one, atomically (Windows renames the running program aside), and downgrades are refused.

If anything fails, your installed copy is left exactly as it was. Copies installed by Homebrew, Scoop or `go install` are not replaced behind their manager's back; the command tells you what to run instead (or pass `--force`). A program built from source has no signing key and can look for updates but not install them. Maintainers: see [RELEASING.md](RELEASING.md).

The install scripts apply the same checks (the signature check needs `openssl` on macOS and Linux, which is normally present; without it they say so and rely on the checksum alone).

## Data and files

| What | Where |
| --- | --- |
| Identity key | `<data-dir>/identity.key` (encrypted once encryption is on) |
| Wrapped data key | `<data-dir>/vault.key` |
| Messages, groups, invitations, verification marks | SQLite database; schema versioned with `PRAGMA user_version` |
| Your prekeys and other peers' prekey bundles | The same database (private keys encrypted) |
| Messages held for others | The same database (end-to-end encrypted blobs; expire after 7 days) |
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
  offline/           prekeys and encryption to offline recipients
  relay/             store-and-forward: sender, relay and recipient roles
  protocol/          wire frames and payloads
  ratchet/           Double Ratchet
  services/          group and history rules
  storage/           SQLite (pure Go driver), field-level encryption
  vault/             data-key management (passphrase / DPAPI)
  ui/ utils/ ...     console, sanitising, rate limiting, logging, errors
```

A connection goes through these steps: TCP, TLS 1.3 handshake with mutual authentication (each side learns the other's authentic ID), `Hello` exchange, then a ratchet handshake whose ephemeral keys are signed with each identity key and bound to the TLS session. After that every application frame travels inside a ratchet-sealed `Secure` frame.

Offline delivery sits beside this: prekey bundles ride the same secure connections, `relay` hands sealed messages to peers that agree to hold them, and the recipient's receipt returns the same way.

Wire format: frames are `kind (1 byte) | length (4 bytes) | body`. Control frames are JSON, file chunks are raw bytes. The maximum body size is fixed per kind and checked before any allocation.

## Development

```bash
go vet ./...
go test ./...                 # all packages
go test -race ./...           # needs cgo (a C compiler); CI runs it
CGO_ENABLED=0 go build ./cmd/lazy-chat  # the release configuration
```

The suite includes end-to-end tests that start complete applications on loopback (real TLS, discovery and SQLite) and drive them through their CLIs, and tests that scan the raw database files for plaintext. CI builds every release archive as a dry run (GoReleaser snapshot), runs `go vet`, tests with and without the race detector on Linux, Windows and macOS, and scans for known vulnerabilities with `govulncheck`.

Cross-compiling needs no toolchain beyond Go:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lazy-chat-linux-arm64 ./cmd/lazy-chat
```

## Troubleshooting

### Firewall

Every firewall drops unsolicited inbound packets, which is exactly what discovery announcements and incoming chats are, and no program can (or should) get around that on its own. So lazy-chat asks once:

- **Windows**: on first run, if Windows Firewall would keep peers out, the app asks `Allow lazy-chat on private networks? [Y/n]` and, on yes, adds one rule for its own program through a single administrator prompt. The rule covers discovery and chat on any port, applies to *private* networks only, and survives `lazy-chat update` (the program keeps its path). It also removes "block" rules left behind by a dismissed *Allow access?* dialog, which would otherwise override it. If your network is classified as *Public*, the app says so: rules for private networks do not apply there. Do it again at any time with `/firewall` or `lazy-chat firewall`; check with `lazy-chat firewall --status`; undo with `lazy-chat firewall --remove`.
- **Linux**: if `ufw` or `firewalld` is active, the app prints the exact command to run (for example `sudo ufw allow 8080/tcp && sudo ufw allow 9999:10008/udp`). Hand-written iptables/nftables rules cannot be read without root; open the same ports there.
- **macOS**: the system itself asks whether lazy-chat may accept incoming connections; choose *Allow*. If you denied it, `lazy-chat firewall` shows the command that reverses it.

### Finding each other

Peers announce themselves every few seconds on every local network (each adapter's subnet broadcast as well as `255.255.255.255`, because Windows sends the latter out of a single adapter, often a WSL, Hyper-V or VPN one). Once you have been connected to a peer, its address is **remembered** and it is reconnected at every start and every two minutes, so after the first meeting you never need its address again, even on networks where broadcasts do not get through. Reconnection is pinned to the remembered peer ID: another machine that later takes the same address is refused. `/forget <peer>` removes one; `--remember-peers=false` turns this off. The addresses are kept in the local database (like the rest of your metadata, see [What is not protected](#security)).

### When peers don't appear

A peer ID is a fingerprint of a key, not an address, so the app can only reach peers it has *discovered* (the UDP announcements shown in `/list`). Commands naming a peer that was never discovered fail with `peer not found`, followed by a hint.

If broadcasts do not get through (a different subnet, a VPN, guest Wi-Fi, a blocked firewall), connect by address instead:

```
> /connect 192.168.1.20            # port 8080 unless you give one: 192.168.1.20:9000
> /connect d033d57d674e975564c47731bb6b2503@192.168.1.20
```

or at start-up (`--peer 192.168.1.20`, or `"peers": ["192.168.1.20"]` in the configuration), which keeps retrying until the other side is up. The connection is as secure as any other (TLS 1.3 with mutual keys, then the ratchet), and the peer is added to `/list` so you can use its name. What differs is trust: when you give only an address, whoever answers there is accepted, so confirm their identity with `/safety` afterwards. When you give `<id>@address`, only that exact peer is accepted, and anyone else answering is refused. Both machines still need to reach each other's TCP port (8080 by default), so allow it in the firewall.

### Other problems

- **Peers don't appear**: run `/firewall` (or `lazy-chat firewall`) on *both* machines, make sure both are on the same network and that it is classified as *Private* on Windows, then connect once by address (`/connect <ip>`); after that they find each other automatically. Some networks (guest Wi-Fi with client isolation, many corporate networks) block devices from talking to each other at all; nothing on the two computers can fix that.
- **Address already in use**: pick another `--port`; discovery automatically takes the next free UDP port in its range.
- **`could not store the key in the OS keychain` / `timed out waiting for the OS keychain`**: the keychain is locked or unavailable (a Linux session without a running Secret Service, an SSH session on macOS). Unlock it, or use `--encryption passphrase`.
- **`key is not in the OS keychain`**: the data directory was created under another account or machine, or the keychain entry was removed.
- **`wrong passphrase`**: the passphrase does not match this data directory. There is no recovery path; if you have lost it, start with a new `--data-dir`.
- **`a passphrase is required`**: no terminal is attached. Use `--passphrase-file` (or `--encryption off` to opt out).
- **`encryption is switched off`**: the data is already encrypted; remove `--encryption off`.
- **`could not connect`**: the peer's firewall, or the peer restarted with a new identity. Wait for its next announcement and retry.
- **Messages show "(not delivered)"**: the peer was unreachable. If you were connected to anyone who could hold it, it is queued with relays ("queued with relays") and will arrive when they return; otherwise it is retried automatically when you next reach them or a relay. It changes to delivered only when the recipient's signed receipt arrives.
- **"saved but not delivered" when writing to an offline peer**: you have never met them (no prekey bundle) and nobody connected to you holds one, or none of your connected peers is willing to hold messages. Connect to a peer who knows them, or wait until they are online.
- **No notifications**: enable with `--notifications`; Linux needs `notify-send` (libnotify).
- **`update` says "no release signing key"**: this copy was built from source. Install a release to get verified updates.
- **`update` cannot write**: the program is in a folder you do not own; re-run with `sudo`, or install somewhere you do.

### Testing notifications

The unit tests check what is handed to the operating system (hostile text never reaches a script, flooding is bounded) without showing anything. To see real notifications and require the OS helper to accept them:

```bash
LAZYCHAT_TEST_NOTIFY=1 go test ./internal/notification -run Real -v
```

On Windows this has been confirmed by eye as well as by exit status. On macOS and Linux it checks that the helper (`osascript`, `notify-send`) exits successfully; it needs a desktop session and, on Linux, a notification daemon.

## Roadmap

- [x] Group chat (invitations, roster sync)
- [x] Message history persistence
- [x] Encrypted, mutually authenticated transport
- [x] Forward secrecy and post-compromise security (Double Ratchet)
- [x] Encryption at rest
- [x] Out-of-band verification (safety numbers)
- [x] Verified file transfer
- [x] Automatic retry of undelivered direct messages
- [x] Offline delivery: end-to-end encrypted store-and-forward through relays, with signed receipts
- [ ] Re-queueing of group messages to offline members after the first attempt
- [x] Hiding the sender from relays (sealed sender)
- [x] macOS Keychain and Linux Secret Service key storage
- [x] One-command install (Linux, macOS, Windows), signed releases and verified `lazy-chat update`
- [x] Built-in firewall setup, discovery on every network adapter, remembered peers
- [ ] Optional relay server for networks that block devices from reaching each other
- [ ] Web interface

## License

[MIT](LICENSE) © 2026 Benson Samaasi
