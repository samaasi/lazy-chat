// Package cli is the interactive command-line interface.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/samaasi/lazy-chat/internal/address"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/filetransfer"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/messaging"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/ui"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	// commandTimeout bounds commands that touch the network or database.
	commandTimeout = 30 * time.Second
	// maxInputLine is the longest input line accepted.
	maxInputLine = 64 * 1024
	defaultCount = 50
	maxCount     = 500
)

// Deps are the collaborators of the CLI.
type Deps struct {
	In        io.Reader
	Console   *ui.Console
	SelfID    string
	SelfName  string
	Peers     interfaces.PeerManager
	Net       interfaces.NetworkManager
	Dialer    AddressDialer
	Handler   *messaging.Handler
	Groups    *services.GroupService
	History   *services.MessageHistoryService
	Files     *filetransfer.Manager
	Verify    storage.VerificationStorage
	Relay     RelayInfo
	StartedAt time.Time
	Version   string
}

// AddressDialer connects to a peer at a given address, without discovery.
type AddressDialer interface {
	ConnectToAddress(ctx context.Context, t address.Target) (peerID, name string, err error)
}

// RelayInfo reports what this peer holds for others.
type RelayInfo interface {
	Enabled() bool
	Usage(ctx context.Context) (envelopes int, bytes, capacity int64, err error)
}

// CLI handles command line interface interactions
type CLI struct {
	Deps
	commands []command
}

type command struct {
	names []string // first is canonical
	usage string   // arguments, for help and usage errors
	help  string
	run   func(ctx context.Context, arg string) error
}

// errUsage makes the dispatcher print the command's usage line.
var errUsage = errors.New("usage")

// errQuit ends the session.
var errQuit = errors.New("quit")

// New creates a CLI.
func New(d Deps) *CLI {
	c := &CLI{Deps: d}
	c.commands = c.buildCommands()
	return c
}

// Start runs the read-eval loop until the input ends, the context is
// cancelled or the user quits. It returns nil on a normal exit.
func (c *CLI) Start(ctx context.Context) error {
	c.printWelcome()

	lines := make(chan string)
	scanErr := make(chan error, 1)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(c.In)
		sc.Buffer(make([]byte, 0, 4096), maxInputLine)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		scanErr <- sc.Err()
	}()

	for {
		c.Console.ShowPrompt()
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			c.Console.InputDone()
			if !ok {
				select {
				case err := <-scanErr:
					if err != nil {
						return fmt.Errorf("reading input: %w", err)
					}
				default:
				}
				return nil
			}
			if err := c.execute(ctx, line); err != nil {
				if errors.Is(err, errQuit) {
					return nil
				}
				c.Console.Printf("Error: %v", err)
				if errors.Is(err, apperrors.ErrPeerNotFound) {
					c.Console.Printf("  %s", notDiscoveredHint)
				}
			}
		}
	}
}

// execute runs one input line.
func (c *CLI) execute(ctx context.Context, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if !strings.HasPrefix(line, "/") {
		c.Console.Printf("Messages are sent with /send <peer> <text>. Type /help for all commands.")
		return nil
	}

	name, arg, _ := strings.Cut(line, " ")
	name = strings.ToLower(name)
	arg = strings.TrimSpace(arg)

	for _, cmd := range c.commands {
		if !slices.Contains(cmd.names, name) {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		err := cmd.run(ctx, arg)
		cancel()
		if errors.Is(err, errUsage) {
			c.Console.Printf("Usage: %s %s", cmd.names[0], cmd.usage)
			return nil
		}
		return err
	}
	c.Console.Printf("Unknown command: %s. Type /help for available commands.", name)
	return nil
}

// splitN splits s into at most n parts on whitespace; the last part keeps the
// rest of the string verbatim (so message text is not reformatted).
func splitN(s string, n int) []string {
	var parts []string
	s = strings.TrimSpace(s)
	for len(parts) < n-1 {
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			break
		}
		parts = append(parts, s[:i])
		s = strings.TrimLeft(s[i:], " \t")
	}
	if s != "" {
		parts = append(parts, s)
	}
	return parts
}

func parseCount(s string) (int, error) {
	if s == "" {
		return defaultCount, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%q is not a positive number", s)
	}
	return min(n, maxCount), nil
}

// ---- Command table -----------------------------------------------------------

func (c *CLI) buildCommands() []command {
	return []command{
		{[]string{"/help", "/h"}, "", "Show this help", func(context.Context, string) error { c.printHelp(); return nil }},
		{[]string{"/whoami", "/me"}, "", "Show your name and peer ID", c.cmdWhoami},
		{[]string{"/list", "/l"}, "", "List discovered peers", c.cmdList},
		{[]string{"/safety"}, "<peer>", "Show the safety number to compare with a peer", c.cmdSafety},
		{[]string{"/verify"}, "<peer>", "Mark a peer as verified after comparing safety numbers", c.cmdVerify},
		{[]string{"/unverify"}, "<peer>", "Remove a peer's verified mark", c.cmdUnverify},
		{[]string{"/connect", "/c"}, "<peer | [id@]host[:port]>", "Connect to a peer, by name or by address", c.cmdConnect},
		{[]string{"/disconnect"}, "<peer>", "Close the connection to a peer", c.cmdDisconnect},
		{[]string{"/connections", "/conn"}, "", "List active connections", c.cmdConnections},
		{[]string{"/send", "/s"}, "<peer> <message>", "Send a message", c.cmdSend},
		{[]string{"/sendfile", "/sf"}, "<peer> <path>", "Offer a file to a peer", c.cmdSendFile},
		{[]string{"/transfers", "/tf"}, "", "Show file transfers", c.cmdTransfers},
		{[]string{"/getfile"}, "<transfer>", "Accept an incoming file", c.cmdGetFile},
		{[]string{"/rejectfile"}, "<transfer>", "Decline an incoming file", c.cmdRejectFile},
		{[]string{"/cancel"}, "<transfer>", "Cancel a transfer", c.cmdCancel},
		{[]string{"/creategroup", "/cg"}, "<name> [| description]", "Create a group", c.cmdCreateGroup},
		{[]string{"/groups", "/g"}, "", "List your groups", c.cmdGroups},
		{[]string{"/members"}, "<group>", "List a group's members", c.cmdMembers},
		{[]string{"/groupmsg", "/gm"}, "<group> <message>", "Send a message to a group", c.cmdGroupMsg},
		{[]string{"/invite", "/inv"}, "<group> <peer>", "Invite a peer (group creator only)", c.cmdInvite},
		{[]string{"/invites", "/invs"}, "", "Show pending invitations", c.cmdInvites},
		{[]string{"/accept", "/acc"}, "<group>", "Accept an invitation", c.cmdAccept},
		{[]string{"/decline", "/dec"}, "<group>", "Decline an invitation", c.cmdDecline},
		{[]string{"/leavegroup", "/lg"}, "<group>", "Leave a group", c.cmdLeave},
		{[]string{"/kick"}, "<group> <peer>", "Remove a member (group creator only)", c.cmdKick},
		{[]string{"/history", "/hist"}, "<peer> [count]", "Show a conversation", c.cmdHistory},
		{[]string{"/grouphistory", "/gh"}, "<group> [count]", "Show a group's messages", c.cmdGroupHistory},
		{[]string{"/recent", "/r"}, "[count]", "Show the newest messages", c.cmdRecent},
		{[]string{"/search"}, "<text>", "Search message history", c.cmdSearch},
		{[]string{"/export"}, "<peer|group> <file> [text|json]", "Export a conversation to a new file", c.cmdExport},
		{[]string{"/relay"}, "", "Show messages held for offline peers", c.cmdRelay},
		{[]string{"/status", "/st"}, "", "Show application status", c.cmdStatus},
		{[]string{"/quit", "/exit", "/q"}, "", "Exit", func(context.Context, string) error {
			c.Console.Printf("Goodbye!")
			return errQuit
		}},
	}
}

func (c *CLI) printWelcome() {
	c.Console.Printf("========================================")
	c.Console.Printf("  Lazy Chat %s", c.Version)
	c.Console.Printf("  You are %s", c.SelfName)
	c.Console.Printf("  Peer ID %s", c.SelfID)
	c.Console.Printf("========================================")
	c.Console.Printf("Type /help for commands.")
}

func (c *CLI) printHelp() {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "Commands:")
	for _, cmd := range c.commands {
		alias := ""
		if len(cmd.names) > 1 {
			alias = " (" + strings.Join(cmd.names[1:], ", ") + ")"
		}
		fmt.Fprintf(w, "  %s %s\t%s%s\n", cmd.names[0], cmd.usage, cmd.help, alias)
	}
	w.Flush()
	c.Console.Printf("%s", strings.TrimRight(b.String(), "\n"))
	c.Console.Printf("")
	c.Console.Printf("<peer> is a peer ID, a unique ID prefix (4+ characters) or a name; <group> is a group ID, prefix or name.")
}

// ---- Resolving arguments -------------------------------------------------

// resolvePeer turns user input into a peer ID. A full ID is accepted even if
// the peer is not currently known (history of offline peers, for instance).
func (c *CLI) resolvePeer(query string) (string, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	if identity.ValidID(query) {
		return query, nil
	}
	if p, err := c.Peers.ResolvePeer(query); err == nil {
		return p.ID, nil
	} else if !errors.Is(err, apperrors.ErrPeerNotFound) {
		return "", err // e.g. an ambiguous query
	}

	// Peers that connected to us without ever being discovered.
	var match []string
	for _, id := range c.Net.ConnectedPeers() {
		name, _ := c.Net.PeerName(id)
		if (len(query) >= 4 && strings.HasPrefix(id, query)) || strings.EqualFold(name, query) {
			match = append(match, id)
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return "", fmt.Errorf("no peer matches %q (see /list)", query)
	default:
		return "", fmt.Errorf("%q matches %d peers; use a longer ID prefix", query, len(match))
	}
}

func (c *CLI) resolveGroup(ctx context.Context, query string) (*models.Group, error) {
	groups, err := c.Groups.GetUserGroups(ctx)
	if err != nil {
		return nil, err
	}
	return pickGroup(query, groups, func(g *models.Group) (string, string) { return g.ID, g.Name })
}

func pickGroup[T any](query string, items []T, idName func(T) (id, name string)) (T, error) {
	var zero T
	query = strings.TrimSpace(query)
	lower := strings.ToLower(query)

	var byID, byName []T
	for _, it := range items {
		id, name := idName(it)
		switch {
		case strings.EqualFold(id, query):
			return it, nil
		case len(lower) >= 4 && strings.HasPrefix(strings.ToLower(id), lower):
			byID = append(byID, it)
		}
		if strings.EqualFold(name, query) {
			byName = append(byName, it)
		}
	}
	for _, set := range [][]T{byID, byName} {
		switch len(set) {
		case 0:
			continue
		case 1:
			return set[0], nil
		default:
			return zero, fmt.Errorf("%q matches several groups; use the group ID", query)
		}
	}
	return zero, fmt.Errorf("no group matches %q (see /groups)", query)
}

func (c *CLI) name(peerID string) string { return c.Handler.DisplayName(peerID) }

func clean(s string, max int) string { return utils.SanitizeText(s, max) }

// ---- Peers and connections -----------------------------------------------

func (c *CLI) verifiedSet(ctx context.Context) map[string]time.Time {
	if c.Verify == nil {
		return nil
	}
	set, err := c.Verify.ListVerified(ctx)
	if err != nil {
		return nil
	}
	return set
}

func (c *CLI) trust(verified map[string]time.Time, id string) string {
	if _, ok := verified[id]; ok {
		return "verified"
	}
	return "unverified"
}

// ---- Safety numbers -------------------------------------------------------

func (c *CLI) cmdSafety(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	id, err := c.resolvePeer(arg)
	if err != nil {
		return err
	}
	groups := strings.Fields(identity.SafetyNumber(c.SelfID, id))
	status := "NOT verified"
	if c.Verify != nil {
		if ok, _ := c.Verify.IsVerified(ctx, id); ok {
			status = "verified"
		}
	}
	c.Console.Printf("Safety number with %s (%s):", c.name(id), status)
	c.Console.Printf("")
	c.Console.Printf("    %s", strings.Join(groups[:6], "  "))
	c.Console.Printf("    %s", strings.Join(groups[6:], "  "))
	c.Console.Printf("")
	c.Console.Printf("Both of you should see exactly this number. Compare it in person or over a")
	c.Console.Printf("call you trust (not in this chat). If it matches, run: /verify %s", id[:8])
	c.Console.Printf("If it differs, someone is impersonating one of you - do not trust this peer.")
	return nil
}

func (c *CLI) cmdVerify(ctx context.Context, arg string) error {
	return c.setVerified(ctx, arg, true)
}

func (c *CLI) cmdUnverify(ctx context.Context, arg string) error {
	return c.setVerified(ctx, arg, false)
}

func (c *CLI) setVerified(ctx context.Context, arg string, verified bool) error {
	if arg == "" {
		return errUsage
	}
	if c.Verify == nil {
		return errors.New("verification is not available")
	}
	id, err := c.resolvePeer(arg)
	if err != nil {
		return err
	}
	if err := c.Verify.SetVerified(ctx, id, verified); err != nil {
		return err
	}
	if verified {
		c.Console.Printf("%s is now marked verified. Only do this after comparing the safety number (/safety).", c.name(id))
	} else {
		c.Console.Printf("%s is no longer marked verified.", c.name(id))
	}
	return nil
}

func (c *CLI) cmdWhoami(context.Context, string) error {
	c.Console.Printf("Name:    %s", c.SelfName)
	c.Console.Printf("Peer ID: %s", c.SelfID)
	c.Console.Printf("Share your peer ID so others can invite you to groups.")
	return nil
}

func (c *CLI) table(header string, rows [][]string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, header)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
	c.Console.Printf("%s", strings.TrimRight(b.String(), "\n"))
}

func (c *CLI) cmdList(ctx context.Context, _ string) error {
	verified := c.verifiedSet(ctx)
	peers := c.Peers.Peers()
	if len(peers) == 0 {
		c.Console.Printf("No peers discovered yet.")
		return nil
	}
	rows := make([][]string, 0, len(peers))
	for _, p := range peers {
		state := ""
		if c.Net.IsConnected(p.ID) {
			state = "connected"
		}
		rows = append(rows, []string{clean(p.Username, 32), p.ID[:8], p.NetworkAddress(),
			time.Since(p.LastSeen).Truncate(time.Second).String() + " ago", state, c.trust(verified, p.ID)})
	}
	c.Console.Printf("Discovered peers (%d):", len(peers))
	c.table("NAME\tID\tADDRESS\tLAST SEEN\tSTATE\tTRUST", rows)
	return nil
}

// notDiscoveredHint explains the usual reasons a peer cannot be found.
const notDiscoveredHint = "That peer has not been discovered on this network (see /list). Both must be on the same network, " +
	"and the firewall must allow UDP 9999-10008 and the chat's TCP port. " +
	"If broadcasts do not get through, connect by address: /connect <ip>[:port]"

func (c *CLI) cmdConnect(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	if address.LooksLikeAddress(arg) {
		return c.connectAddress(ctx, arg)
	}
	id, err := c.resolvePeer(arg)
	if err != nil {
		return err
	}
	if c.Net.IsConnected(id) {
		c.Console.Printf("Already connected to %s", c.name(id))
		return nil
	}
	c.Console.Printf("Connecting to %s...", c.name(id))
	if err := c.Net.ConnectToPeer(ctx, id); err != nil {
		return fmt.Errorf("could not connect: %w", err)
	}
	return nil // the connection event announces success
}

// connectAddress dials host[:port] or <id>@host[:port] directly.
func (c *CLI) connectAddress(ctx context.Context, arg string) error {
	if c.Dialer == nil {
		return errors.New("connecting by address is not available")
	}
	t, err := address.Parse(arg)
	if err != nil {
		return err
	}
	c.Console.Printf("Connecting to %s...", t)
	id, _, err := c.Dialer.ConnectToAddress(ctx, t)
	if errors.Is(err, apperrors.ErrPeerAlreadyConnected) {
		c.Console.Printf("Already connected to %s", c.name(id))
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not connect: %w", err)
	}
	// The connection event announces success. Without an expected ID, nobody
	// vouched for who answered at that address.
	if t.ID == "" {
		if _, ok := c.verifiedSet(ctx)[id]; !ok {
			c.Console.Printf("  You connected by address without an ID to check, so confirm who this is: /safety %s", id[:8])
		}
	}
	return nil
}

func (c *CLI) cmdDisconnect(_ context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	id, err := c.resolvePeer(arg)
	if err != nil {
		return err
	}
	if !c.Net.IsConnected(id) {
		c.Console.Printf("Not connected to %s", c.name(id))
		return nil
	}
	c.Net.Disconnect(id)
	return nil
}

func (c *CLI) cmdConnections(ctx context.Context, _ string) error {
	verified := c.verifiedSet(ctx)
	ids := c.Net.ConnectedPeers()
	if len(ids) == 0 {
		c.Console.Printf("No active connections.")
		return nil
	}
	rows := make([][]string, 0, len(ids))
	for _, id := range ids {
		name, _ := c.Net.PeerName(id)
		addr := "-"
		if p, ok := c.Peers.GetPeer(id); ok {
			addr = p.NetworkAddress()
		}
		rows = append(rows, []string{clean(name, 32), id[:8], addr, c.trust(verified, id)})
	}
	c.Console.Printf("Active connections (%d), all encrypted and authenticated:", len(ids))
	c.table("NAME\tID\tADDRESS\tTRUST", rows)
	return nil
}

func (c *CLI) cmdRelay(ctx context.Context, _ string) error {
	if c.Relay == nil {
		c.Console.Printf("Offline delivery is not available.")
		return nil
	}
	n, used, capacity, err := c.Relay.Usage(ctx)
	if err != nil {
		return err
	}
	if c.Relay.Enabled() {
		c.Console.Printf("Relaying is ON: holding %d encrypted message(s) for others (%s of %s).", n, ui.FormatBytes(used), ui.FormatBytes(capacity))
		c.Console.Printf("You can see who they are from and for, but never what they say.")
	} else {
		c.Console.Printf("Relaying is OFF: you do not hold messages for others (start with --relay to turn it on).")
		c.Console.Printf("You can still send to offline peers through other peers' relays.")
	}
	return nil
}

func (c *CLI) cmdStatus(context.Context, string) error {
	c.Console.Printf("Name:                %s", c.SelfName)
	c.Console.Printf("Peer ID:             %s", c.SelfID)
	c.Console.Printf("Discovered peers:    %d", len(c.Peers.Peers()))
	c.Console.Printf("Active connections:  %d", len(c.Net.ConnectedPeers()))
	c.Console.Printf("Open transfers:      %d", len(c.Files.GetActiveTransfers()))
	c.Console.Printf("Uptime:              %s", time.Since(c.StartedAt).Truncate(time.Second))
	return nil
}

// ---- Messaging -----------------------------------------------------------

func (c *CLI) cmdSend(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) < 2 {
		return errUsage
	}
	id, err := c.resolvePeer(parts[0])
	if err != nil {
		return err
	}
	err = c.Handler.SendMessage(ctx, id, parts[1])
	note, warn := "", ""
	switch {
	case messaging.IsQueued(err):
		note = "  (offline: queued with relays, delivered when they return)"
		var q *messaging.QueuedError
		if errors.As(err, &q) && q.Exposed > 0 {
			warn = fmt.Sprintf("  ! %d relay(s) could see that this is from you: too few peers are connected to hide it", q.Exposed)
		}
	case err != nil:
		return err
	}
	c.Console.Printf("[%s] you -> %s: %s%s", time.Now().Format("15:04:05"), c.name(id), clean(parts[1], 0), note)
	if warn != "" {
		c.Console.Printf("%s", warn)
	}
	return nil
}

func (c *CLI) cmdGroupMsg(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) < 2 {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, parts[0])
	if err != nil {
		return err
	}
	res, err := c.Handler.SendGroupMessage(ctx, g.ID, parts[1])
	if err != nil {
		return err
	}
	c.Console.Printf("[%s] you -> [%s]: %s", time.Now().Format("15:04:05"), clean(g.Name, models.MaxGroupNameLen), clean(parts[1], 0))
	for _, peerID := range res.Relayed {
		c.Console.Printf("  %s is offline: queued with relays, delivered when they return", c.name(peerID))
	}
	for peerID, ferr := range res.Failed {
		c.Console.Printf("  not delivered to %s: %v", c.name(peerID), ferr)
	}
	return nil
}

// ---- Files ---------------------------------------------------------------

func (c *CLI) cmdSendFile(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) < 2 {
		return errUsage
	}
	id, err := c.resolvePeer(parts[0])
	if err != nil {
		return err
	}
	path := strings.Trim(parts[1], `"'`)
	tid, err := c.Files.SendFile(ctx, id, path)
	if err != nil {
		return err
	}
	c.Console.Printf("Preparing %s for %s (transfer %s)...", clean(path, 120), c.name(id), tid[:8])
	return nil
}

func (c *CLI) cmdTransfers(context.Context, string) error {
	list := c.Files.List()
	if len(list) == 0 {
		c.Console.Printf("No file transfers.")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, t := range list {
		dir := "<-"
		if t.Direction == filetransfer.Sending {
			dir = "->"
		}
		progress := "-"
		if t.FileSize > 0 {
			progress = fmt.Sprintf("%.0f%%", float64(t.BytesTransferred)/float64(t.FileSize)*100)
		}
		status := string(t.Status)
		if t.Reason != "" {
			status += " (" + clean(t.Reason, 60) + ")"
		}
		rows = append(rows, []string{t.TransferID[:8], dir, c.name(t.PeerID), clean(t.FileName, 60), ui.FormatBytes(t.FileSize), progress, status})
	}
	c.table("ID\t\tPEER\tFILE\tSIZE\tDONE\tSTATUS", rows)
	return nil
}

func (c *CLI) cmdGetFile(_ context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	st, err := c.Files.Accept(arg)
	if err != nil {
		return err
	}
	c.Console.Printf("Accepted %q from %s; receiving into the download directory.", clean(st.FileName, 80), c.name(st.PeerID))
	return nil
}

func (c *CLI) cmdRejectFile(_ context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	st, err := c.Files.Reject(arg)
	if err != nil {
		return err
	}
	c.Console.Printf("Declined %q from %s.", clean(st.FileName, 80), c.name(st.PeerID))
	return nil
}

func (c *CLI) cmdCancel(_ context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	st, err := c.Files.Cancel(arg)
	if err != nil {
		return err
	}
	c.Console.Printf("Cancelled transfer of %q.", clean(st.FileName, 80))
	return nil
}

// ---- Groups --------------------------------------------------------------

func (c *CLI) cmdCreateGroup(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	name, desc, _ := strings.Cut(arg, "|")
	g, err := c.Groups.CreateGroup(ctx, strings.TrimSpace(name), strings.TrimSpace(desc))
	if err != nil {
		return err
	}
	c.Console.Printf("Created group %q. ID: %s", g.Name, g.ID)
	c.Console.Printf("Invite people with: /invite %s <peer>", g.ID[:12])
	return nil
}

func (c *CLI) cmdGroups(ctx context.Context, _ string) error {
	groups, err := c.Groups.GetUserGroups(ctx)
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		c.Console.Printf("You are not a member of any groups.")
		return nil
	}
	rows := make([][]string, 0, len(groups))
	for _, g := range groups {
		role := "member"
		if g.CreatedBy == c.SelfID {
			role = "creator"
		}
		rows = append(rows, []string{clean(g.Name, models.MaxGroupNameLen), g.ID, role, clean(g.Description, 60)})
	}
	c.table("NAME\tID\tROLE\tDESCRIPTION", rows)
	return nil
}

func (c *CLI) cmdMembers(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, arg)
	if err != nil {
		return err
	}
	members, err := c.Groups.GetGroupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(members))
	for _, m := range members {
		state := ""
		switch {
		case m.PeerID == c.SelfID:
			state = "you"
		case c.Net.IsConnected(m.PeerID):
			state = "connected"
		}
		rows = append(rows, []string{clean(m.Username, 32), m.PeerID[:8], m.Role, state})
	}
	c.Console.Printf("Members of %s (%d):", clean(g.Name, models.MaxGroupNameLen), len(members))
	c.table("NAME\tID\tROLE\t", rows)
	return nil
}

func (c *CLI) cmdInvite(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) != 2 {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, parts[0])
	if err != nil {
		return err
	}
	peerID, err := c.resolvePeer(parts[1])
	if err != nil {
		return err
	}
	if err := c.Handler.InviteToGroup(ctx, g.ID, peerID); err != nil {
		return err
	}
	c.Console.Printf("Invited %s to %q (valid for %s).", c.name(peerID), clean(g.Name, models.MaxGroupNameLen), messaging.InviteTTL)
	return nil
}

func (c *CLI) cmdInvites(ctx context.Context, _ string) error {
	invites, err := c.Groups.GetPendingInvites(ctx)
	if err != nil {
		return err
	}
	if len(invites) == 0 {
		c.Console.Printf("No pending invitations.")
		return nil
	}
	rows := make([][]string, 0, len(invites))
	for _, inv := range invites {
		rows = append(rows, []string{clean(inv.GroupName, models.MaxGroupNameLen), inv.GroupID, c.name(inv.InviterID),
			time.Until(inv.ExpiresAt).Truncate(time.Minute).String()})
	}
	c.table("GROUP\tID\tFROM\tEXPIRES IN", rows)
	return nil
}

func (c *CLI) pendingInviteGroup(ctx context.Context, query string) (string, error) {
	invites, err := c.Groups.GetPendingInvites(ctx)
	if err != nil {
		return "", err
	}
	inv, err := pickGroup(query, invites, func(i *models.GroupInvite) (string, string) { return i.GroupID, i.GroupName })
	if err != nil {
		return "", errors.New("no pending invitation matches " + strconv.Quote(query) + " (see /invites)")
	}
	return inv.GroupID, nil
}

func (c *CLI) cmdAccept(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	gid, err := c.pendingInviteGroup(ctx, arg)
	if err != nil {
		return err
	}
	g, err := c.Handler.AcceptInvite(ctx, gid)
	if g != nil {
		c.Console.Printf("Joined group %q.", clean(g.Name, models.MaxGroupNameLen))
	}
	return err
}

func (c *CLI) cmdDecline(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	gid, err := c.pendingInviteGroup(ctx, arg)
	if err != nil {
		return err
	}
	if err := c.Handler.DeclineInvite(ctx, gid); err != nil {
		return err
	}
	c.Console.Printf("Declined the invitation.")
	return nil
}

func (c *CLI) cmdLeave(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, arg)
	if err != nil {
		return err
	}
	if err := c.Handler.LeaveGroup(ctx, g.ID); err != nil {
		return err
	}
	c.Console.Printf("Left group %q.", clean(g.Name, models.MaxGroupNameLen))
	return nil
}

func (c *CLI) cmdKick(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) != 2 {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, parts[0])
	if err != nil {
		return err
	}
	members, err := c.Groups.GetGroupMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	// Members may not be discovered peers, so resolve within the roster too.
	peerID, err := pickGroupMember(parts[1], members)
	if err != nil {
		return err
	}
	if err := c.Handler.RemoveMember(ctx, g.ID, peerID); err != nil {
		return err
	}
	c.Console.Printf("Removed %s from %q.", c.name(peerID), clean(g.Name, models.MaxGroupNameLen))
	return nil
}

func pickGroupMember(query string, members []*models.GroupMember) (string, error) {
	m, err := pickGroup(query, members, func(m *models.GroupMember) (string, string) { return m.PeerID, m.Username })
	if err != nil {
		return "", errors.New("no member matches " + strconv.Quote(query))
	}
	return m.PeerID, nil
}

// ---- History -------------------------------------------------------------

func (c *CLI) printMessages(msgs []*models.ChatMessage, groupNames map[string]string) {
	for _, m := range services.Chronological(msgs) {
		mark := ""
		if m.From == c.SelfID && !m.Delivered {
			mark = "  (not delivered)"
		}
		where := ""
		if m.IsGroupMessage() {
			label := groupNames[m.GroupID]
			if label == "" {
				label = m.GroupID[:min(8, len(m.GroupID))]
			}
			where = "[" + clean(label, models.MaxGroupNameLen) + "] "
		}
		c.Console.Printf("[%s] %s%s: %s%s", m.Timestamp.Format("2006-01-02 15:04:05"), where, c.name(m.From), clean(m.Message, 0), mark)
	}
}

func (c *CLI) groupNameIndex(ctx context.Context) map[string]string {
	idx := map[string]string{}
	if groups, err := c.Groups.GetUserGroups(ctx); err == nil {
		for _, g := range groups {
			idx[g.ID] = g.Name
		}
	}
	return idx
}

func (c *CLI) cmdHistory(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) == 0 {
		return errUsage
	}
	id, err := c.resolvePeer(parts[0])
	if err != nil {
		return err
	}
	n := defaultCount
	if len(parts) == 2 {
		if n, err = parseCount(parts[1]); err != nil {
			return err
		}
	}
	msgs, err := c.History.GetDirectMessageHistory(ctx, id, storage.Page{Limit: n})
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		c.Console.Printf("No messages with %s.", c.name(id))
		return nil
	}
	c.Console.Printf("Conversation with %s (newest %d):", c.name(id), len(msgs))
	c.printMessages(msgs, nil)
	return nil
}

func (c *CLI) cmdGroupHistory(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) == 0 {
		return errUsage
	}
	g, err := c.resolveGroup(ctx, parts[0])
	if err != nil {
		return err
	}
	n := defaultCount
	if len(parts) == 2 {
		if n, err = parseCount(parts[1]); err != nil {
			return err
		}
	}
	msgs, err := c.History.GetGroupMessageHistory(ctx, g.ID, storage.Page{Limit: n})
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		c.Console.Printf("No messages in %q.", clean(g.Name, models.MaxGroupNameLen))
		return nil
	}
	c.Console.Printf("Group %q (newest %d):", clean(g.Name, models.MaxGroupNameLen), len(msgs))
	c.printMessages(msgs, map[string]string{g.ID: g.Name})
	return nil
}

func (c *CLI) cmdRecent(ctx context.Context, arg string) error {
	n, err := parseCount(arg)
	if err != nil {
		return err
	}
	msgs, err := c.History.GetRecentMessages(ctx, n)
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		c.Console.Printf("No messages yet.")
		return nil
	}
	c.Console.Printf("Recent messages:")
	c.printMessages(msgs, c.groupNameIndex(ctx))
	return nil
}

func (c *CLI) cmdSearch(ctx context.Context, arg string) error {
	if arg == "" {
		return errUsage
	}
	msgs, err := c.History.SearchMessages(ctx, arg, storage.Page{Limit: defaultCount})
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		c.Console.Printf("No messages contain %q.", clean(arg, 60))
		return nil
	}
	c.Console.Printf("%d match(es):", len(msgs))
	c.printMessages(msgs, c.groupNameIndex(ctx))
	return nil
}

func (c *CLI) cmdExport(ctx context.Context, arg string) error {
	parts := splitN(arg, 2)
	if len(parts) < 2 {
		return errUsage
	}
	target, rest := parts[0], parts[1]

	// "<file> [format]": a trailing known format word is the format.
	format, path := "text", rest
	if i := strings.LastIndexAny(rest, " 	"); i > 0 {
		if last := strings.ToLower(strings.TrimSpace(rest[i:])); slices.Contains(services.ExportFormats, last) {
			format, path = last, strings.TrimSpace(rest[:i])
		}
	}
	path = strings.Trim(path, `"'`)

	// A group (by name or ID) first, then a peer.
	conversation, isGroup := "", false
	if g, err := c.resolveGroup(ctx, target); err == nil {
		conversation, isGroup = g.ID, true
	} else if id, perr := c.resolvePeer(target); perr == nil {
		conversation = id
	} else {
		return fmt.Errorf("%q is neither a group nor a peer", target)
	}

	// Never overwrite: an export is a copy of private data.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	if err := c.History.ExportConversation(ctx, f, conversation, isGroup, format); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	c.Console.Printf("Exported to %s (%s).", path, format)
	return nil
}
