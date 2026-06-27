// Package imap is a minimal IMAP4rev1 client (RFC 3501) over net.Conn, with
// optional implicit TLS or STARTTLS. It supports the subset the parser needs:
// login, select a mailbox, UID SEARCH with a caller-supplied criteria, fetch
// each message body to a temp file, mark messages deleted by UID, expunge, and
// logout.
//
// The package is an abstraction boundary: the app depends only on the small
// Client method set, so this hand-rolled implementation can be swapped for a
// full library (e.g. github.com/emersion/go-imap) later without touching the
// app, should OAuth2/SASL or richer IMAP features ever be required.
package imap

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"cerb2-goparser/internal/clog"
)

// Client is a connected IMAP session.
type Client struct {
	conn        net.Conn
	r           *bufio.Reader
	timeout     time.Duration
	log         *clog.Logger
	host        string
	tag         int
	uids        []int  // message UIDs from UID SEARCH
	idx         int    // Fetch cursor into uids
	last        int    // last fetched UID (Delete/STORE target)
	uidValidity uint32 // mailbox UIDVALIDITY reported by SELECT
}

// Dial connects to host:port. When tlsConf is non-nil the connection uses
// implicit TLS (ServerName defaults to host). It reads the server greeting.
func Dial(log *clog.Logger, host string, port, timeoutSec int, tlsConf *tls.Config) (*Client, error) {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	timeout := time.Duration(timeoutSec) * time.Second
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if tlsConf != nil {
		tc := tlsConf.Clone()
		if tc.ServerName == "" {
			tc.ServerName = host
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tc)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	c := &Client{conn: conn, r: bufio.NewReader(conn), timeout: timeout, log: log, host: host}
	line, err := c.readLine()
	if err != nil {
		c.Close()
		return nil, err
	}
	if !strings.HasPrefix(line, "* OK") {
		c.Close()
		return nil, fmt.Errorf("imap greeting: %s", strings.TrimSpace(line))
	}
	return c, nil
}

func (c *Client) nextTag() string {
	c.tag++
	return fmt.Sprintf("A%03d", c.tag)
}

func (c *Client) send(line string) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	_, err := io.WriteString(c.conn, line+"\r\n")
	return err
}

func (c *Client) readLine() (string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.r.ReadString('\n')
}

// cmd sends a tagged command and returns the untagged response lines, erroring
// on a NO/BAD completion. It is line-based and must not be used for responses
// carrying literals (FETCH BODY[] is handled by Fetch).
func (c *Client) cmd(format string, args ...any) ([]string, error) {
	tag := c.nextTag()
	command := fmt.Sprintf(format, args...)
	if err := c.send(tag + " " + command); err != nil {
		return nil, err
	}
	var untagged []string
	for {
		line, err := c.readLine()
		if err != nil {
			return untagged, err
		}
		if strings.HasPrefix(line, tag+" ") {
			status := strings.TrimSpace(line[len(tag)+1:])
			if strings.HasPrefix(status, "OK") {
				return untagged, nil
			}
			return untagged, fmt.Errorf("%s: %s", strings.Fields(command)[0], status)
		}
		untagged = append(untagged, line)
	}
}

// StartTLS upgrades a plaintext connection to TLS via the STARTTLS command. It
// must be called after Dial (with a nil tlsConf) and before Login. As a guard
// against a buffering/injection attack, it refuses to proceed if the server
// sent anything after the STARTTLS reply but before the handshake.
func (c *Client) StartTLS(tlsConf *tls.Config) error {
	if _, err := c.cmd("STARTTLS"); err != nil {
		return err
	}
	if c.r.Buffered() > 0 {
		return fmt.Errorf("imap: unexpected data buffered after STARTTLS")
	}
	tc := &tls.Config{}
	if tlsConf != nil {
		tc = tlsConf.Clone()
	}
	if tc.ServerName == "" {
		tc.ServerName = c.host
	}
	tlsConn := tls.Client(c.conn, tc)
	_ = tlsConn.SetDeadline(time.Now().Add(c.timeout))
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	c.conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
	return nil
}

// Login authenticates with LOGIN.
func (c *Client) Login(user, pass string) error {
	_, err := c.cmd("LOGIN %s %s", quote(user), quote(pass))
	return err
}

// UIDValidity returns the mailbox UIDVALIDITY reported by the last Select. It is
// stable across sessions while the mailbox is not recreated, so callers may pair
// it with fetched UIDs to recognize messages across runs.
func (c *Client) UIDValidity() uint32 { return c.uidValidity }

// Select opens a mailbox read-write, records its UIDVALIDITY, and loads the UIDs
// of the messages matching criteria via UID SEARCH (criteria defaults to "ALL").
// It returns the number of matching messages.
func (c *Client) Select(mailbox, criteria string) (int, error) {
	if mailbox == "" {
		mailbox = "INBOX"
	}
	if criteria == "" {
		criteria = "ALL"
	}
	selResp, err := c.cmd("SELECT %s", quote(mailbox))
	if err != nil {
		return 0, err
	}
	for _, line := range selResp {
		if v, ok := parseUIDValidity(line); ok {
			c.uidValidity = v
		}
	}

	uids, err := c.uidSearch(criteria)
	if err != nil {
		return 0, err
	}
	c.uids = uids
	return len(c.uids), nil
}

// uidSearch runs UID SEARCH with the given criteria and returns the matching
// UIDs.
func (c *Client) uidSearch(criteria string) ([]int, error) {
	untagged, err := c.cmd("UID SEARCH %s", criteria)
	if err != nil {
		return nil, err
	}
	var uids []int
	for _, line := range untagged {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 2 && f[0] == "*" && strings.EqualFold(f[1], "SEARCH") {
			for _, num := range f[2:] {
				if v, err := strconv.Atoi(num); err == nil {
					uids = append(uids, v)
				}
			}
		}
	}
	return uids, nil
}

// UIDs returns a copy of the UIDs matched by the last Select.
func (c *Client) UIDs() []int {
	out := make([]int, len(c.uids))
	copy(out, c.uids)
	return out
}

// SearchAllUIDs returns every UID currently in the selected mailbox (UID SEARCH
// ALL), used to prune stored state of messages that no longer exist.
func (c *Client) SearchAllUIDs() ([]int, error) {
	return c.uidSearch("ALL")
}

// Fetch downloads the next matched message body into a temp file and returns its
// path, or "" when no messages remain. It is a convenience wrapper over FetchUID
// that iterates the UIDs from the last Select.
func (c *Client) Fetch(tmpPattern string) (string, error) {
	if c.idx >= len(c.uids) {
		return "", nil
	}
	uid := c.uids[c.idx]
	c.idx++
	return c.FetchUID(uid, tmpPattern)
}

// FetchUID downloads the message with the given UID into a temp file (created
// from tmpPattern) and returns its path. It uses BODY.PEEK[] so the \Seen flag
// is not changed, and records the UID as the Delete target.
func (c *Client) FetchUID(uid int, tmpPattern string) (string, error) {
	c.last = uid

	tag := c.nextTag()
	if err := c.send(fmt.Sprintf("%s UID FETCH %d BODY.PEEK[]", tag, uid)); err != nil {
		return "", err
	}

	dir, prefix := splitPattern(tmpPattern)
	f, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	for {
		line, err := c.readLine()
		if err != nil {
			return "", err
		}
		if size, ok := parseLiteral(line); ok {
			_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
			if _, err := io.CopyN(f, c.r, size); err != nil {
				return "", err
			}
			continue
		}
		if strings.HasPrefix(line, tag+" ") {
			status := strings.TrimSpace(line[len(tag)+1:])
			if !strings.HasPrefix(status, "OK") {
				return "", fmt.Errorf("UID FETCH %d: %s", uid, status)
			}
			break
		}
	}
	return f.Name(), nil
}

// Delete marks the most recently fetched message \Deleted by UID. Call Expunge
// once after the fetch loop to actually remove flagged messages.
func (c *Client) Delete() error {
	if c.last == 0 {
		return nil
	}
	_, err := c.cmd(`UID STORE %d +FLAGS (\Deleted)`, c.last)
	return err
}

// Expunge permanently removes all \Deleted messages from the mailbox.
func (c *Client) Expunge() error {
	_, err := c.cmd("EXPUNGE")
	return err
}

// Logout sends LOGOUT and closes the connection.
func (c *Client) Logout() error {
	_, _ = c.cmd("LOGOUT")
	return c.Close()
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// parseLiteral returns the byte count of a trailing IMAP literal "{n}" (or
// "{n+}") on line, and whether one is present.
func parseLiteral(line string) (int64, bool) {
	s := strings.TrimRight(line, "\r\n")
	if !strings.HasSuffix(s, "}") {
		return 0, false
	}
	open := strings.LastIndexByte(s, '{')
	if open < 0 {
		return 0, false
	}
	num := strings.TrimSuffix(s[open+1:len(s)-1], "+")
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// parseUIDValidity extracts the value of a "[UIDVALIDITY n]" response code from
// a SELECT untagged line, if present.
func parseUIDValidity(line string) (uint32, bool) {
	const marker = "[UIDVALIDITY "
	i := strings.Index(strings.ToUpper(line), marker)
	if i < 0 {
		return 0, false
	}
	rest := line[i+len(marker):]
	j := strings.IndexByte(rest, ']')
	if j < 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(rest[:j]), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// quote returns s as an IMAP quoted string.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func splitPattern(pat string) (dir, prefix string) {
	if i := strings.LastIndexAny(pat, "/\\"); i >= 0 {
		dir = pat[:i]
		prefix = pat[i+1:]
	} else {
		dir = "."
		prefix = pat
	}
	prefix = strings.TrimRight(prefix, "X")
	if prefix == "" {
		prefix = "cerbmail_"
	}
	if dir == "" {
		dir = "."
	}
	return dir, prefix
}
