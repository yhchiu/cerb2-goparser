// Package imap is a minimal IMAP4rev1 client (RFC 3501) over net.Conn, with
// optional implicit TLS. It supports the subset the parser needs: login, select
// a mailbox, search for messages, fetch each message body to a temp file, mark
// messages deleted, expunge, and logout.
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
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration
	log     *clog.Logger
	tag     int
	msgs    []int // sequence numbers from SEARCH
	idx     int   // Fetch cursor into msgs
	last    int   // last fetched sequence number (Delete target)
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

	c := &Client{conn: conn, r: bufio.NewReader(conn), timeout: timeout, log: log}
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

// Login authenticates with LOGIN.
func (c *Client) Login(user, pass string) error {
	_, err := c.cmd("LOGIN %s %s", quote(user), quote(pass))
	return err
}

// Select opens a mailbox read-write and loads the sequence numbers of all
// messages via SEARCH ALL, returning the message count.
func (c *Client) Select(mailbox string) (int, error) {
	if mailbox == "" {
		mailbox = "INBOX"
	}
	if _, err := c.cmd("SELECT %s", quote(mailbox)); err != nil {
		return 0, err
	}
	untagged, err := c.cmd("SEARCH ALL")
	if err != nil {
		return 0, err
	}
	for _, line := range untagged {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 2 && f[0] == "*" && strings.EqualFold(f[1], "SEARCH") {
			for _, num := range f[2:] {
				if v, err := strconv.Atoi(num); err == nil {
					c.msgs = append(c.msgs, v)
				}
			}
		}
	}
	return len(c.msgs), nil
}

// Fetch downloads the next message body into a temp file (created from
// tmpPattern) and returns its path, or "" when no messages remain. It uses
// BODY.PEEK[] so the \Seen flag is not changed.
func (c *Client) Fetch(tmpPattern string) (string, error) {
	if c.idx >= len(c.msgs) {
		return "", nil
	}
	seq := c.msgs[c.idx]
	c.idx++
	c.last = seq

	tag := c.nextTag()
	if err := c.send(fmt.Sprintf("%s FETCH %d BODY.PEEK[]", tag, seq)); err != nil {
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
				return "", fmt.Errorf("FETCH %d: %s", seq, status)
			}
			break
		}
	}
	return f.Name(), nil
}

// Delete marks the most recently fetched message \Deleted. Call Expunge once
// after the fetch loop to actually remove flagged messages (expunging mid-loop
// would renumber sequence numbers).
func (c *Client) Delete() error {
	if c.last == 0 {
		return nil
	}
	_, err := c.cmd(`STORE %d +FLAGS (\Deleted)`, c.last)
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
