// Package pop3 is a minimal POP3 client (RFC 1939) over net.Conn, replacing the
// C csocket/cpop3 layer. It supports the subset the parser uses: greeting,
// USER/PASS, STAT, LIST, RETR (streamed to a temp file with dot-unstuffing),
// DELE, and QUIT.
package pop3

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"cerb2-goparser/internal/clog"
)

// Client is a connected POP3 session.
type Client struct {
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration
	log     *clog.Logger
	msgs    []int // message numbers from LIST
	idx     int   // RETR cursor into msgs
	last    int   // last RETR'd message number (DELE target)
}

// Dial connects to host:port, applies the per-read timeout, and reads the
// server greeting.
func Dial(log *clog.Logger, host string, port, timeoutSec int) (*Client, error) {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	timeout := time.Duration(timeoutSec) * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, r: bufio.NewReader(conn), timeout: timeout, log: log}
	line, err := c.readLine()
	if err != nil {
		c.Close()
		return nil, err
	}
	if !isOK(line) {
		c.Close()
		return nil, fmt.Errorf("pop3 greeting: %s", strings.TrimSpace(line))
	}
	return c, nil
}

func (c *Client) send(s string) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	_, err := io.WriteString(c.conn, s+"\r\n")
	return err
}

func (c *Client) readLine() (string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.r.ReadString('\n')
}

func isOK(line string) bool { return strings.HasPrefix(line, "+OK") }

// command sends one command and returns its single-line status reply, erroring
// on -ERR.
func (c *Client) command(s string) (string, error) {
	if err := c.send(s); err != nil {
		return "", err
	}
	line, err := c.readLine()
	if err != nil {
		return "", err
	}
	if !isOK(line) {
		return "", fmt.Errorf("%s: %s", strings.Fields(s)[0], strings.TrimSpace(line))
	}
	return line, nil
}

// User sends the USER command.
func (c *Client) User(user string) error {
	_, err := c.command("USER " + user)
	return err
}

// Pass sends the PASS command.
func (c *Client) Pass(pass string) error {
	_, err := c.command("PASS " + pass)
	return err
}

// Stat returns the message count and, when non-zero, loads the message numbers
// via LIST so Retr can iterate them.
func (c *Client) Stat() (int, error) {
	line, err := c.command("STAT")
	if err != nil {
		return 0, err
	}
	var count, size int
	_, _ = fmt.Sscanf(line, "+OK %d %d", &count, &size)
	if count > 0 {
		if err := c.list(); err != nil {
			return count, err
		}
	}
	return count, nil
}

func (c *Client) list() error {
	if _, err := c.command("LIST"); err != nil {
		return err
	}
	for {
		l, err := c.readLine()
		if err != nil {
			return err
		}
		if strings.TrimRight(l, "\r\n") == "." {
			break
		}
		var msgno int
		if n, _ := fmt.Sscanf(l, "%d", &msgno); n == 1 {
			c.msgs = append(c.msgs, msgno)
		}
	}
	return nil
}

// Retr downloads the next listed message into a temp file (created from
// tmpPattern) and returns its path. It returns "" when no messages remain.
// Lines are dot-unstuffed and the body ends at the "\r\n.\r\n" terminator; a
// read timeout is treated as end-of-message, matching the C leniency.
func (c *Client) Retr(tmpPattern string) (string, error) {
	if c.idx >= len(c.msgs) {
		return "", nil
	}
	msgno := c.msgs[c.idx]
	c.idx++
	c.last = msgno

	if _, err := c.command(fmt.Sprintf("RETR %d", msgno)); err != nil {
		return "", err
	}

	dir, prefix := splitPattern(tmpPattern)
	f, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	for {
		l, err := c.readLine()
		if err != nil {
			break // timeout/EOF => assume message complete
		}
		if strings.TrimRight(l, "\r\n") == "." {
			break // terminator
		}
		if strings.HasPrefix(l, ".") {
			l = l[1:] // un-stuff leading dot
		}
		if _, werr := io.WriteString(f, l); werr != nil {
			return "", werr
		}
	}
	return f.Name(), nil
}

// Dele marks the most recently retrieved message for deletion.
func (c *Client) Dele() error {
	if c.last == 0 {
		return nil
	}
	_, err := c.command(fmt.Sprintf("DELE %d", c.last))
	return err
}

// Quit sends QUIT and closes the connection.
func (c *Client) Quit() error {
	_ = c.send("QUIT")
	_, _ = c.readLine()
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
