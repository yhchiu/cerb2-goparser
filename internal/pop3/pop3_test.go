package pop3

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// startServer launches a one-shot fake POP3 server returning retrBody for RETR.
func startServer(t *testing.T, retrBody string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		io.WriteString(conn, "+OK POP3 ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "USER"), strings.HasPrefix(cmd, "PASS"):
				io.WriteString(conn, "+OK\r\n")
			case cmd == "STAT":
				io.WriteString(conn, "+OK 1 100\r\n")
			case cmd == "LIST":
				io.WriteString(conn, "+OK 1 messages\r\n1 100\r\n.\r\n")
			case strings.HasPrefix(cmd, "RETR"):
				io.WriteString(conn, "+OK 100 octets\r\n")
				io.WriteString(conn, retrBody)
			case strings.HasPrefix(cmd, "DELE"):
				io.WriteString(conn, "+OK deleted\r\n")
			case cmd == "QUIT":
				io.WriteString(conn, "+OK bye\r\n")
				return
			default:
				io.WriteString(conn, "-ERR unknown\r\n")
			}
		}
	}()
	return ln.Addr().String()
}

func TestPOP3Flow(t *testing.T) {
	body := "Subject: Test\r\n\r\n..dotline\r\nNormal\r\n.\r\n"
	addr := startServer(t, body)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	c, err := Dial(nil, host, port, 5)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.User("u"); err != nil {
		t.Fatalf("User: %v", err)
	}
	if err := c.Pass("p"); err != nil {
		t.Fatalf("Pass: %v", err)
	}
	count, err := c.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if count != 1 {
		t.Fatalf("Stat count = %d, want 1", count)
	}

	fn, err := c.Retr(filepath.Join(t.TempDir(), "cerbmail_XXXXXX"))
	if err != nil {
		t.Fatalf("Retr: %v", err)
	}
	data, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	want := "Subject: Test\r\n\r\n.dotline\r\nNormal\r\n"
	if string(data) != want {
		t.Errorf("retrieved = %q, want %q", data, want)
	}

	// no more messages
	if fn2, _ := c.Retr(filepath.Join(t.TempDir(), "cerbmail_XXXXXX")); fn2 != "" {
		t.Errorf("expected no second message, got %q", fn2)
	}

	if err := c.Dele(); err != nil {
		t.Errorf("Dele: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Errorf("Quit: %v", err)
	}
}

func TestPOP3AuthError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		io.WriteString(conn, "+OK ready\r\n")
		r.ReadString('\n') // USER
		io.WriteString(conn, "-ERR no such user\r\n")
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	c, err := Dial(nil, host, port, 5)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.User("bad"); err == nil {
		t.Error("expected USER error")
	}
	c.Close()
}
