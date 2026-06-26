package imap

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// startServer launches a one-shot fake IMAP server serving the given messages
// (keyed by sequence number) for FETCH.
func startServer(t *testing.T, messages map[int]string) string {
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
		io.WriteString(conn, "* OK IMAP ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			tag := fields[0]
			switch strings.ToUpper(fields[1]) {
			case "LOGIN":
				io.WriteString(conn, tag+" OK logged in\r\n")
			case "SELECT":
				io.WriteString(conn, "* 2 EXISTS\r\n")
				io.WriteString(conn, tag+" OK [READ-WRITE] SELECT completed\r\n")
			case "SEARCH":
				io.WriteString(conn, "* SEARCH 1 2\r\n")
				io.WriteString(conn, tag+" OK SEARCH completed\r\n")
			case "FETCH":
				seq, _ := strconv.Atoi(fields[2])
				body := messages[seq]
				fmt.Fprintf(conn, "* %d FETCH (BODY[] {%d}\r\n", seq, len(body))
				io.WriteString(conn, body)
				io.WriteString(conn, ")\r\n")
				io.WriteString(conn, tag+" OK FETCH completed\r\n")
			case "STORE":
				io.WriteString(conn, tag+" OK STORE completed\r\n")
			case "EXPUNGE":
				io.WriteString(conn, tag+" OK EXPUNGE completed\r\n")
			case "LOGOUT":
				io.WriteString(conn, "* BYE\r\n")
				io.WriteString(conn, tag+" OK LOGOUT completed\r\n")
				return
			default:
				io.WriteString(conn, tag+" BAD unknown\r\n")
			}
		}
	}()
	return ln.Addr().String()
}

func TestIMAPFlow(t *testing.T) {
	msgs := map[int]string{
		1: "Subject: One\r\n\r\nbody one\r\n",
		2: "Subject: Two\r\n\r\n..dotline stays\r\nbody two\r\n",
	}
	addr := startServer(t, msgs)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	c, err := Dial(nil, host, port, 5, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Login("u", "p"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	count, err := c.Select("INBOX")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	pattern := filepath.Join(t.TempDir(), "cerbmail_XXXXXX")
	for i := 1; i <= 2; i++ {
		fn, err := c.Fetch(pattern)
		if err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != msgs[i] {
			t.Errorf("message %d = %q, want %q", i, data, msgs[i])
		}
	}

	// no more messages
	if fn, _ := c.Fetch(pattern); fn != "" {
		t.Errorf("expected no third message, got %q", fn)
	}

	if err := c.Delete(); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := c.Expunge(); err != nil {
		t.Errorf("Expunge: %v", err)
	}
	if err := c.Logout(); err != nil {
		t.Errorf("Logout: %v", err)
	}
}

func TestParseLiteral(t *testing.T) {
	cases := []struct {
		in    string
		size  int64
		isLit bool
	}{
		{"* 1 FETCH (BODY[] {26}\r\n", 26, true},
		{"* 1 FETCH (BODY[] {26+}\r\n", 26, true},
		{"A001 OK done\r\n", 0, false},
		{"* SEARCH 1 2 3\r\n", 0, false},
	}
	for _, c := range cases {
		size, ok := parseLiteral(c.in)
		if ok != c.isLit || size != c.size {
			t.Errorf("parseLiteral(%q) = %d,%v want %d,%v", c.in, size, ok, c.size, c.isLit)
		}
	}
}
