package imap

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// serveIMAP runs the fake-server command loop, serving messages (keyed by UID)
// for FETCH. It understands the "UID" command prefix.
func serveIMAP(w io.Writer, r *bufio.Reader, messages map[int]string) {
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
		cmd := strings.ToUpper(fields[1])
		args := fields[2:]
		if cmd == "UID" && len(fields) >= 3 {
			cmd = strings.ToUpper(fields[2])
			args = fields[3:]
		}
		switch cmd {
		case "LOGIN":
			io.WriteString(w, tag+" OK logged in\r\n")
		case "SELECT":
			io.WriteString(w, "* 2 EXISTS\r\n")
			io.WriteString(w, "* OK [UIDVALIDITY 42] mailbox open\r\n")
			io.WriteString(w, tag+" OK [READ-WRITE] SELECT completed\r\n")
		case "SEARCH":
			io.WriteString(w, "* SEARCH 1001 1002\r\n")
			io.WriteString(w, tag+" OK SEARCH completed\r\n")
		case "FETCH":
			uid, _ := strconv.Atoi(args[0])
			body := messages[uid]
			fmt.Fprintf(w, "* 1 FETCH (UID %d BODY[] {%d}\r\n", uid, len(body))
			io.WriteString(w, body)
			io.WriteString(w, ")\r\n")
			io.WriteString(w, tag+" OK FETCH completed\r\n")
		case "STORE":
			io.WriteString(w, tag+" OK STORE completed\r\n")
		case "EXPUNGE":
			io.WriteString(w, tag+" OK EXPUNGE completed\r\n")
		case "LOGOUT":
			io.WriteString(w, "* BYE\r\n")
			io.WriteString(w, tag+" OK LOGOUT completed\r\n")
			return
		default:
			io.WriteString(w, tag+" BAD unknown\r\n")
		}
	}
}

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
		serveIMAP(conn, r, messages)
	}()
	return ln.Addr().String()
}

// startSTARTTLSServer answers the greeting and STARTTLS in plaintext, upgrades
// to TLS with cert, then serves the IMAP session over TLS.
func startSTARTTLSServer(t *testing.T, cert tls.Certificate, messages map[int]string) string {
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
		io.WriteString(conn, "* OK ready\r\n")
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToUpper(fields[1]) != "STARTTLS" {
			return
		}
		io.WriteString(conn, fields[0]+" OK begin TLS\r\n")
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		serveIMAP(tc, bufio.NewReader(tc), messages)
	}()
	return ln.Addr().String()
}

func dialFields(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestIMAPFlow(t *testing.T) {
	msgs := map[int]string{
		1001: "Subject: One\r\n\r\nbody one\r\n",
		1002: "Subject: Two\r\n\r\n..dotline stays\r\nbody two\r\n",
	}
	host, port := dialFields(startServer(t, msgs))

	c, err := Dial(nil, host, port, 5, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Login("u", "p"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	count, err := c.Select("INBOX", "ALL")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	if c.UIDValidity() != 42 {
		t.Errorf("UIDValidity = %d, want 42", c.UIDValidity())
	}

	pattern := filepath.Join(t.TempDir(), "cerbmail_XXXXXX")
	for _, uid := range []int{1001, 1002} {
		fn, err := c.Fetch(pattern)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != msgs[uid] {
			t.Errorf("uid %d = %q, want %q", uid, data, msgs[uid])
		}
	}
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

func TestIMAPStartTLS(t *testing.T) {
	cert := selfSignedCert(t)
	msgs := map[int]string{1001: "Subject: x\r\n\r\nsecure body\r\n"}
	host, port := dialFields(startSTARTTLSServer(t, cert, msgs))

	c, err := Dial(nil, host, port, 5, nil) // plaintext first
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	if err := c.Login("u", "p"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	count, err := c.Select("INBOX", "UNSEEN") // custom search criteria
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if count != 2 { // fake server always returns 1001 1002
		t.Fatalf("count = %d, want 2", count)
	}
	fn, err := c.Fetch(filepath.Join(t.TempDir(), "cerbmail_XXXXXX"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	data, _ := os.ReadFile(fn)
	if string(data) != msgs[1001] {
		t.Errorf("fetched %q, want %q", data, msgs[1001])
	}
	_ = c.Logout()
}

func TestParseLiteral(t *testing.T) {
	cases := []struct {
		in    string
		size  int64
		isLit bool
	}{
		{"* 1 FETCH (BODY[] {26}\r\n", 26, true},
		{"* 1 FETCH (UID 5 BODY[] {26+}\r\n", 26, true},
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

func TestParseUIDValidity(t *testing.T) {
	if v, ok := parseUIDValidity("* OK [UIDVALIDITY 123] ready"); !ok || v != 123 {
		t.Errorf("got %d,%v want 123,true", v, ok)
	}
	if _, ok := parseUIDValidity("* OK [READ-WRITE] selected"); ok {
		t.Error("did not expect a UIDVALIDITY")
	}
}

// TestCmdSkipsEmbeddedLiteral verifies that cmd() treats an IMAP literal's
// payload as opaque data rather than re-parsing it as protocol lines. The
// literal's payload here is crafted to contain text that looks exactly like
// this command's own tagged completion; a line-based reader with no literal
// awareness would mistake it for the real reply, return early, and leave the
// actual completion (plus the closing ")\r\n") unread in the buffer to corrupt
// whatever command is sent next on the same connection.
func TestCmdSkipsEmbeddedLiteral(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		io.WriteString(conn, "* OK ready\r\n")

		// First command: reply with an untagged FETCH whose literal payload is
		// itself a forged tagged-OK line for this same command.
		line, _ := r.ReadString('\n')
		tag := strings.Fields(line)[0]
		forged := tag + " OK forged\r\n"
		fmt.Fprintf(conn, "* 1 FETCH (FLAGS {%d}\r\n%s)\r\n", len(forged), forged)
		io.WriteString(conn, tag+" OK done\r\n")

		// Second command: only a correctly realigned reader will see just the
		// tagged completion here, with nothing left over from the first.
		line, _ = r.ReadString('\n')
		tag = strings.Fields(line)[0]
		io.WriteString(conn, tag+" OK done2\r\n")
	}()

	host, port := dialFields(ln.Addr().String())
	c, err := Dial(nil, host, port, 5, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	untagged, err := c.cmd("NOOP")
	if err != nil {
		t.Fatalf("cmd: %v", err)
	}
	if len(untagged) != 2 {
		t.Fatalf("untagged = %q, want 2 lines (literal payload leaked as a protocol line?)", untagged)
	}

	untagged2, err := c.cmd("NOOP")
	if err != nil {
		t.Fatalf("cmd after literal: %v (connection desynced)", err)
	}
	if len(untagged2) != 0 {
		t.Fatalf("second cmd untagged = %q, want none (leftover bytes from the literal response?)", untagged2)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
