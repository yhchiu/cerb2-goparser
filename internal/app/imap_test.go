package app

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/xmltree"
)

type recordingPoster struct{ count int }

func (r *recordingPoster) Deliver(*config.Config, *xmltree.Node, *clog.Logger) (bool, error) {
	r.count++
	return true, nil
}

// startFakeIMAP launches a fake IMAP server that serves repeated connections
// (so a test can run the parser more than once). messages are keyed by UID. When
// authToken is non-empty the server requires SASL XOAUTH2 carrying that token.
func startFakeIMAP(t *testing.T, messages map[int]string, authToken string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeIMAP(conn, messages, authToken)
		}
	}()
	return ln.Addr().String()
}

func serveFakeIMAP(conn net.Conn, messages map[int]string, authToken string) {
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
		cmd := strings.ToUpper(fields[1])
		args := fields[2:]
		if cmd == "UID" && len(fields) >= 3 {
			cmd = strings.ToUpper(fields[2])
			args = fields[3:]
		}
		switch cmd {
		case "LOGIN":
			io.WriteString(conn, tag+" OK ok\r\n")
		case "AUTHENTICATE":
			if len(args) < 2 || strings.ToUpper(args[0]) != "XOAUTH2" || !xoauth2HasToken(args[1], authToken) {
				io.WriteString(conn, "+ eyJzdGF0dXMiOiI0MDEifQ==\r\n")
				r.ReadString('\n') // client's empty response
				io.WriteString(conn, tag+" NO auth failed\r\n")
				continue
			}
			io.WriteString(conn, tag+" OK authenticated\r\n")
		case "SELECT":
			io.WriteString(conn, "* 2 EXISTS\r\n* OK [UIDVALIDITY 1] ok\r\n"+tag+" OK ok\r\n")
		case "SEARCH":
			io.WriteString(conn, "* SEARCH 1 2\r\n"+tag+" OK ok\r\n")
		case "FETCH":
			uid, _ := strconv.Atoi(args[0])
			body := messages[uid]
			fmt.Fprintf(conn, "* 1 FETCH (UID %d BODY[] {%d}\r\n", uid, len(body))
			io.WriteString(conn, body+")\r\n"+tag+" OK ok\r\n")
		case "LOGOUT":
			io.WriteString(conn, "* BYE\r\n"+tag+" OK ok\r\n")
			return
		default:
			io.WriteString(conn, tag+" OK ok\r\n")
		}
	}
}

// xoauth2HasToken reports whether the base64 XOAUTH2 initial response carries the
// wanted bearer token. An empty wanted token accepts anything.
func xoauth2HasToken(ir, wanted string) bool {
	if wanted == "" {
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(ir)
	if err != nil {
		return false
	}
	return strings.Contains(string(decoded), "auth=Bearer "+wanted+"\x01")
}

func writeIMAPConfig(t *testing.T, dir, host, port string, extraGlobal string) (cfgPath, logPath string) {
	t.Helper()
	cfgXML := "<configuration>\n" +
		"  <global><tmp_dir value=\"" + xmlEscape(dir+string(os.PathSeparator)) + "\"/>" + extraGlobal + "</global>\n" +
		"  <imap><host value=\"" + host + "\"/><port value=\"" + port + "\"/>" +
		"<user value=\"u\"/><password value=\"p\"/><delete value=\"false\"/></imap>\n" +
		"</configuration>\n"
	cfgPath = filepath.Join(dir, "config.xml")
	if err := os.WriteFile(cfgPath, []byte(cfgXML), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(dir, "log.txt")
}

func TestRunIMAPMode(t *testing.T) {
	addr := startFakeIMAP(t, map[int]string{
		1: "Content-Type: text/plain\r\nSubject: One\r\n\r\nbody one\r\n",
		2: "Content-Type: text/plain\r\nSubject: Two\r\n\r\nbody two\r\n",
	}, "")
	host, portStr, _ := net.SplitHostPort(addr)
	dir := t.TempDir()
	cfgPath, logPath := writeIMAPConfig(t, dir, host, portStr, "")

	rec := &recordingPoster{}
	rc := run([]string{cfgPath, "DEBUG", logPath}, strings.NewReader(""), io.Discard, rec)
	if rc != ExitOK {
		t.Fatalf("run rc = %d, want %d", rc, ExitOK)
	}
	if rec.count != 2 {
		t.Errorf("delivered %d messages, want 2", rec.count)
	}
}

func TestRunIMAPDedup(t *testing.T) {
	addr := startFakeIMAP(t, map[int]string{
		1: "Content-Type: text/plain\r\nSubject: One\r\n\r\nbody one\r\n",
		2: "Content-Type: text/plain\r\nSubject: Two\r\n\r\nbody two\r\n",
	}, "")
	host, portStr, _ := net.SplitHostPort(addr)
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	cfgPath, logPath := writeIMAPConfig(t, dir, host, portStr,
		"<imap_state value=\""+xmlEscape(stateFile)+"\"/>")

	// first run delivers both messages and records their UIDs
	rec1 := &recordingPoster{}
	if rc := run([]string{cfgPath, "DEBUG", logPath}, strings.NewReader(""), io.Discard, rec1); rc != ExitOK {
		t.Fatalf("run 1 rc = %d", rc)
	}
	if rec1.count != 2 {
		t.Fatalf("run 1 delivered %d, want 2", rec1.count)
	}
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// second run: messages still on the server (delete=false) but already
	// processed, so nothing is delivered
	rec2 := &recordingPoster{}
	if rc := run([]string{cfgPath, "DEBUG", logPath}, strings.NewReader(""), io.Discard, rec2); rc != ExitOK {
		t.Fatalf("run 2 rc = %d", rc)
	}
	if rec2.count != 0 {
		t.Errorf("run 2 delivered %d, want 0 (already processed)", rec2.count)
	}
}

// TestRunIMAPXOAUTH2 drives the full IMAP mode with OAuth2: the parser mints an
// access token from a fake token endpoint and authenticates with SASL XOAUTH2,
// which the fake IMAP server accepts only for that exact token.
func TestRunIMAPXOAUTH2(t *testing.T) {
	const accessToken = "tok-abc123"

	var tokenCalls int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"token_type":"Bearer"}`, accessToken)
	}))
	defer tokenSrv.Close()

	addr := startFakeIMAP(t, map[int]string{
		1: "Content-Type: text/plain\r\nSubject: One\r\n\r\nbody one\r\n",
		2: "Content-Type: text/plain\r\nSubject: Two\r\n\r\nbody two\r\n",
	}, accessToken)
	host, portStr, _ := net.SplitHostPort(addr)

	dir := t.TempDir()
	cfgXML := "<configuration>\n" +
		"  <global><tmp_dir value=\"" + xmlEscape(dir+string(os.PathSeparator)) + "\"/></global>\n" +
		"  <imap>\n" +
		"    <host value=\"" + host + "\"/><port value=\"" + portStr + "\"/>\n" +
		"    <user value=\"spam@contoso.com\"/>\n" +
		"    <auth value=\"xoauth2\"/>\n" +
		"    <oauth_client_id value=\"client-id\"/>\n" +
		"    <oauth_refresh_token value=\"bootstrap-rt\"/>\n" +
		"    <oauth_token_url value=\"" + xmlEscape(tokenSrv.URL) + "\"/>\n" +
		"    <delete value=\"false\"/>\n" +
		"  </imap>\n" +
		"</configuration>\n"
	cfgPath := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(cfgPath, []byte(cfgXML), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log.txt")

	rec := &recordingPoster{}
	rc := run([]string{cfgPath, "DEBUG", logPath}, strings.NewReader(""), io.Discard, rec)
	if rc != ExitOK {
		t.Fatalf("run rc = %d, want %d", rc, ExitOK)
	}
	if rec.count != 2 {
		t.Errorf("delivered %d messages, want 2", rec.count)
	}
	if tokenCalls == 0 {
		t.Error("token endpoint was never called")
	}
}
