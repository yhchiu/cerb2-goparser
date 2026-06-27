package app

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
// (so a test can run the parser more than once). messages are keyed by UID.
func startFakeIMAP(t *testing.T, messages map[int]string) string {
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
			go serveFakeIMAP(conn, messages)
		}
	}()
	return ln.Addr().String()
}

func serveFakeIMAP(conn net.Conn, messages map[int]string) {
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
	})
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
	})
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
