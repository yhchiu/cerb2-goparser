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

func startFakeIMAP(t *testing.T, messages map[int]string) string {
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
				io.WriteString(conn, tag+" OK ok\r\n")
			case "SELECT":
				io.WriteString(conn, "* 2 EXISTS\r\n"+tag+" OK ok\r\n")
			case "SEARCH":
				io.WriteString(conn, "* SEARCH 1 2\r\n"+tag+" OK ok\r\n")
			case "FETCH":
				seq, _ := strconv.Atoi(fields[2])
				body := messages[seq]
				fmt.Fprintf(conn, "* %d FETCH (BODY[] {%d}\r\n", seq, len(body))
				io.WriteString(conn, body+")\r\n"+tag+" OK ok\r\n")
			case "LOGOUT":
				io.WriteString(conn, "* BYE\r\n"+tag+" OK ok\r\n")
				return
			default:
				io.WriteString(conn, tag+" OK ok\r\n")
			}
		}
	}()
	return ln.Addr().String()
}

func TestRunIMAPMode(t *testing.T) {
	addr := startFakeIMAP(t, map[int]string{
		1: "Content-Type: text/plain\r\nSubject: One\r\n\r\nbody one\r\n",
		2: "Content-Type: text/plain\r\nSubject: Two\r\n\r\nbody two\r\n",
	})
	host, portStr, _ := net.SplitHostPort(addr)

	dir := t.TempDir()
	cfgXML := "<configuration>\n" +
		"  <global><tmp_dir value=\"" + xmlEscape(dir+string(os.PathSeparator)) + "\"/></global>\n" +
		"  <imap><host value=\"" + host + "\"/><port value=\"" + portStr + "\"/>" +
		"<user value=\"u\"/><password value=\"p\"/><delete value=\"false\"/></imap>\n" +
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
}
