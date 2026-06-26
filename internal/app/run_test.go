package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/xmltree"
)

type panicPoster struct{}

func (panicPoster) Deliver(*config.Config, *xmltree.Node, *clog.Logger) (bool, error) {
	panic("boom")
}

func TestProcessOnePanicRecover(t *testing.T) {
	dir := t.TempDir()
	msg := filepath.Join(dir, "msg.eml")
	if err := os.WriteFile(msg, []byte("Subject: Hi\r\nContent-Type: text/plain\r\n\r\nbody\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{TmpMimePattern: filepath.Join(dir, "cerbmime_XXXXXX")}

	// A panic during delivery must be recovered (no crash) and reported as a
	// failed delivery so the surrounding batch loop can continue.
	ok := processOne(cfg, msg, nil, io.Discard, panicPoster{})
	if ok {
		t.Error("processOne = true, want false after a panic")
	}
	if _, err := os.Stat(msg); err != nil {
		t.Errorf("message file should be kept after a failed delivery: %v", err)
	}
}

func TestPipeDebugParse(t *testing.T) {
	dir := t.TempDir()
	tmpVal := dir + string(os.PathSeparator)

	cfgXML := "<configuration>\n" +
		"  <debug><xml value=\"1\"/><parse value=\"1\"/></debug>\n" +
		"  <global><tmp_dir value=\"" + xmlEscape(tmpVal) + "\"/></global>\n" +
		"</configuration>\n"

	cfgPath := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(cfgPath, []byte(cfgXML), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log.txt")

	email := "From: a@b.com\r\n" +
		"Subject: Hi\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello\r\n"

	var out bytes.Buffer
	rc := run([]string{cfgPath, "DEBUG", logPath}, strings.NewReader(email), &out, nil)
	if rc != ExitOK {
		t.Fatalf("run rc = %d, want %d", rc, ExitOK)
	}

	got := out.String()
	for _, want := range []string{"<?xml", "<email>", "<subject>", "Hi", "<from>"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestUsage(t *testing.T) {
	rc := run([]string{"only-one-arg"}, strings.NewReader(""), &bytes.Buffer{}, nil)
	if rc != ExitUsage {
		t.Errorf("rc = %d, want %d", rc, ExitUsage)
	}
}

func TestUnixToDOS(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\nb", "a\r\nb"},
		{"a\r\nb", "a\r\nb"},
		{"\n", "\r\n"},
		{"a\r\n\nb", "a\r\n\r\nb"},
		{"no newline", "no newline"},
	}
	for _, c := range cases {
		if got := string(unixToDOS([]byte(c.in))); got != c.want {
			t.Errorf("unixToDOS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// xmlEscape escapes a Windows path (with backslashes) for safe XML attribute use.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
