package mimeparse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cerb2-goparser/internal/xmltree"
)

func parse(t *testing.T, raw string) (*xmltree.Node, string) {
	t.Helper()
	dir := t.TempDir()
	pattern := filepath.Join(dir, "cerbmime_XXXXXX")
	p := NewParser(nil, strings.NewReader(raw), pattern)
	email := p.FileParse()
	if email == nil {
		t.Fatal("FileParse returned nil")
	}
	return email, dir
}

func readTemp(t *testing.T, n *xmltree.Node) string {
	t.Helper()
	if n == nil {
		t.Fatal("tempname node missing")
	}
	b, err := os.ReadFile(string(n.Data))
	if err != nil {
		t.Fatalf("reading temp %q: %v", n.Data, err)
	}
	return string(b)
}

func TestParsePlainText(t *testing.T) {
	raw := "From: a@b.com\r\n" +
		"To: c@d.com\r\n" +
		"Subject: Hi\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello world\r\n" +
		"This is a test\r\n"

	email, _ := parse(t, raw)

	if ct := email.Get("email", "headers", "content-type"); ct != nil {
		if v, _ := ct.Attribute("case"); v != "b" {
			t.Errorf("content-type case = %q, want b", v)
		}
	} else {
		t.Fatal("missing content-type")
	}

	tn := email.Get("email", "file", "tempname")
	if got := readTemp(t, tn); got != "Hello world\r\nThis is a test\r\n" {
		t.Errorf("body = %q", got)
	}
}

func TestParseMultipartBase64(t *testing.T) {
	raw := "From: a@b.com\r\n" +
		"Subject: multi\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n" +
		"\r\n" +
		"preamble\r\n" +
		"--BOUND\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Body text here\r\n" +
		"--BOUND\r\n" +
		"Content-Type: application/octet-stream; name=\"hi.txt\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"hi.txt\"\r\n" +
		"\r\n" +
		"SGVsbG8sIFdvcmxkIQ==\r\n" +
		"--BOUND--\r\n"

	email, _ := parse(t, raw)

	if ct := email.Get("email", "headers", "content-type"); ct != nil {
		if v, _ := ct.Attribute("case"); v != "a" {
			t.Errorf("top content-type case = %q, want a", v)
		}
		if b := ct.Get("content-type", "boundary"); b == nil || string(b.Data) != "BOUND" {
			t.Errorf("boundary = %v, want BOUND", b)
		}
	}

	email.Iterate()
	sub1 := email.Next("sub")
	sub2 := email.Next("sub")
	if sub1 == nil || sub2 == nil {
		t.Fatalf("expected 2 sub parts, got %v %v", sub1, sub2)
	}
	if email.Next("sub") != nil {
		t.Error("expected exactly 2 sub parts")
	}

	if got := readTemp(t, sub1.Get("sub", "file", "tempname")); got != "Body text here\r\n" {
		t.Errorf("part1 body = %q", got)
	}

	fnode := sub2.Get("sub", "file")
	if fnode == nil {
		t.Fatal("part2 file node missing")
	}
	if v, _ := fnode.Attribute("name"); v != "hi.txt" {
		t.Errorf("part2 file name = %q, want hi.txt", v)
	}
	if got := readTemp(t, fnode.Get("file", "tempname")); got != "Hello, World!" {
		t.Errorf("part2 decoded = %q, want %q", got, "Hello, World!")
	}
}

func TestParseQuotedPrintable(t *testing.T) {
	raw := "Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"Caf=C3=A9 = wonderful=\r\n" +
		" continued\r\n"

	email, _ := parse(t, raw)
	got := readTemp(t, email.Get("email", "file", "tempname"))
	// =C3=A9 -> two bytes 0xC3 0xA9; trailing "=\r\n" is a soft break joining lines.
	want := "Caf\xc3\xa9 = wonderful continued\r\n"
	if got != want {
		t.Errorf("qp body = %q, want %q", got, want)
	}
}
