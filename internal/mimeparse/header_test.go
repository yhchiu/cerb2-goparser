package mimeparse

import (
	"strings"
	"testing"
)

func newTestParser(headers string) *Parser {
	return NewParser(nil, strings.NewReader(headers), "")
}

func TestHeaderParseBasic(t *testing.T) {
	hdr := "To: alice@example.com\r\n" +
		"From: Bob <bob@example.com>\r\n" +
		"Subject: Hello\r\n" +
		"Content-Type: multipart/mixed; boundary=\"abc123\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n"

	root := newTestParser(hdr).HeaderParse()

	cases := []struct{ path, want string }{
		{"to", "alice@example.com"},
		{"from", "Bob <bob@example.com>"},
		{"subject", "Hello"},
	}
	for _, c := range cases {
		n := root.Get("headers", c.path)
		if n == nil {
			t.Errorf("missing header %q", c.path)
			continue
		}
		if string(n.Data) != c.want {
			t.Errorf("header %q = %q, want %q", c.path, n.Data, c.want)
		}
	}

	ct := root.Get("headers", "content-type")
	if ct == nil {
		t.Fatal("missing content-type")
	}
	if v, _ := ct.Attribute("case"); v != "a" {
		t.Errorf("content-type case = %q, want a", v)
	}
	bnd := root.Get("headers", "content-type", "boundary")
	if bnd == nil || string(bnd.Data) != "abc123" {
		t.Errorf("boundary = %v, want abc123", bnd)
	}

	cte := root.Get("headers", "content-transfer-encoding")
	if v, _ := cte.Attribute("case"); v != "a" {
		t.Errorf("cte case = %q, want a", v)
	}
}

func TestHeaderParseFolding(t *testing.T) {
	hdr := "Subject: Hello\r\n" +
		" World\r\n" +
		"\r\n"
	root := newTestParser(hdr).HeaderParse()
	subj := root.Get("headers", "subject")
	if subj == nil {
		t.Fatal("missing subject")
	}
	if string(subj.Data) != "Hello World" {
		t.Errorf("folded subject = %q, want %q", subj.Data, "Hello World")
	}
}

func TestHeaderParseDisposition(t *testing.T) {
	hdr := "Content-Type: application/octet-stream; name=\"doc.pdf\"\r\n" +
		"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n"
	root := newTestParser(hdr).HeaderParse()

	ct := root.Get("headers", "content-type")
	if v, _ := ct.Attribute("case"); v != "f" {
		t.Errorf("content-type case = %q, want f", v)
	}
	name := root.Get("headers", "content-type", "name")
	if name == nil || string(name.Data) != "doc.pdf" {
		t.Errorf("ct name = %v, want doc.pdf", name)
	}
	cd := root.Get("headers", "content-disposition")
	if v, _ := cd.Attribute("attachment"); v != "true" {
		t.Errorf("disposition attachment = %q, want true", v)
	}
	fn := root.Get("headers", "content-disposition", "filename")
	if fn == nil || string(fn.Data) != "doc.pdf" {
		t.Errorf("filename = %v, want doc.pdf", fn)
	}
}

func TestHeaderParseNoContentType(t *testing.T) {
	hdr := "To: x@y.com\r\n\r\n"
	root := newTestParser(hdr).HeaderParse()
	ct := root.Get("headers", "content-type")
	if ct == nil {
		t.Fatal("expected synthesized content-type")
	}
	if v, _ := ct.Attribute("case"); v != "z" {
		t.Errorf("case = %q, want z", v)
	}
	if string(ct.Data) != "unknown" {
		t.Errorf("data = %q, want unknown", ct.Data)
	}
}
