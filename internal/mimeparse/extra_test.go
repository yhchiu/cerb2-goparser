package mimeparse

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseSubject(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Plain subject", "Plain subject"},
		{"=?utf-8?Q?Caf=C3=A9?=", "Caf\xc3\xa9"},
		{"=?utf-8?B?SGVsbG8=?=", "Hello"},
		{"=?iso-8859-1?Q?a_b?=", "a b"},
		{"Hi =?utf-8?B?SGVsbG8=?= there", "Hi Hello there"},
		{"=?x?Q?one?= =?x?Q?two?=", "one two"},
	}
	for _, c := range cases {
		got := string(ParseSubject([]byte(c.in)))
		if got != c.want {
			t.Errorf("ParseSubject(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUUDecodeLine(t *testing.T) {
	// "#0V%T" is the uuencoding of "Cat" (length char '#'=3, data "0V%T").
	out, stop := uuDecodeLine([]byte("#0V%T\r\n"))
	if stop {
		t.Fatal("unexpected stop")
	}
	if string(out) != "Cat" {
		t.Errorf("uuDecodeLine = %q, want Cat", out)
	}
}

func TestParseUUEmail(t *testing.T) {
	raw := "Content-Type: text/plain\r\n" +
		"\r\n" +
		"begin 644 cat.txt\r\n" +
		"#0V%T\r\n" +
		"`\r\n" +
		"end\r\n"

	email, _ := parse(t, raw)
	email.Iterate()
	sub := email.Next("sub")
	if sub == nil {
		t.Fatal("expected uuencode <sub>")
	}
	f := sub.Get("sub", "file")
	if f == nil {
		t.Fatal("missing file node")
	}
	if v, _ := f.Attribute("name"); v != "cat.txt" {
		t.Errorf("file name attr = %q, want cat.txt", v)
	}
	if got := readTemp(t, f.Get("file", "tempname")); got != "Cat" {
		t.Errorf("uu decoded = %q, want Cat", got)
	}
}

func TestParseTNEFEmail(t *testing.T) {
	// Minimal winmail.dat: magic + key, then attach-begin (0x9002),
	// filename (0x8010) "a.txt", and file data (0x800F) "Hi".
	winmail := []byte{
		0x78, 0x9F, 0x3E, 0x22, // magic
		0x00, 0x00, // TNEF key
		0x02,                   // attachment
		0x02, 0x90, 0x06, 0x00, // name=0x9002 (begin)
		0x00, 0x00, 0x00, 0x00, // length 0
		0x00, 0x00, // checksum
		0x02,                   // attachment
		0x10, 0x80, 0x00, 0x00, // name=0x8010 (filename)
		0x06, 0x00, 0x00, 0x00, // length 6
		'a', '.', 't', 'x', 't', 0x00, // "a.txt\0"
		0x00, 0x00, // checksum
		0x02,                   // attachment
		0x0F, 0x80, 0x00, 0x00, // name=0x800F (file data)
		0x02, 0x00, 0x00, 0x00, // length 2
		'H', 'i', // "Hi"
		0x00, 0x00, // checksum
	}
	b64 := base64.StdEncoding.EncodeToString(winmail)

	raw := "Content-Type: application/ms-tnef\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		b64 + "\r\n"

	email, _ := parse(t, raw)
	if ct := email.Get("email", "headers", "content-type"); ct != nil {
		if v, _ := ct.Attribute("case"); v != "g" {
			t.Errorf("content-type case = %q, want g", v)
		}
	}
	// parseTNEF nests a <sub> under the email.
	tnefSub := email.Get("email", "sub")
	if tnefSub == nil {
		t.Fatal("missing TNEF <sub>")
	}
	f := tnefSub.Get("sub", "file")
	if f == nil {
		t.Fatal("missing TNEF file node")
	}
	if v, _ := f.Attribute("name"); v != "a.txt" {
		t.Errorf("TNEF file name = %q, want a.txt", v)
	}
	if got := readTemp(t, f.Get("file", "tempname")); got != "Hi" {
		t.Errorf("TNEF data = %q, want Hi", got)
	}
}

// ensure base64 wrapped across multiple lines still decodes (sanity for decodeB64).
func TestBase64MultiLine(t *testing.T) {
	raw := "Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"SGVsbG8s\r\n" +
		"IFdvcmxk\r\n" +
		"IQ==\r\n"
	email, _ := parse(t, raw)
	got := readTemp(t, email.Get("email", "file", "tempname"))
	if !strings.HasPrefix(got, "Hello, World!") {
		t.Errorf("multiline base64 = %q, want Hello, World!", got)
	}
}
