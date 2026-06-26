package crypt

import (
	"strings"
	"testing"
)

func TestCipherRoundTrip(t *testing.T) {
	cases := []struct{ l, r uint32 }{
		{0, 0},
		{0xdeadbeef, 0x12345678},
		{0xffffffff, 0x00000000},
		{0x01020304, 0xa1b2c3d4},
	}
	for _, c := range cases {
		el, er := encypher(c.l, c.r)
		dl, dr := decypher(el, er)
		if dl != c.l || dr != c.r {
			t.Errorf("round trip %08x/%08x -> %08x/%08x", c.l, c.r, dl, dr)
		}
	}
}

// licensePlain builds a 10-field license plaintext with the given expiration.
func licensePlain(expiration string) string {
	return strings.Join([]string{
		"Pro",
		"Acme Inc",
		"admin@acme.com",
		"20200101",
		expiration,
		`"example.com","foo.com"`,
		"5",
		"ABC123",
		"0",
		"Hello World",
	}, "\n") + "\n"
}

func TestKeyInfoValid(t *testing.T) {
	key := Encrypt([]byte(licensePlain("20991231")))

	node := KeyInfo([]byte(key))
	if node == nil {
		t.Fatal("KeyInfo returned nil for a valid key")
	}
	if node.Name != "key" {
		t.Errorf("root = %q, want key", node.Name)
	}
	if tn := node.Get("key", "type"); tn == nil || string(tn.Data) != "Pro" {
		t.Errorf("type = %v, want Pro", tn)
	}
	if ex := node.Get("key", "expiration"); ex == nil || string(ex.Data) != "20991231" {
		t.Errorf("expiration = %v, want 20991231", ex)
	}
	if s := node.Get("key", "serial"); s == nil || string(s.Data) != "ABC123" {
		t.Errorf("serial = %v, want ABC123", s)
	}
	if tl := node.Get("key", "tagline"); tl == nil || string(tl.Data) != "Hello World" {
		t.Errorf("tagline = %v, want Hello World", tl)
	}

	var domains []string
	node.Iterate()
	for d := node.Next("domain"); d != nil; d = node.Next("domain") {
		domains = append(domains, string(d.Data))
	}
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "foo.com" {
		t.Errorf("domains = %v, want [example.com foo.com]", domains)
	}
}

func TestKeyInfoExpired(t *testing.T) {
	key := Encrypt([]byte(licensePlain("20000101")))
	if node := KeyInfo([]byte(key)); node != nil {
		t.Error("expected nil for expired key")
	}
}

func TestKeyInfoCorrupt(t *testing.T) {
	if node := KeyInfo([]byte("not a real key zzzz")); node != nil {
		t.Error("expected nil for corrupt key")
	}
	if node := KeyInfo([]byte("deadbeefdeadbeef")); node != nil {
		t.Error("expected nil for short/garbage key (too few fields)")
	}
}
