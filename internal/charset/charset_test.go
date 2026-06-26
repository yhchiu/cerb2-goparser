package charset

import (
	"testing"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

func TestToUTF8Latin1(t *testing.T) {
	// ISO-8859-1: 0xE9 == 'é'
	out, err := ToUTF8("iso-8859-1", []byte{'C', 'a', 'f', 0xE9})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "Café" {
		t.Errorf("got %q, want Café", out)
	}
}

func TestToUTF8RoundTrip(t *testing.T) {
	cases := map[string]string{
		"iso-8859-1":   "café",
		"windows-1252": "naïve €",
		"big5":         "中文測試",
		"shift_jis":    "日本語",
		"euc-kr":       "한국어",
	}
	for cs, orig := range cases {
		enc, err := htmlindex.Get(cs)
		if err != nil {
			t.Fatalf("get %s: %v", cs, err)
		}
		encoded, _, err := transform.Bytes(enc.NewEncoder(), []byte(orig))
		if err != nil {
			t.Fatalf("encode %s: %v", cs, err)
		}
		got, err := ToUTF8(cs, encoded)
		if err != nil {
			t.Fatalf("ToUTF8 %s: %v", cs, err)
		}
		if string(got) != orig {
			t.Errorf("%s round trip = %q, want %q", cs, got, orig)
		}
	}
}

func TestToUTF8Passthrough(t *testing.T) {
	if out, err := ToUTF8("utf-8", []byte("héllo")); err != nil || string(out) != "héllo" {
		t.Errorf("utf-8 passthrough = %q, %v", out, err)
	}
	if out, err := ToUTF8("", []byte("abc")); err != nil || string(out) != "abc" {
		t.Errorf("empty charset = %q, %v", out, err)
	}
}

func TestToUTF8LossyUnknown(t *testing.T) {
	if got := ToUTF8Lossy("no-such-charset", []byte("abc")); string(got) != "abc" {
		t.Errorf("unknown charset lossy = %q, want abc", got)
	}
}
