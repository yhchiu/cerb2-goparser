// Package charset converts byte data from a named (email/IANA) charset to UTF-8,
// using golang.org/x/text. It re-enables the charset conversion the C parser
// had stubbed out (its ICU code was commented out).
package charset

import (
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// ToUTF8 decodes data, which is in the charset named by name, into UTF-8. An
// empty or UTF-8 charset (and any unrecognized name) returns the input
// unchanged; a decode error returns the input unchanged with the error.
func ToUTF8(name string, data []byte) ([]byte, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return data, nil
	}
	enc, err := htmlindex.Get(name)
	if err != nil {
		return data, err
	}
	if enc == encoding.Nop {
		return data, nil
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err != nil {
		return data, err
	}
	return out, nil
}

// ToUTF8Lossy is ToUTF8 but always returns valid UTF-8, falling back to the
// original bytes when the charset is unknown or conversion fails. It matches the
// mimeparse.Transcoder signature.
func ToUTF8Lossy(name string, data []byte) []byte {
	out, err := ToUTF8(name, data)
	if err != nil {
		return data
	}
	return out
}
