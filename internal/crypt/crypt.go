// Package crypt ports the Cerberus license-key cipher (Blowfish with embedded,
// pre-scheduled P/S tables, misnamed "rsa" in the C source) and the key decoder
// that turns an encrypted hex key into license fields.
package crypt

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cerb2-goparser/internal/xmltree"
)

// KeyInfo decrypts an encrypted hex license key and returns a <key> tree with the
// license fields (<type>, <expiration>, <domain>..., <serial>, <tagline>), or
// nil if the key is corrupt or expired. Mirrors cer_key_info.
//
// The decrypted plaintext is the native (little-endian) byte serialization of
// the decrypted uint32 blocks, matching the C little-endian path.
func KeyInfo(key []byte) *xmltree.Node {
	if len(key) == 0 {
		return nil
	}

	// keep only hex digits
	hexStr := make([]byte, 0, len(key))
	for _, c := range key {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexStr = append(hexStr, c)
		}
	}
	n := len(hexStr) / 8
	if n == 0 {
		return nil
	}

	// parse 8-hex-char groups into uint32 words (one extra zero slot, as in C)
	data := make([]uint32, n+1)
	for i := 0; i < n; i++ {
		v, err := strconv.ParseUint(string(hexStr[i*8:i*8+8]), 16, 32)
		if err != nil {
			return nil
		}
		data[i] = uint32(v)
	}

	// decrypt block pairs in place
	for i := 0; i < n; i += 2 {
		l, r := decypher(data[i], data[i+1])
		data[i], data[i+1] = l, r
	}

	// little-endian byte serialization of the decrypted words
	plain := make([]byte, 0, n*4)
	for i := 0; i < n; i++ {
		w := data[i]
		plain = append(plain, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	if z := bytes.IndexByte(plain, 0); z >= 0 {
		plain = plain[:z]
	}

	// a valid key has at least 10 newline-separated fields
	if bytes.Count(plain, []byte("\n")) < 10 {
		return nil
	}
	lines := bytes.Split(plain, []byte("\n"))

	keyNode := xmltree.New("key")
	keyNode.AddChild("type").AddData(lines[0])
	keyNode.AddChild("expiration").AddData(lines[4])

	if !expirationValid(lines[4]) {
		return nil
	}

	for _, d := range extractQuoted(lines[5]) {
		keyNode.AddChild("domain").AddData(d)
	}
	keyNode.AddChild("serial").AddData(lines[7])
	keyNode.AddChild("tagline").AddData(lines[9])
	return keyNode
}

// Encrypt encodes a newline-delimited license plaintext into the hex key format
// that KeyInfo decodes. It is the inverse of KeyInfo's decryption step and
// mirrors the offline ccrypt key-generation tool.
func Encrypt(plain []byte) string {
	p := make([]byte, len(plain))
	copy(p, plain)
	for len(p)%8 != 0 {
		p = append(p, 0)
	}
	n := len(p) / 4
	data := make([]uint32, n)
	for i := 0; i < n; i++ {
		b := p[i*4:]
		data[i] = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}
	for i := 0; i < n; i += 2 {
		l, r := encypher(data[i], data[i+1])
		data[i], data[i+1] = l, r
	}
	var sb strings.Builder
	for _, w := range data {
		fmt.Fprintf(&sb, "%08x", w)
	}
	return sb.String()
}

// expirationValid parses a YYYYMMDD expiration and reports whether the key is
// within range (year < 2100 and the date is not in the past), matching the
// mktime check in cer_key_info.
func expirationValid(exp []byte) bool {
	if len(exp) < 8 {
		return false
	}
	year := atoiBytes(exp[0:4])
	month := atoiBytes(exp[4:6])
	day := atoiBytes(exp[6:8])
	if year >= 2100 {
		return false
	}
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.Local)
	return !t.Before(time.Now())
}

// extractQuoted returns the contents of each double-quoted run in line, matching
// the domain-extraction loop in cer_key_info.
func extractQuoted(line []byte) [][]byte {
	var out [][]byte
	i := 0
	for i < len(line) {
		s := bytes.IndexByte(line[i:], '"')
		if s < 0 {
			break
		}
		start := i + s + 1
		e := bytes.IndexByte(line[start:], '"')
		if e < 0 {
			break
		}
		end := start + e
		out = append(out, line[start:end])
		i = end + 1
		if i < len(line) && line[i] == ',' {
			i++
		}
	}
	return out
}

func atoiBytes(b []byte) int {
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int(c-'0')
	}
	return v
}
