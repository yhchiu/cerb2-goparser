package mimeparse

import "bytes"

// subject decoder states (mirror the #defines in cmime_parse_subject.c)
const (
	subjDefault = iota
	subjBeginning
	subjQP
	subjB64
	subjEnding
)

// ParseSubject decodes RFC-2047 encoded-words ("=?charset?Q|B?text?=") in a
// subject value, concatenating adjacent words. It mirrors cmime_parse_subject:
// the ICU charset transcoding is disabled in the C source, so decoded bytes are
// emitted as-is with no charset conversion.
func ParseSubject(subject []byte) []byte {
	if subject == nil {
		return nil
	}
	final := make([]byte, 0, len(subject))
	var encoded []byte
	state := subjDefault
	s := subject
	n := len(s)
	i := 0

	for i < n {
		switch state {
		case subjBeginning:
			i += 2 // past "=?"
			q := indexByteFrom(s, i, '?')
			if q < 0 {
				state = subjDefault
				break
			}
			// charset = s[i:q] (ignored: transcoding disabled)
			encoded = encoded[:0]
			i = q + 1 // at the Q/B byte
			if i < n && (s[i] == 'q' || s[i] == 'Q') {
				state = subjQP
			} else if i < n && (s[i] == 'b' || s[i] == 'B') {
				state = subjB64
			} else {
				state = subjDefault
			}
			i += 2 // past the Q/B and the following '?'

		case subjQP:
			for i+1 < n && !(s[i] == '?' && s[i+1] == '=') {
				switch {
				case s[i] == '_':
					encoded = append(encoded, ' ')
					i++
				case s[i] == '=' && i+1 < n && isAlnum(s[i+1]):
					if i+2 < n {
						encoded = append(encoded, strtolHex2(s[i+1], s[i+2]))
						i += 3
					} else {
						i++
					}
				case s[i] == '\t':
					i++
				default:
					encoded = append(encoded, s[i])
					i++
				}
			}
			state = subjEnding

		case subjB64:
			end := indexSubFrom(s, i, []byte("?="))
			if end < 0 {
				end = n
			}
			encoded = append(encoded, b64DecodeString(s[i:end])...)
			i = end
			state = subjEnding

		case subjEnding:
			if i+1 < n && s[i] == '?' && s[i+1] == '=' {
				i += 2
			}
			final = append(final, encoded...)
			state = subjDefault

		default: // subjDefault
			if i+1 < n && s[i] == '=' && s[i+1] == '?' && indexSubFrom(s, i, []byte("?=")) >= 0 {
				state = subjBeginning
			} else {
				if s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
					final = append(final, s[i])
				}
				i++
			}
		}
	}
	return final
}

func indexByteFrom(s []byte, from int, c byte) int {
	if from < 0 || from >= len(s) {
		return -1
	}
	if i := bytes.IndexByte(s[from:], c); i >= 0 {
		return from + i
	}
	return -1
}

func indexSubFrom(s []byte, from int, sub []byte) int {
	if from < 0 || from > len(s) {
		return -1
	}
	if i := bytes.Index(s[from:], sub); i >= 0 {
		return from + i
	}
	return -1
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// strtolHex2 parses up to two hex digits (strtol base 16 semantics) of a,b.
func strtolHex2(a, b byte) byte {
	v := 0
	got := false
	for _, c := range []byte{a, b} {
		d := hcTab[c]
		if d < 0 {
			break
		}
		v = v*16 + int(d)
		got = true
	}
	if !got {
		return 0
	}
	return byte(v)
}
