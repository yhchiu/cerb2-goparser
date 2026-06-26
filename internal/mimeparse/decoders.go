package mimeparse

import (
	"bytes"
	"os"

	"cerb2-goparser/internal/xmltree"
)

// ---- lookup tables (built to match the C b64d[] and hc[] arrays) ----

var b64d = buildB64()
var hcTab = buildHC()

func buildB64() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(alpha); i++ {
		t[alpha[i]] = int8(i)
	}
	return t
}

func buildHC() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for c := byte('0'); c <= '9'; c++ {
		t[c] = int8(c - '0')
	}
	for c := byte('A'); c <= 'F'; c++ {
		t[c] = int8(c - 'A' + 10)
	}
	for c := byte('a'); c <= 'f'; c++ {
		t[c] = int8(c - 'a' + 10)
	}
	t[255] = 0 // matches the trailing 0 in the C hc[] table
	return t
}

// ---- partWriter: streams decoded output to a temp file, splitting at
// MaxFileSize and recording each new file as a <tempname> child of files. ----

type partWriter struct {
	p     *Parser
	files *xmltree.Node // the <file> node to which split <tempname> nodes attach
	cur   *os.File
	pos   int
	split bool
	err   error
}

func (pw *partWriter) write(b []byte) {
	if pw.err != nil || len(b) == 0 {
		return
	}
	if pw.split && pw.files != nil && MaxFileSize < pw.pos+len(b) {
		pw.rotate()
		if pw.err != nil {
			return
		}
	}
	n, err := pw.cur.Write(b)
	pw.pos += n
	if err != nil {
		pw.err = err
	}
}

func (pw *partWriter) rotate() {
	_ = pw.cur.Close()
	f, err := pw.p.mkTemp()
	if err != nil {
		pw.err = err
		return
	}
	pw.cur = f
	pw.pos = 0
	tn := pw.files.AddChild("tempname")
	tn.AddDataString(f.Name())
}

// ---- base64 streaming state machine ----

// b64State accumulates a base64 sextet stream into bytes, emitting each byte as
// it completes. The partial trailing byte is discarded, matching the net output
// of cmime_parse_b64.
type b64State struct {
	quad int
	cur  byte
}

// feed decodes the base64 characters in src, appending completed bytes to out.
// Non-base64 bytes are skipped. When stopAtEq is true a '=' ends processing of
// src (used by the streaming body decoder); otherwise '=' is skipped like any
// other non-base64 byte (used by cmime_parse_b64_string).
func (s *b64State) feed(src []byte, out *[]byte, stopAtEq bool) {
	for _, c := range src {
		if c == '=' {
			if stopAtEq {
				return
			}
			continue
		}
		v := b64d[c]
		if v < 0 {
			continue
		}
		switch s.quad & 3 {
		case 0:
			s.cur = byte(v) << 2
		case 1:
			s.cur |= byte(v&0x30) >> 4
			*out = append(*out, s.cur)
			s.cur = byte(v&0x0F) << 4
		case 2:
			s.cur |= byte(v&0x3C) >> 2
			*out = append(*out, s.cur)
			s.cur = byte(v&0x03) << 6
		case 3:
			s.cur |= byte(v & 0x3F)
			*out = append(*out, s.cur)
		}
		s.quad++
	}
}

// b64DecodeString decodes a complete base64 string in one shot, mirroring
// cmime_parse_b64_string (does not stop at '=').
func b64DecodeString(src []byte) []byte {
	st := &b64State{}
	var out []byte
	st.feed(src, &out, false)
	return out
}

// qpDecodeLine decodes one quoted-printable line, matching
// cmime_parse_qptext_line: "=\r\n" is a soft break (removed), "=HH" decodes to a
// byte, an "=" followed by a non-hex byte is copied literally.
func qpDecodeLine(line []byte) []byte {
	out := make([]byte, 0, len(line))
	n := len(line)
	for i := 0; i < n; {
		if line[i] == '=' {
			switch {
			case i+2 < n && line[i+1] == '\r' && line[i+2] == '\n':
				i += 3
			case i+1 < n && hcTab[line[i+1]] == -1:
				out = append(out, line[i])
				i++
			case i+2 < n:
				out = append(out, byte(int(hcTab[line[i+1]])*16+int(hcTab[line[i+2]])))
				i += 3
			default:
				out = append(out, line[i])
				i++
			}
		} else {
			out = append(out, line[i])
			i++
		}
	}
	return out
}

func stripTrailingCRLF(line []byte) []byte {
	n := len(line)
	for n > 0 && (line[n-1] == '\n' || line[n-1] == '\r') {
		n--
	}
	return line[:n]
}

// atBoundary reports whether line is a "--<boundary>..." delimiter for the given
// boundary, matching the C strncmp(line+2, boundary, len) prefix test.
func atBoundary(line, boundary []byte) bool {
	return len(line) > 4 && line[0] == '-' && line[1] == '-' && bytes.HasPrefix(line[2:], boundary)
}

// decodeText copies raw (already-decoded) text lines to pw, watching for a
// multipart boundary or, when not inside multipart, a uuencode "begin" line.
// Mirrors cmime_parse_text.
func (p *Parser) decodeText(pw *partWriter, sub *xmltree.Node, boundary []byte) {
	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		if len(line) > 4 {
			if boundary != nil {
				if atBoundary(line, boundary) {
					break // leave the boundary unconsumed for the caller
				}
			} else if line[0] == 'b' {
				if name := parseUUBegin(line); name != nil {
					p.lr.next()
					p.parseUU(name, sub, boundary)
					continue
				}
			}
		}
		pw.write(line)
		p.lr.next()
	}
}

// decodeQP is decodeText with quoted-printable decoding per line. Mirrors
// cmime_parse_qptext.
func (p *Parser) decodeQP(pw *partWriter, sub *xmltree.Node, boundary []byte) {
	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		if len(line) > 4 {
			if boundary != nil {
				if atBoundary(line, boundary) {
					break
				}
			} else if line[0] == 'b' {
				if name := parseUUBegin(line); name != nil {
					p.lr.next()
					p.parseUU(name, sub, boundary)
					continue
				}
			}
		}
		pw.write(qpDecodeLine(line))
		p.lr.next()
	}
}

// decodeB64 streams a base64-decoded body to pw. Mirrors cmime_parse_b64.
func (p *Parser) decodeB64(pw *partWriter, sub *xmltree.Node, boundary []byte) {
	st := &b64State{}
	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		if len(line) > 4 {
			if boundary != nil {
				if atBoundary(line, boundary) {
					break
				}
			} else if line[0] == 'b' {
				if name := parseUUBegin(line); name != nil {
					p.lr.next()
					p.parseUU(name, sub, boundary)
					continue
				}
			}
		}
		var out []byte
		st.feed(stripTrailingCRLF(line), &out, true)
		pw.write(out)
		p.lr.next()
	}
}
