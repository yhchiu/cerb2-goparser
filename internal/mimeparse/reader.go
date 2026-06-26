// Package mimeparse is a faithful Go port of the C "cmime" email parser. It
// walks a raw RFC-822/MIME message, decodes transfer encodings (base64,
// quoted-printable, plain text, uuencode, TNEF), extracts attachment bodies to
// temp files, and builds an xmltree matching the structure the original C
// parser posted to the Cerberus backend.
package mimeparse

import (
	"bufio"
	"io"
)

// lineReader reproduces the cfile peek/consume line model. getLine returns the
// next line including its "\r\n" terminator; calling getLine again without an
// intervening next re-returns the same line (the C rewind via line_used==0).
// next marks the current line consumed so the following getLine advances. This
// single-line "un-read" is what lets a decoder peek a multipart boundary and
// leave it for the enclosing parser.
type lineReader struct {
	r    *bufio.Reader
	cur  []byte
	have bool
	used bool
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 8192)}
}

// getLine returns the next line (peek). ok is false at end of input.
func (lr *lineReader) getLine() (line []byte, ok bool) {
	if lr.have && !lr.used {
		return lr.cur, true
	}
	b, err := lr.r.ReadBytes('\n')
	if len(b) == 0 {
		lr.have = false
		if err != nil {
			return nil, false
		}
		return nil, false
	}
	lr.cur = b
	lr.have = true
	lr.used = false
	return lr.cur, true
}

// next marks the current line consumed (cfile_getline_next).
func (lr *lineReader) next() { lr.used = true }
