package mimeparse

import (
	"io"
	"os"
	"strings"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/xmltree"
)

// MaxFileSize is CMIMEMAXFILESIZE: decoded output files are split once they
// reach this many bytes, emitting an additional <tempname> node per split.
const MaxFileSize = 524290

// BuildNumber matches the C BUILDNUMBER (Makefile) and is embedded as the
// parser_version in the output XML.
const BuildNumber = "649"

// Parser holds the state for parsing one email message.
type Parser struct {
	log       *clog.Logger
	lr        *lineReader
	tmpDir    string
	tmpPrefix string
}

// NewParser creates a parser reading the message from r. tmpPattern is the
// cfile-style temp path (e.g. "/tmp/cerbmime_XXXXXX"); its directory and prefix
// are used when creating temp files for extracted body parts.
func NewParser(log *clog.Logger, r io.Reader, tmpPattern string) *Parser {
	dir, prefix := splitPattern(tmpPattern)
	return &Parser{log: log, lr: newLineReader(r), tmpDir: dir, tmpPrefix: prefix}
}

func splitPattern(pat string) (dir, prefix string) {
	if i := strings.LastIndexAny(pat, "/\\"); i >= 0 {
		dir = pat[:i]
		prefix = pat[i+1:]
	} else {
		dir = "."
		prefix = pat
	}
	prefix = strings.TrimRight(prefix, "X")
	if prefix == "" {
		prefix = "cerbmime_"
	}
	if dir == "" {
		dir = "."
	}
	return dir, prefix
}

// mkTemp creates a new temp file for decoded output and returns it. The caller
// is responsible for closing it; the file's name is recorded in the XML.
func (p *Parser) mkTemp() (*os.File, error) {
	return os.CreateTemp(p.tmpDir, p.tmpPrefix+"*")
}

func (p *Parser) logf(level clog.Level, format string, args ...any) {
	if p.log != nil {
		p.log.Log(level, format, args...)
	}
}

// isspace822 matches the C isspace macro: space, \f, \n, \r, \t, \v.
func isspace822(c byte) bool {
	return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v'
}

// isFoldWS matches the leading-whitespace set used for header continuation
// lines in cmime_parse_822: \f, \t, \v, space (not \r or \n).
func isFoldWS(c byte) bool {
	return c == '\f' || c == '\t' || c == '\v' || c == ' '
}

// cAtoi mimics C atoi over bytes: optional leading whitespace and sign, then
// leading decimal digits; returns 0 when no digits are present.
func cAtoi(b []byte) int {
	i, n := 0, len(b)
	for i < n && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	sign := 1
	if i < n && (b[i] == '+' || b[i] == '-') {
		if b[i] == '-' {
			sign = -1
		}
		i++
	}
	val := 0
	for i < n && b[i] >= '0' && b[i] <= '9' {
		val = val*10 + int(b[i]-'0')
		i++
	}
	return sign * val
}

// parentBoundary returns the parent-boundary bytes for a <sub> part, or nil.
func parentBoundary(sub *xmltree.Node) []byte {
	if bn := sub.Get("sub", "parent-boundary"); bn != nil {
		return bn.Data
	}
	return nil
}

// asciiLower returns a copy with ASCII A-Z lowered, preserving byte length so
// offsets computed against it stay valid for the original (mirrors
// cstring_strlower, which is byte-wise ASCII).
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}
