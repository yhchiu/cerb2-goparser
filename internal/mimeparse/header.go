package mimeparse

import (
	"bytes"

	"cerb2-goparser/internal/xmltree"
)

// HeaderParse reads RFC-822 headers up to the blank line and returns a
// <headers> node. It then derives the content-type / content-transfer-encoding
// "case" attributes and extracts content-type/disposition parameters, exactly
// as cmime_header_parse does.
func (p *Parser) HeaderParse() *xmltree.Node {
	root := xmltree.New("headers")
	var node *xmltree.Node

	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		p.lr.next()
		node = parse822(root, line, node)
		if node == nil {
			break
		}
	}

	// content-type case + parameters
	if ct := root.Get("headers", "content-type"); ct != nil && len(ct.Data) > 0 {
		dupe := asciiLower(ct.Data)
		ct.AddAttribute("case", contentTypeCase(dupe))
		headerParseCT(dupe, ct, "boundary")
		headerParseCT(dupe, ct, "charset")
		headerParseCT(dupe, ct, "name")
	} else {
		// boundary found but no content type: mark unknown
		n := root.AddChild("content-type")
		n.AddDataString("unknown")
		n.AddAttribute("case", "z")
	}

	// content-disposition parameters (filename, size)
	if cd := root.Get("headers", "content-disposition"); cd != nil && len(cd.Data) > 0 {
		dupe := asciiLower(cd.Data)
		headerParseCT(dupe, cd, "filename")
		headerParseCT(dupe, cd, "size")
	}

	// content-transfer-encoding case
	if cte := root.Get("headers", "content-transfer-encoding"); cte != nil && len(cte.Data) > 0 {
		dupe := asciiLower(cte.Data)
		cte.AddAttribute("case", transferEncodingCase(dupe))
	}

	// content-disposition kind (inline / attachment / form-data)
	if cd := root.Get("headers", "content-disposition"); cd != nil && len(cd.Data) > 0 {
		dupe := asciiLower(cd.Data)
		switch {
		case bytes.Contains(dupe, []byte("inline")):
			cd.AddAttribute("inline", "true")
		case bytes.Contains(dupe, []byte("attachment")):
			cd.AddAttribute("attachment", "true")
		case bytes.Contains(dupe, []byte("form-data")):
			cd.AddAttribute("form-data", "true")
		}
	}

	return root
}

func contentTypeCase(dupe []byte) string {
	switch {
	case bytes.Contains(dupe, []byte("multipart/")):
		return "a"
	case bytes.Contains(dupe, []byte("text/plain")):
		return "b"
	case bytes.Contains(dupe, []byte("text/html")):
		return "c"
	case bytes.Contains(dupe, []byte("text/")):
		return "d"
	case bytes.Contains(dupe, []byte("message/rfc822")):
		return "e"
	case bytes.Contains(dupe, []byte("/octet-stream")):
		return "f"
	case bytes.Contains(dupe, []byte("/ms-tnef")):
		return "g"
	default:
		return "z"
	}
}

func transferEncodingCase(dupe []byte) string {
	switch {
	case bytes.Contains(dupe, []byte("base64")):
		return "a"
	case bytes.Contains(dupe, []byte("7bit")):
		return "b"
	case bytes.Contains(dupe, []byte("8bit")):
		return "c"
	case bytes.Contains(dupe, []byte("quoted-printable")):
		return "d"
	case bytes.Contains(dupe, []byte("uuencode")):
		return "e"
	default:
		return "z"
	}
}

// headerParseCT extracts a parameter (boundary, charset, name, filename, size)
// from a header value, matching cmime_header_parse_ct. The search runs over the
// lowercased dupe but the captured value bytes come from the original (node)
// data at the same offsets, so the value preserves its original case.
//
// Faithful quirk: the tag is matched with a plain substring search, so e.g.
// searching "name" can match inside "filename" — reproduced here.
func headerParseCT(dupe []byte, node *xmltree.Node, tagname string) {
	orig := node.Data
	if bytes.IndexByte(dupe, ';') < 0 {
		return
	}
	tpos := bytes.Index(dupe, []byte(tagname))
	if tpos < 0 {
		return
	}
	eq := bytes.IndexByte(dupe[tpos:], '=')
	if eq < 0 {
		return
	}
	posa := tpos + eq + 1
	for posa < len(dupe) && isspace822(dupe[posa]) {
		posa++
	}
	if posa >= len(dupe) {
		return
	}
	quoted := false
	if dupe[posa] == '"' {
		quoted = true
		posa++
	}
	posb := posa
	if quoted {
		for posb < len(dupe) && dupe[posb] != '"' {
			posb++
		}
	} else {
		for posb < len(dupe) && !isspace822(dupe[posb]) && dupe[posb] != '"' && dupe[posb] != ';' {
			posb++
		}
	}
	snode := node.AddChild(tagname)
	end := posb
	if end > len(orig) {
		end = len(orig)
	}
	if posa <= end {
		snode.AddData(orig[posa:end])
	}
}

// parse822 parses one header line (terminator included) into root, returning the
// node future continuation lines should append to. nil signals end of headers.
// Mirrors cmime_parse_822.
func parse822(root *xmltree.Node, line []byte, last *xmltree.Node) *xmltree.Node {
	if root == nil || len(line) == 0 {
		return nil
	}

	// continuation (folded) line
	if isFoldWS(line[0]) {
		i := 0
		for i < len(line) && isFoldWS(line[i]) {
			i++
		}
		contentEnd := len(line) - 2 // strip \r\n
		if contentEnd < i {
			contentEnd = i
		}
		// append " " + unfolded content
		val := make([]byte, 0, contentEnd-i+1)
		val = append(val, ' ')
		val = append(val, line[i:contentEnd]...)
		if last != nil {
			last.AddData(val)
		}
		if i+1 < len(line) && line[i] == '\r' && line[i+1] == '\n' {
			return nil
		}
		return last
	}

	// blank line: end of headers
	if len(line) >= 2 && line[0] == '\r' && line[1] == '\n' {
		return nil
	}

	// normal header: scan for ": " or ":\t", lowercasing the name as we go
	name := make([]byte, 0, len(line))
	colon := -1
	for pos := 0; pos < len(line); pos++ {
		c := line[pos]
		if c == ':' && pos+1 < len(line) && (line[pos+1] == ' ' || line[pos+1] == '\t') {
			colon = pos
			break
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		name = append(name, c)
	}

	// no header separator found: return root so a following folded line appends
	// to it (matches the C generic-line behavior)
	if colon < 0 {
		return root
	}

	node := root.AddChild(string(name))
	if len(line)-colon > 2 {
		v := colon + 2
		for v < len(line) && isspace822(line[v]) {
			v++
		}
		contentEnd := len(line) - 2
		if v < contentEnd {
			node.AddData(line[v:contentEnd])
		}
	}
	return node
}
