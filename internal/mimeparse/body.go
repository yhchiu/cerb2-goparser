package mimeparse

import (
	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/xmltree"
)

// FileParse parses a whole email message and returns the <email> node, mirroring
// cmime_file_parse: parse the top-level headers, then dispatch the body.
func (p *Parser) FileParse() *xmltree.Node {
	header := p.HeaderParse()
	if header == nil {
		return nil
	}
	email := xmltree.New("email")
	email.Append(header)
	p.bodyParse(email, "email")
	return email
}

// bodyParse decodes the body of the part contained in sub (whose element name is
// topnode, "email" or "sub"), dispatching on the content-type "case" attribute.
// Mirrors cmime_body_parse.
func (p *Parser) bodyParse(sub *xmltree.Node, topnode string) *xmltree.Node {
	ct := sub.Get(topnode, "headers", "content-type")
	caseAttr, ok := ct.Attribute("case")
	if !ok {
		p.bodyParseDefault(sub)
		return sub
	}

	switch caseAttr {
	case "a":
		p.bodyParseMultipart(sub, ct)
	case "g":
		p.bodyParseTNEF(sub)
	default: // b, c, d, e, f, z
		p.bodyParseDefault(sub)
	}
	return sub
}

// bodyParseMultipart walks a multipart body, recursing into each part delimited
// by the boundary. Mirrors the 'a' case of cmime_body_parse.
func (p *Parser) bodyParseMultipart(sub, ct *xmltree.Node) {
	boundaryNode := ct.Get("content-type", "boundary")
	if boundaryNode == nil {
		return // multipart needs a boundary
	}
	boundary := boundaryNode.Data
	bl := len(boundary)

	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		p.lr.next()
		if len(line) <= 4 {
			continue
		}
		switch {
		case line[0] == '-' && line[1] == '-' && hasBoundaryPrefix(line, boundary):
			c2, c3 := byteAt(line, 2+bl), byteAt(line, 2+bl+1)
			if c2 == '-' && c3 == '-' {
				return // closing boundary
			}
			header := p.HeaderParse()
			if header != nil && header.HasChildren() && c2 != '-' && c3 != '-' {
				part := sub.AddChild("sub")
				part.Append(header)
				pb := part.AddChild("parent-boundary")
				pb.AddData(boundary)
				p.bodyParse(part, "sub")
			} else {
				return
			}
		case line[0] == 'b':
			if name := parseUUBegin(line); name != nil {
				p.parseUU(name, sub, boundary)
			}
		}
	}
}

// bodyParseDefault handles text/octet-stream/unknown bodies: it creates a
// <file> with a <tempname>, derives the original filename, picks the transfer
// encoding from this part's (or the email's) headers, and runs the matching
// decoder. Mirrors the default case of cmime_body_parse.
func (p *Parser) bodyParseDefault(sub *xmltree.Node) {
	f, err := p.mkTemp()
	if err != nil {
		p.logf(clog.Error, "cmime: mkTemp: %v", err)
		return
	}

	filenode := sub.AddChild("file")
	tn := filenode.AddChild("tempname")
	tn.AddDataString(f.Name())

	// original filename: prefer content-disposition filename, else content-type name
	if fn := sub.Get("sub", "headers", "content-disposition", "filename"); fn != nil {
		filenode.AddAttribute("name", string(fn.Data))
		filenode.AddChild("filename").AddData(fn.Data)
	} else if nm := sub.Get("sub", "headers", "content-type", "name"); nm != nil {
		filenode.AddAttribute("name", string(nm.Data))
		filenode.AddChild("filename").AddData(nm.Data)
	}

	// transfer encoding case: from this <sub> part, or the top-level <email>
	var cteCase string
	if sub.Name != "" {
		switch sub.Name[0] {
		case 's':
			cteCase, _ = sub.Get("sub", "headers", "content-transfer-encoding").Attribute("case")
		case 'e':
			cteCase, _ = sub.Get("email", "headers", "content-transfer-encoding").Attribute("case")
		}
	}

	boundaryNode := sub.Get("sub", "parent-boundary")
	var boundary []byte
	if boundaryNode != nil {
		boundary = boundaryNode.Data
	}

	pw := &partWriter{p: p, files: filenode, cur: f, split: true}
	switch cteCase {
	case "a": // base64
		p.decodeB64(pw, sub, boundary)
	case "d": // quoted-printable
		p.decodeQP(pw, sub, boundary)
	case "e": // uuencode: handled by the multipart/boundary scan, nothing here
	default: // 7bit, 8bit, unknown -> raw text
		p.decodeText(pw, sub, boundary)
	}
	_ = pw.cur.Close()
}

// hasBoundaryPrefix reports whether line[2:] starts with boundary.
func hasBoundaryPrefix(line, boundary []byte) bool {
	if len(line)-2 < len(boundary) {
		return false
	}
	for i := 0; i < len(boundary); i++ {
		if line[2+i] != boundary[i] {
			return false
		}
	}
	return true
}

func byteAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}
