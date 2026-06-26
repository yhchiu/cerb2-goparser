package mimeparse

import "cerb2-goparser/internal/xmltree"

// dec decodes one uuencode character: ((c - ' ') & 077).
func dec(c byte) byte { return byte((int(c) - ' ') & 0o77) }

// isDec reports whether c is a valid uuencode character (' '..'`').
func isDec(c byte) bool {
	v := int(c) - ' '
	return v >= 0 && v <= 0o77+1
}

// parseUUBegin returns the filename from a uuencode "begin <mode> <name>" line
// (mode must parse to 1..777), or nil otherwise. Mirrors cmime_parse_uu_begin.
func parseUUBegin(line []byte) []byte {
	if len(line) < 5 || string(line[:5]) != "begin" {
		return nil
	}
	i := 0
	for i < len(line) && line[i] != ' ' && line[i] != 0 {
		i++
	}
	if i >= len(line) || line[i] != ' ' {
		return nil
	}
	i++
	modeStart := i
	for i < len(line) && line[i] != ' ' && line[i] != 0 {
		i++
	}
	if i >= len(line) || line[i] != ' ' {
		return nil
	}
	mode := cAtoi(line[modeStart:i])
	if !(mode > 0 && mode <= 777) {
		return nil
	}
	i++
	nameStart := i
	for i < len(line) && line[i] != '\r' && line[i] != 0 {
		i++
	}
	if i > nameStart {
		name := make([]byte, i-nameStart)
		copy(name, line[nameStart:i])
		return name
	}
	return nil
}

// uuDecodeLine decodes one uuencoded line, returning the decoded bytes and
// whether decoding should stop (an invalid character was hit). Mirrors the inner
// decode loop of cmime_parse_uu.
func uuDecodeLine(line []byte) (out []byte, stop bool) {
	if len(line) == 0 {
		return nil, false
	}
	n := int(dec(line[0]))
	if n <= 0 {
		return nil, false
	}
	i := 1
	at := func(j int) byte { return byteAt(line, j) }
	for n > 0 {
		if n >= 3 {
			if !isDec(at(i)) && !isDec(at(i+1)) && !isDec(at(i+2)) && !isDec(at(i+3)) {
				return out, true
			}
			out = append(out, dec(at(i))<<2|dec(at(i+1))>>4)
			out = append(out, dec(at(i+1))<<4|dec(at(i+2))>>2)
			out = append(out, dec(at(i+2))<<6|dec(at(i+3)))
		} else {
			if n >= 1 {
				if !(isDec(at(i)) && isDec(at(i+1))) {
					return out, true
				}
				out = append(out, dec(at(i))<<2|dec(at(i+1))>>4)
			}
			if n >= 2 {
				if !(isDec(at(i+1)) && isDec(at(i+2))) {
					return out, true
				}
				out = append(out, dec(at(i+1))<<4|dec(at(i+2))>>2)
			}
		}
		i += 4
		n -= 3
	}
	return out, false
}

// parseUU decodes a uuencoded section into a temp file, attaching a <sub> with
// <file>/<filename>/<tempname> and a <content-disposition> to psub. Mirrors
// cmime_parse_uu.
func (p *Parser) parseUU(filename []byte, psub *xmltree.Node, boundary []byte) {
	f, err := p.mkTemp()
	if err != nil {
		return
	}
	sub := psub.AddChild("sub")
	filenode := sub.AddChild("file")
	filenode.AddAttribute("name", string(filename))
	filenode.AddChild("filename").AddData(filename)
	filenode.AddChild("tempname").AddDataString(f.Name())
	cd := sub.AddChild("content-disposition")
	cd.AddChild("filename").AddData(filename)

	pw := &partWriter{p: p, files: filenode, cur: f, split: true}
	for {
		line, ok := p.lr.getLine()
		if !ok {
			break
		}
		if len(line) > 2 {
			if boundary != nil && line[0] == '-' && line[1] == '-' && hasBoundaryPrefix(line, boundary) {
				break // leave boundary unconsumed for the caller
			}
			if line[0] == 'e' && line[1] == 'n' && line[2] == 'd' {
				p.lr.next()
				break
			}
		}
		decoded, stop := uuDecodeLine(line)
		pw.write(decoded)
		p.lr.next()
		if stop {
			break
		}
	}
	_ = pw.cur.Close()
}
