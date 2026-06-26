package mimeparse

import (
	"bytes"
	"os"

	"cerb2-goparser/internal/xmltree"
)

// tnefMagic is the MS-TNEF signature (little-endian INT32 0x223e9f78).
const tnefMagic = 0x223e9f78

// tnefReader is a forward-only cursor over the decoded winmail.dat bytes. All
// cfile seeks in the C are SEEK_CUR with positive offsets, so a position index
// suffices.
type tnefReader struct {
	data []byte
	pos  int
}

func (r *tnefReader) read(n int) []byte {
	if n <= 0 || r.pos >= len(r.data) {
		return nil
	}
	end := r.pos + n
	if end > len(r.data) {
		end = len(r.data)
	}
	b := r.data[r.pos:end]
	r.pos = end
	return b
}

func (r *tnefReader) seek(n int) {
	r.pos += n
	if r.pos > len(r.data) {
		r.pos = len(r.data)
	}
	if r.pos < 0 {
		r.pos = 0
	}
}

func (r *tnefReader) eof() bool { return r.pos >= len(r.data) }

func int32le(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// bodyParseTNEF base64-decodes a winmail.dat body to a temp file, then extracts
// its embedded attachments. Mirrors the 'g' case of cmime_body_parse.
func (p *Parser) bodyParseTNEF(sub *xmltree.Node) {
	f, err := p.mkTemp()
	if err != nil {
		return
	}
	boundary := parentBoundary(sub)
	pw := &partWriter{p: p, cur: f, split: false}
	p.decodeB64(pw, sub, boundary)
	_ = pw.cur.Close()

	data, rerr := os.ReadFile(f.Name())
	_ = os.Remove(f.Name())
	if rerr != nil {
		return
	}
	p.parseTNEF(data, sub)
}

// parseTNEF walks the TNEF stream in data, extracting attachment file names and
// data into temp files attached under a new <sub> of psub. Mirrors
// cmime_parse_tnef.
func (p *Parser) parseTNEF(data []byte, psub *xmltree.Node) {
	r := &tnefReader{data: data}
	sub := psub.AddChild("sub")

	var filenode *xmltree.Node
	var pw *partWriter
	closeCur := func() {
		if pw != nil {
			_ = pw.cur.Close()
			pw = nil
		}
	}

	magic := r.read(4)
	if int32le(magic) != tnefMagic {
		return
	}
	r.seek(2) // skip TNEF key

	for !r.eof() {
		t := r.read(1)
		if len(t) < 1 {
			break
		}
		switch t[0] {
		case 0x01: // message attribute
			r.seek(4)
			if l := r.read(4); len(l) == 4 {
				r.seek(int(int32le(l)) + 2)
			}

		case 0x02: // attachment attribute
			xb := r.read(4)
			if len(xb) < 4 {
				closeCur()
				return
			}
			name := int(int32le(xb) & 0xFFFF)
			lb := r.read(4)
			if len(lb) < 4 {
				closeCur()
				return
			}
			length := int(int32le(lb))

			switch name {
			case 0x800F: // file data
				if pw != nil {
					pw.write(r.read(length))
					r.seek(2) // checksum
				} else {
					r.seek(length + 2)
				}
			case 0x8010: // file name
				d := r.read(length)
				fn := d
				if len(fn) > 0 {
					fn = fn[:len(fn)-1] // drop trailing NUL
				}
				if filenode != nil {
					filenode.AddChild("filename").AddData(fn)
					filenode.AddAttribute("name", cString(d))
				}
				cd := sub.AddChild("content-disposition")
				cd.AddChild("filename").AddData(fn)
				r.seek(2)
			case 0x9002: // beginning of attachment
				closeCur()
				if f, err := p.mkTemp(); err == nil {
					filenode = sub.AddChild("file")
					filenode.AddChild("tempname").AddDataString(f.Name())
					pw = &partWriter{p: p, files: filenode, cur: f, split: true}
				}
				r.seek(length + 2) // fall through: skip the record data + checksum
			default:
				r.seek(length + 2)
			}

		default:
			closeCur()
			return
		}
	}
	closeCur()
}
