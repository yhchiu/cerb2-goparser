package xmltree

import (
	"bytes"
	"sort"
)

const xmlHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"

// ToString serializes the subtree to XML, reproducing cxml_node_tostring
// byte-for-byte: a UTF-8 declaration at level 0, two-space indentation per
// level, attributes and children emitted in name-sorted order, self-closing
// (" />") empty elements, and CDATA-wrapped character data when it contains any
// byte outside the printable ASCII range or '&'/'<'.
func (n *Node) ToString() []byte {
	if n == nil {
		return nil
	}
	return n.render(0)
}

// String is ToString as a Go string.
func (n *Node) String() string { return string(n.ToString()) }

func (n *Node) render(level int) []byte {
	var cs bytes.Buffer

	if level == 0 {
		cs.WriteString(xmlHeader)
	}

	indent(&cs, level)
	cs.WriteByte('<')
	cs.Write(cleanElement([]byte(n.Name)))

	closed := false

	// attributes, sorted by name
	if len(n.attrs) > 0 {
		keys := make([]string, 0, len(n.attrs))
		for k := range n.attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cs.WriteByte(' ')
			cs.Write(cleanElement([]byte(k)))
			cs.WriteString("=\"")
			cs.Write(cleanAttribute([]byte(n.attrs[k])))
			cs.WriteByte('"')
		}
	}

	// child elements, recursing
	for _, c := range n.sortedChildren() {
		dm := c.render(level + 1)
		if len(dm) > 0 && !closed {
			cs.WriteString(">\n")
			closed = true
		}
		cs.Write(dm)
	}

	// character data
	if len(n.Data) > 0 {
		if !closed {
			cs.WriteString(">\n")
			closed = true
		}
		if needsCDATA(n.Data) {
			indent(&cs, level+1)
			cs.WriteString("<![CDATA[\n")
			indent(&cs, level+2)
			cs.Write(n.Data)
			cs.WriteByte('\n')
			indent(&cs, level+1)
			cs.WriteString("]]>\n")
		} else {
			indent(&cs, level+1)
			cs.Write(n.Data)
			cs.WriteByte('\n')
		}
	} else if !closed {
		cs.WriteString(" />\n")
	}

	if closed {
		indent(&cs, level)
		cs.WriteString("</")
		cs.Write(cleanElement([]byte(n.Name)))
		cs.WriteString(">\n")
	}

	return cs.Bytes()
}

func indent(b *bytes.Buffer, level int) {
	for x := 0; x < level; x++ {
		b.WriteString("  ")
	}
}

// needsCDATA reports whether data must be wrapped in CDATA, matching the C test
// `c<33 || c>126 || c=='&' || c=='<'` over unsigned bytes.
func needsCDATA(data []byte) bool {
	for _, c := range data {
		if c < 33 || c > 126 || c == '&' || c == '<' {
			return true
		}
	}
	return false
}

// cleanElement sanitizes an element or attribute name: if the first byte is not
// [A-Za-z_] the result is prefixed with '_', then only [A-Za-z0-9_.-] bytes are
// kept. Mirrors cxml_node_tostring_clean_element.
func cleanElement(s []byte) []byte {
	out := make([]byte, 0, len(s)+1)
	if len(s) == 0 {
		return out
	}
	first := s[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_') {
		out = append(out, '_')
	}
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '-' {
			out = append(out, c)
		}
	}
	return out
}

// cleanAttribute sanitizes an attribute value, keeping only the byte set
// allowed by cxml_node_tostring_clean_attribute (printable ASCII subsets; all
// bytes >= 0x80 are dropped, matching the C signed-char comparisons).
func cleanAttribute(s []byte) []byte {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= '?' && c <= '~') || (c >= '\'' && c <= ';') ||
			c == ' ' || c == '!' || c == '#' || c == '$' || c == '%' || c == '=' {
			out = append(out, c)
		}
	}
	return out
}
