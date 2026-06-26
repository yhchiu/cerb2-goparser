package xmltree

import (
	"encoding/xml"
	"io"
	"strings"
)

// Read parses XML from r into a Node tree, mirroring the cxml expat callbacks
// (cxml_fn_start/end/data): each start element becomes a child node carrying its
// attributes; character data is trimmed (leading spaces, trailing \n\r\t) and
// appended to the current node, separated by a single space when that node
// already holds data. Comments and processing instructions are ignored.
func Read(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var root *Node
	var stack []*Node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			node := New(t.Name.Local)
			for _, a := range t.Attr {
				node.AddAttribute(a.Name.Local, a.Value)
			}
			if len(stack) > 0 {
				stack[len(stack)-1].Append(node)
			} else if root == nil {
				root = node
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			node := stack[len(stack)-1]
			trimmed := trimData([]byte(t))
			if len(trimmed) > 0 {
				if len(node.Data) > 0 {
					node.AddData([]byte(" "))
				}
				node.AddData(trimmed)
			}
		}
	}
	return root, nil
}

// ReadString parses XML from a string into a Node tree.
func ReadString(s string) (*Node, error) { return Read(strings.NewReader(s)) }

// trimData trims leading ' ' and trailing '\n','\r','\t', matching cxml_fn_data.
func trimData(b []byte) []byte {
	end := len(b)
	for end > 0 {
		switch b[end-1] {
		case '\n', '\r', '\t':
			end--
			continue
		}
		break
	}
	start := 0
	for start < end && b[start] == ' ' {
		start++
	}
	return b[start:end]
}
