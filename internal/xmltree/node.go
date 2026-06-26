// Package xmltree is a faithful Go port of the C "cxml" DOM. It models the
// CXMLNODE tree (name, character data, attributes, child elements) and
// reproduces cxml_node_tostring's serialization byte-for-byte so the XML posted
// to the Cerberus backend is wire-identical to the original C parser.
//
// Children are stored in insertion order but serialized and iterated in
// name-sorted order, because the C code backs them with a red-black dict keyed
// by element name (dict_first/dict_next walk in sorted order, ties broken by
// insertion order). Attributes are likewise emitted sorted by name.
package xmltree

import "sort"

// Node is one element in the tree. The zero value is not usable; create nodes
// with New or (*Node).AddChild.
type Node struct {
	Name     string
	Data     []byte // raw character data; may be appended to repeatedly
	attrs    map[string]string
	children []*Node
	parent   *Node
	last     int // iterator cursor into the sorted child view; -1 == not started
}

// New creates a detached node with the given name. A node must have a name, so
// an empty name yields nil, matching cxml_node_create.
func New(name string) *Node {
	if name == "" {
		return nil
	}
	return &Node{Name: name, last: -1}
}

// AddChild creates a child element with the given name, appends it, and returns
// it. Equivalent to cxml_node_create(parent, name).
func (n *Node) AddChild(name string) *Node {
	c := New(name)
	if c == nil {
		return nil
	}
	n.Append(c)
	return c
}

// Append attaches an already-built subtree as a child. Equivalent to
// cxml_node_addnode.
func (n *Node) Append(child *Node) {
	if n == nil || child == nil {
		return
	}
	child.parent = n
	n.children = append(n.children, child)
}

// Parent returns the node's parent, or nil for a root.
func (n *Node) Parent() *Node {
	if n == nil {
		return nil
	}
	return n.parent
}

// HasChildren reports whether the node has any child elements.
func (n *Node) HasChildren() bool {
	return n != nil && len(n.children) > 0
}

// Children returns a copy of the child nodes in insertion order.
func (n *Node) Children() []*Node {
	if n == nil || len(n.children) == 0 {
		return nil
	}
	out := make([]*Node, len(n.children))
	copy(out, n.children)
	return out
}

// AddData appends raw bytes to the node's character data. Equivalent to
// cxml_node_adddata (plain concatenation, no separator).
func (n *Node) AddData(data []byte) {
	if n == nil || len(data) == 0 {
		return
	}
	n.Data = append(n.Data, data...)
}

// AddDataString is AddData for a string.
func (n *Node) AddDataString(s string) { n.AddData([]byte(s)) }

// SetData replaces the node's character data.
func (n *Node) SetData(data []byte) {
	if n == nil {
		return
	}
	n.Data = data
}

// AddAttribute adds an attribute. Like the C dict (no duplicates allowed), the
// first value written for a name wins.
func (n *Node) AddAttribute(name, value string) {
	if n == nil || name == "" {
		return
	}
	if n.attrs == nil {
		n.attrs = make(map[string]string)
	}
	if _, ok := n.attrs[name]; !ok {
		n.attrs[name] = value
	}
}

// Attribute returns the value of a named attribute and whether it was present.
// Equivalent to cxml_node_getattribute.
func (n *Node) Attribute(name string) (string, bool) {
	if n == nil || n.attrs == nil {
		return "", false
	}
	v, ok := n.attrs[name]
	return v, ok
}

// childByName returns the first child (in insertion order, which is also the
// lowest in sorted order among equal names) with the given name.
func (n *Node) childByName(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Get walks a path of element names starting at this node. The first segment
// must equal this node's name; each remaining segment descends to the first
// matching child. Returns nil if any segment fails to match. Equivalent to the
// variadic cxml_node_get(node, "a", "b", ... , NULL).
func (n *Node) Get(path ...string) *Node {
	if n == nil || len(path) == 0 {
		return nil
	}
	if n.Name != path[0] {
		return nil
	}
	cur := n
	for _, seg := range path[1:] {
		next := cur.childByName(seg)
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// sortedChildren returns the children stably sorted by name, mirroring the
// in-order traversal of the C red-black child dict.
func (n *Node) sortedChildren() []*Node {
	if len(n.children) == 0 {
		return nil
	}
	out := make([]*Node, len(n.children))
	copy(out, n.children)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Iterate resets the sibling iterator used by Next, matching cxml_node_iterate.
func (n *Node) Iterate() {
	if n != nil {
		n.last = -1
	}
}

// Next returns successive children equal to match, in iteration order. It
// reproduces cxml_node_next: the first call (after Iterate) finds the first
// matching child; later calls advance to the next child in sorted order and
// return it only if it still equals match (otherwise nil, ending the run).
func (n *Node) Next(match string) *Node {
	if n == nil || len(n.children) == 0 {
		return nil
	}
	sorted := n.sortedChildren()
	if n.last < 0 {
		for i, c := range sorted {
			if c.Name == match {
				n.last = i
				return c
			}
		}
		return nil
	}
	idx := n.last + 1
	if idx >= len(sorted) {
		return nil
	}
	n.last = idx
	c := sorted[idx]
	if c.Name != match {
		return nil
	}
	return c
}
