package xmltree

import "testing"

// TestToStringGolden reproduces the assertion embedded in cxml_node_tostring.c
// (Test__cxml_node_tostring), the canonical wire-format vector.
func TestToStringGolden(t *testing.T) {
	a := New("a")
	b := a.AddChild("b")
	a.AddChild("c")
	d := b.AddChild("d")
	d.AddDataString("test")
	d.AddAttribute("test", "value")

	want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a>\n  <b>\n    <d test=\"value\">\n      test\n    </d>\n  </b>\n  <c />\n</a>\n"
	if got := a.String(); got != want {
		t.Errorf("ToString mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestChildOrdering checks children serialize sorted by name (not insertion
// order), matching the C red-black child dict.
func TestChildOrdering(t *testing.T) {
	root := New("root")
	root.AddChild("zebra")
	root.AddChild("apple")
	root.AddChild("mango")

	want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n  <apple />\n  <mango />\n  <zebra />\n</root>\n"
	if got := root.String(); got != want {
		t.Errorf("child ordering mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestCDATA checks that data with non-printable / special bytes is CDATA-wrapped.
func TestCDATA(t *testing.T) {
	n := New("x")
	n.AddDataString("a < b & c")
	want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<x>\n  <![CDATA[\n    a < b & c\n  ]]>\n</x>\n"
	if got := n.String(); got != want {
		t.Errorf("cdata mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestGet(t *testing.T) {
	a := New("a")
	b := a.AddChild("b")
	a.AddChild("c")
	d := b.AddChild("d")

	if got := a.Get("a", "b", "d"); got != d {
		t.Errorf("Get path a/b/d = %v, want d", got)
	}
	if got := a.Get("a", "c", "e"); got != nil {
		t.Errorf("Get missing path = %v, want nil", got)
	}
	if got := a.Get("x"); got != nil {
		t.Errorf("Get wrong root = %v, want nil", got)
	}
}

// TestNext mirrors Test__cxml_node_next: three children named "bcd" iterate in
// insertion order.
func TestNext(t *testing.T) {
	a := New("a")
	b := a.AddChild("bcd")
	c := a.AddChild("bcd")
	d := a.AddChild("bcd")

	a.Iterate()
	if got := a.Next("bcd"); got != b {
		t.Errorf("Next #1 = %v, want b", got)
	}
	if got := a.Next("bcd"); got != c {
		t.Errorf("Next #2 = %v, want c", got)
	}
	if got := a.Next("bcd"); got != d {
		t.Errorf("Next #3 = %v, want d", got)
	}
	if got := a.Next("bcd"); got != nil {
		t.Errorf("Next #4 = %v, want nil", got)
	}
}

func TestReadRoundTrip(t *testing.T) {
	src := `<configuration>
	  <key>
	    <parser user="name" password="pw" url="http://localhost/parser.php" />
	  </key>
	  <global>
	    <tmp_dir value="/tmp/" />
	  </global>
	</configuration>`

	root, err := ReadString(src)
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if root == nil || root.Name != "configuration" {
		t.Fatalf("root = %v, want <configuration>", root)
	}
	parser := root.Get("configuration", "key", "parser")
	if parser == nil {
		t.Fatal("could not find configuration/key/parser")
	}
	if v, _ := parser.Attribute("user"); v != "name" {
		t.Errorf("parser@user = %q, want name", v)
	}
	if v, _ := parser.Attribute("url"); v != "http://localhost/parser.php" {
		t.Errorf("parser@url = %q, want url", v)
	}
	tmp := root.Get("configuration", "global", "tmp_dir")
	if v, _ := tmp.Attribute("value"); v != "/tmp/" {
		t.Errorf("tmp_dir@value = %q, want /tmp/", v)
	}
}

func TestReadCharDataTrim(t *testing.T) {
	// cxml_fn_data trims leading spaces and trailing \n\r\t (not trailing spaces).
	root, err := ReadString("<xsp https=\"true\">   ABCDEF0123\n\t</xsp>")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if string(root.Data) != "ABCDEF0123" {
		t.Errorf("xsp data = %q, want ABCDEF0123", root.Data)
	}
	if v, _ := root.Attribute("https"); v != "true" {
		t.Errorf("xsp@https = %q, want true", v)
	}
}
