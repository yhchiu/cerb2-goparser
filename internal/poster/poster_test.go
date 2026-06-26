package poster

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/xmltree"
)

func buildEmail(attachPath string) *xmltree.Node {
	email := xmltree.New("email")
	h := email.AddChild("headers")
	h.AddChild("subject").AddDataString("Hi")
	f := email.AddChild("file")
	f.AddChild("tempname").AddDataString(attachPath)
	return email
}

func TestDeliverDirectKey(t *testing.T) {
	dir := t.TempDir()
	attach := filepath.Join(dir, "att.bin")
	if err := os.WriteFile(attach, []byte("ATTACHDATA"), 0o644); err != nil {
		t.Fatal(err)
	}

	var fields map[string][]string
	var fileContent string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		fields = r.MultipartForm.Value
		if fh := r.MultipartForm.File[attach]; len(fh) > 0 {
			f, _ := fh[0].Open()
			b, _ := io.ReadAll(f)
			fileContent = string(b)
		}
		w.WriteHeader(http.StatusOK) // empty body => delivered
	}))
	defer srv.Close()

	cfgXML := `<configuration><key><parser url="` + srv.URL +
		`" user="bob" password="pw"/></key></configuration>`
	cfg, err := config.Load(strings.NewReader(cfgXML), nil)
	if err != nil {
		t.Fatal(err)
	}

	email := buildEmail(attach)
	delivered, err := New(cfg).Deliver(cfg, email, nil)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !delivered {
		t.Error("delivered = false, want true (empty response body)")
	}
	if got := fields["user"]; len(got) == 0 || got[0] != "bob" {
		t.Errorf("user field = %v, want bob", got)
	}
	if got := fields["password"]; len(got) == 0 || got[0] != "pw" {
		t.Errorf("password field = %v, want pw", got)
	}
	if got := fields["xml"]; len(got) == 0 || !strings.Contains(got[0], "<email>") {
		t.Errorf("xml field missing <email>: %v", got)
	}
	if fileContent != "ATTACHDATA" {
		t.Errorf("uploaded file = %q, want ATTACHDATA", fileContent)
	}
}

func TestDeliverPHPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "some php error")
	}))
	defer srv.Close()

	cfgXML := `<configuration><key><parser url="` + srv.URL +
		`" user="u" password="p"/></key></configuration>`
	cfg, _ := config.Load(strings.NewReader(cfgXML), nil)

	email := xmltree.New("email")
	email.AddChild("headers")

	delivered, err := New(cfg).Deliver(cfg, email, nil)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if delivered {
		t.Error("delivered = true, want false (non-empty response)")
	}
}

func TestDeliverNoKey(t *testing.T) {
	cfg, _ := config.Load(strings.NewReader(`<configuration></configuration>`), nil)
	email := xmltree.New("email")
	delivered, err := New(cfg).Deliver(cfg, email, nil)
	if delivered {
		t.Error("delivered = true, want false")
	}
	if err == nil {
		t.Error("expected error for missing <key>")
	}
}
