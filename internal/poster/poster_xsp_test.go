package poster

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/crypt"
	"cerb2-goparser/internal/xmltree"
)

func TestDeliverXSP(t *testing.T) {
	var serverURL string
	var bootSeen, parserSeen bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		if r.FormValue("action") == "boot" {
			bootSeen = true
			if r.FormValue("user") != "bootu" || r.FormValue("password") != "bootp" {
				t.Errorf("boot creds = %q/%q, want bootu/bootp", r.FormValue("user"), r.FormValue("password"))
			}
			fmt.Fprintf(w, `<config><key><parser url="%s" user="pu" password="pp"/></key></config>`, serverURL)
			return
		}
		// final parser post
		parserSeen = true
		if r.FormValue("user") != "pu" || r.FormValue("password") != "pp" {
			t.Errorf("parser creds = %q/%q, want pu/pp", r.FormValue("user"), r.FormValue("password"))
		}
		// empty body => delivered
	}))
	defer srv.Close()
	serverURL = srv.URL

	domain := strings.TrimPrefix(srv.URL, "http://")
	plain := strings.Join([]string{
		"Pro", "Acme", "a@b.com", "20200101", "20991231",
		`"` + domain + `"`, "5", "S", "0", "tag",
	}, "\n") + "\n"
	key := crypt.Encrypt([]byte(plain))

	cfgXML := `<configuration><xsp user="bootu" password="bootp">` + key + `</xsp></configuration>`
	cfg, err := config.Load(strings.NewReader(cfgXML), nil)
	if err != nil {
		t.Fatal(err)
	}

	email := xmltree.New("email")
	email.AddChild("headers").AddChild("subject").AddDataString("Hi")

	delivered, err := New(cfg).Deliver(cfg, email, nil)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !bootSeen {
		t.Error("xSP boot request was not made")
	}
	if !parserSeen {
		t.Error("final parser request was not made")
	}
	if !delivered {
		t.Error("delivered = false, want true")
	}
}
