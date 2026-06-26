package config

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	src := `<configuration>
  <debug>
    <xml value="1" />
    <parse value="1" />
  </debug>
  <xsp https="true" user="u" password="p">DEADBEEF</xsp>
  <global>
    <tmp_dir value="/tmp/" />
    <max_pop3_messages value="5" />
    <pop3_timeout value="20" />
    <max_pop3_delete value="false" />
  </global>
  <ssl>
    <verify value="2" />
  </ssl>
  <pop3>
    <host value="mail.example.com" />
    <port value="995" />
    <user value="bob" />
    <password value="secret" />
    <delete value="false" />
  </pop3>
  <pop3>
    <host value="mail2.example.com" />
  </pop3>
</configuration>`

	cfg, err := Load(strings.NewReader(src), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.XSP != "DEADBEEF" {
		t.Errorf("XSP = %q, want DEADBEEF", cfg.XSP)
	}
	if !cfg.ParserHTTPS {
		t.Error("ParserHTTPS = false, want true")
	}
	if cfg.ParserUser != "u" || cfg.ParserPass != "p" {
		t.Errorf("parser creds = %q/%q, want u/p", cfg.ParserUser, cfg.ParserPass)
	}
	if cfg.TmpMimePattern != "/tmp/cerbmime_XXXXXX" {
		t.Errorf("TmpMimePattern = %q", cfg.TmpMimePattern)
	}
	if cfg.POP3Max != 5 {
		t.Errorf("POP3Max = %d, want 5", cfg.POP3Max)
	}
	if cfg.POP3Timeout != 20 {
		t.Errorf("POP3Timeout = %d, want 20", cfg.POP3Timeout)
	}
	if cfg.POP3MaxDelete {
		t.Error("POP3MaxDelete = true, want false")
	}
	if cfg.Verify != 2 {
		t.Errorf("Verify = %d, want 2", cfg.Verify)
	}
	if !cfg.DebugParse || !cfg.PrintXML {
		t.Errorf("debug flags: parse=%v xml=%v", cfg.DebugParse, cfg.PrintXML)
	}
	if len(cfg.POP3) != 2 {
		t.Fatalf("POP3 accounts = %d, want 2", len(cfg.POP3))
	}
	a := cfg.POP3[0]
	if a.Host != "mail.example.com" || a.Port != 995 || a.User != "bob" || a.Pass != "secret" || a.Delete {
		t.Errorf("pop3[0] = %+v", a)
	}
	b := cfg.POP3[1]
	if b.Host != "mail2.example.com" || b.Port != 110 || !b.Delete {
		t.Errorf("pop3[1] defaults = %+v", b)
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(strings.NewReader(`<configuration></configuration>`), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.POP3Max != 1024 || cfg.POP3Timeout != 30 || cfg.Verify != -1 || !cfg.POP3MaxDelete {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	if len(cfg.POP3) != 0 {
		t.Errorf("expected no pop3 accounts, got %d", len(cfg.POP3))
	}
}
