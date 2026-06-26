// Package config loads the Cerberus XML configuration file into a Config,
// mirroring cer_load_config.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/xmltree"
)

// POP3Account is one <pop3> mailbox to fetch from.
type POP3Account struct {
	Host   string
	Port   int
	User   string
	Pass   string
	Delete bool
}

// IMAPAccount is one <imap> mailbox to fetch from.
type IMAPAccount struct {
	Host    string
	Port    int
	User    string
	Pass    string
	Delete  bool
	TLS     bool   // implicit TLS (e.g. port 993)
	Mailbox string // defaults to INBOX
}

// Config holds the parsed configuration. Zero-value defaults are set by Load.
type Config struct {
	// xSP key + parser credentials
	XSP         string
	ParserHTTPS bool
	ParserUser  string
	ParserPass  string

	// temp file patterns (directory + cfile-style XXXXXX suffix)
	TmpMailPattern string // for the saved incoming message
	TmpMimePattern string // for extracted MIME body parts

	// POP3 behavior
	POP3Max       int  // max messages per run (default 1024)
	POP3MaxDelete bool // delete everything we can (default true)
	POP3Timeout   int  // read timeout seconds (default 30)

	// TLS
	CAInfo string
	CAPath string
	Verify int // -1 = unset; else 0/1/2

	LibCurl string // accepted for compatibility, unused (Go uses net/http)

	// CharsetUTF8 enables converting RFC-2047 encoded-word subjects to UTF-8.
	// Off by default to match the C (whose ICU conversion was disabled).
	CharsetUTF8 bool

	// CharsetUTF8Body enables converting text/* part bodies to UTF-8. Controlled
	// separately from CharsetUTF8 and off by default.
	CharsetUTF8Body bool

	// debug flags
	PrintXML   bool
	PrintCurl  bool
	SuperClean bool
	DebugParse bool

	POP3 []POP3Account
	IMAP []IMAPAccount

	// Root is the parsed <configuration> element, retained so the poster can
	// read a direct <key><parser> when no xSP key is configured.
	Root *xmltree.Node
}

// TLSConfig builds a *tls.Config from the ssl settings: verify 0 disables
// certificate verification, and cainfo/capath add trusted roots. Shared by the
// HTTP poster and the IMAP client.
func TLSConfig(cfg *Config) *tls.Config {
	t := &tls.Config{}
	if cfg.Verify == 0 {
		t.InsecureSkipVerify = true
	}
	if cfg.CAInfo != "" || cfg.CAPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if cfg.CAInfo != "" {
			if pem, err := os.ReadFile(cfg.CAInfo); err == nil {
				pool.AppendCertsFromPEM(pem)
			}
		}
		if cfg.CAPath != "" {
			if entries, err := os.ReadDir(cfg.CAPath); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					if pem, err := os.ReadFile(filepath.Join(cfg.CAPath, e.Name())); err == nil {
						pool.AppendCertsFromPEM(pem)
					}
				}
			}
		}
		t.RootCAs = pool
	}
	return t
}

// Load parses the configuration XML from r.
func Load(r io.Reader, log *clog.Logger) (*Config, error) {
	cfg := &Config{
		POP3Max:       1024,
		POP3Timeout:   30,
		Verify:        -1,
		POP3MaxDelete: true,
	}

	root, err := xmltree.Read(r)
	if err != nil {
		return nil, err
	}
	if root == nil || root.Name != "configuration" {
		return nil, fmt.Errorf("config: missing <configuration> root element")
	}
	cfg.Root = root

	// xSP key + credentials
	if n := root.Get("configuration", "xsp"); n != nil {
		cfg.XSP = string(n.Data)
		if v, _ := n.Attribute("https"); v == "true" {
			cfg.ParserHTTPS = true
		}
		if v, ok := n.Attribute("user"); ok {
			cfg.ParserUser = v
			if pw, ok := n.Attribute("password"); ok {
				cfg.ParserPass = pw
			}
		}
	}

	// tmp_dir -> temp patterns
	tmpPath := ""
	if v, ok := attr(root.Get("configuration", "global", "tmp_dir"), "value"); ok {
		tmpPath = v
		if tmpPath != "" {
			if last := tmpPath[len(tmpPath)-1]; last != '/' && last != '\\' {
				tmpPath += string(os.PathSeparator)
				log.Log(clog.Warn, "XML: Trailing slash was not on the tmp_dir element. I added one! (%s)", tmpPath)
			}
		}
	} else {
		log.Log(clog.Warn, "tmp_dir not found in xml config file, using current directory")
	}
	cfg.TmpMailPattern = tmpPath + "cerbmail_XXXXXX"
	cfg.TmpMimePattern = tmpPath + "cerbmime_XXXXXX"

	// debug flags
	cfg.PrintXML = atoiNode(root.Get("configuration", "debug", "xml")) != 0
	cfg.PrintCurl = atoiNode(root.Get("configuration", "debug", "curl")) != 0
	cfg.DebugParse = atoiNode(root.Get("configuration", "debug", "parse")) != 0
	cfg.SuperClean = atoiNode(root.Get("configuration", "debug", "superclean")) != 0

	// TLS
	if v, ok := attr(root.Get("configuration", "ssl", "cainfo"), "value"); ok {
		cfg.CAInfo = v
	}
	if v, ok := attr(root.Get("configuration", "ssl", "capath"), "value"); ok {
		cfg.CAPath = v
	}
	if v, ok := attr(root.Get("configuration", "ssl", "verify"), "value"); ok {
		cfg.Verify = atoi(v)
	}

	// global
	if v, ok := attr(root.Get("configuration", "global", "max_pop3_messages"), "value"); ok {
		cfg.POP3Max = atoi(v)
	}
	if v, ok := attr(root.Get("configuration", "global", "max_pop3_delete"), "value"); ok && v == "false" {
		cfg.POP3MaxDelete = false
	}
	if v, ok := attr(root.Get("configuration", "global", "pop3_timeout"), "value"); ok {
		cfg.POP3Timeout = atoi(v)
		if cfg.POP3Timeout <= 0 {
			cfg.POP3Timeout = 30
		}
	}
	if v, ok := attr(root.Get("configuration", "global", "libcurl"), "value"); ok && len(v) > 7 {
		cfg.LibCurl = v
	}
	if v, ok := attr(root.Get("configuration", "global", "charset_utf8"), "value"); ok && v == "true" {
		cfg.CharsetUTF8 = true
	}
	if v, ok := attr(root.Get("configuration", "global", "charset_utf8_body"), "value"); ok && v == "true" {
		cfg.CharsetUTF8Body = true
	}

	// pop3 blocks (a host is required to register an account)
	root.Iterate()
	for {
		n := root.Next("pop3")
		if n == nil {
			break
		}
		host, ok := attr(n.Get("pop3", "host"), "value")
		if !ok {
			continue
		}
		acct := POP3Account{Host: host, Port: 110, Delete: true}
		if v, ok := attr(n.Get("pop3", "port"), "value"); ok {
			acct.Port = atoi(v)
		}
		if v, ok := attr(n.Get("pop3", "user"), "value"); ok {
			acct.User = v
		}
		if v, ok := attr(n.Get("pop3", "password"), "value"); ok {
			acct.Pass = v
		}
		if v, ok := attr(n.Get("pop3", "delete"), "value"); ok && v == "false" {
			acct.Delete = false
		}
		cfg.POP3 = append(cfg.POP3, acct)
	}

	// imap blocks
	root.Iterate()
	for {
		n := root.Next("imap")
		if n == nil {
			break
		}
		host, ok := attr(n.Get("imap", "host"), "value")
		if !ok {
			continue
		}
		acct := IMAPAccount{Host: host, Delete: true, Mailbox: "INBOX"}
		if v, ok := attr(n.Get("imap", "tls"), "value"); ok && v == "true" {
			acct.TLS = true
		}
		if v, ok := attr(n.Get("imap", "port"), "value"); ok {
			acct.Port = atoi(v)
		} else if acct.TLS {
			acct.Port = 993
		} else {
			acct.Port = 143
		}
		if v, ok := attr(n.Get("imap", "user"), "value"); ok {
			acct.User = v
		}
		if v, ok := attr(n.Get("imap", "password"), "value"); ok {
			acct.Pass = v
		}
		if v, ok := attr(n.Get("imap", "delete"), "value"); ok && v == "false" {
			acct.Delete = false
		}
		if v, ok := attr(n.Get("imap", "mailbox"), "value"); ok && v != "" {
			acct.Mailbox = v
		}
		cfg.IMAP = append(cfg.IMAP, acct)
	}

	return cfg, nil
}

// LoadFile loads configuration from a file path.
func LoadFile(path string, log *clog.Logger) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f, log)
}

func attr(n *xmltree.Node, name string) (string, bool) {
	if n == nil {
		return "", false
	}
	return n.Attribute(name)
}

func atoiNode(n *xmltree.Node) int {
	v, _ := attr(n, "value")
	return atoi(v)
}

// atoi mimics C atoi: parse leading decimal digits, 0 if none.
func atoi(s string) int {
	i, n := 0, len(s)
	for i < n && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	sign := 1
	if i < n && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			sign = -1
		}
		i++
	}
	val := 0
	for i < n && s[i] >= '0' && s[i] <= '9' {
		val = val*10 + int(s[i]-'0')
		i++
	}
	return sign * val
}
