// Package poster delivers parsed emails to the Cerberus backend over HTTP,
// replacing the libcurl multipart POST machinery (cer_curl_*, cer_add_sub_files)
// with net/http + mime/multipart. The form fields and file parts match what the
// C tool sent so the backend sees an identical request.
package poster

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/crypt"
	"cerb2-goparser/internal/xmltree"
)

// HTTPPoster implements app.Poster.
type HTTPPoster struct {
	client *http.Client
}

// New builds an HTTPPoster whose TLS verification matches the config's ssl
// settings (verify 0 disables verification; cainfo/capath add trusted roots).
func New(cfg *config.Config) *HTTPPoster {
	return &HTTPPoster{
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig(cfg)}},
	}
}

// Deliver posts the parsed email to the parser endpoint. When an xSP key is
// configured it first decrypts it and boots against the xSP service to obtain
// the parser URL/credentials; otherwise it reads <key><parser> directly from the
// config. Returns delivered=true when the backend replied with an empty body.
func (p *HTTPPoster) Deliver(cfg *config.Config, email *xmltree.Node, log *clog.Logger) (bool, error) {
	keyRoot := cfg.Root
	if cfg.XSP != "" {
		boot, err := p.xspBoot(cfg, email, log)
		if err != nil {
			return false, err
		}
		keyRoot = boot
	}
	if keyRoot == nil {
		return false, nil
	}

	keyRoot.Iterate()
	key := keyRoot.Next("key")
	if key == nil {
		return false, fmt.Errorf("no <key> found in %s", keyRootKind(cfg))
	}
	parser := key.Get("key", "parser")
	if parser == nil {
		return false, fmt.Errorf("key matched but no <key><parser> element")
	}
	url, _ := parser.Attribute("url")
	user, uok := parser.Attribute("user")
	pass, pok := parser.Attribute("password")
	if url == "" {
		return false, fmt.Errorf("key matched but the parser URL was missing")
	}
	if !uok {
		return false, fmt.Errorf("parser user could not be found")
	}
	if !pok {
		return false, fmt.Errorf("parser password could not be found")
	}

	resp, err := p.postParser(url, user, pass, email, log)
	if err != nil {
		return false, err
	}
	if len(resp) == 0 {
		return true, nil // empty body => delivered
	}
	log.Log(clog.Fatal, "PHP: %s", resp)
	return false, nil
}

func keyRootKind(cfg *config.Config) string {
	if cfg.XSP != "" {
		return "xSP boot response"
	}
	return "config file"
}

// xspBoot decrypts the license key, derives the xSP domain, posts action=boot,
// and returns the parsed response root (whose <key> children hold the parser
// config). Mirrors the xsp block of cer_parse_files.
func (p *HTTPPoster) xspBoot(cfg *config.Config, email *xmltree.Node, log *clog.Logger) (*xmltree.Node, error) {
	keyInfo := crypt.KeyInfo([]byte(cfg.XSP))
	if keyInfo == nil {
		return nil, fmt.Errorf("xSP key is invalid or expired")
	}
	keyInfo.Iterate()
	domainNode := keyInfo.Next("domain")
	if domainNode == nil {
		return nil, fmt.Errorf("xSP key has no domain")
	}
	scheme := "http://"
	if cfg.ParserHTTPS {
		scheme = "https://"
	}
	url := scheme + string(domainNode.Data)
	log.Log(clog.Debug, "Giving cURL URL: %s", url)

	resp, err := p.post(url, func(w *multipart.Writer) error {
		_ = w.WriteField("user", cfg.ParserUser)
		_ = w.WriteField("password", cfg.ParserPass)
		_ = w.WriteField("xml", string(email.ToString()))
		_ = w.WriteField("action", "boot")
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("xSP boot returned no data; check the config login information")
	}
	root, err := xmltree.Read(bytes.NewReader(resp))
	if err != nil {
		return nil, fmt.Errorf("xSP boot XML parse: %w", err)
	}
	return root, nil
}

// postParser posts the email XML plus all extracted attachment files.
func (p *HTTPPoster) postParser(url, user, pass string, email *xmltree.Node, log *clog.Logger) ([]byte, error) {
	log.Log(clog.Debug, "Posting via cURL to %s", url)
	return p.post(url, func(w *multipart.Writer) error {
		_ = w.WriteField("user", user)
		_ = w.WriteField("password", pass)
		_ = w.WriteField("xml", string(email.ToString()))
		return addSubFiles(email, w)
	})
}

// post builds a multipart/form-data body via fill and POSTs it to url.
func (p *HTTPPoster) post(url string, fill func(*multipart.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := fill(w); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// addSubFiles attaches every <file><tempname> in the tree as a file upload,
// recursing through <sub> nodes. The form field name is the temp file path
// (matching CURLFORM_PTRNAME) and the upload is that file (CURLFORM_FILE).
func addSubFiles(node *xmltree.Node, w *multipart.Writer) error {
	for _, file := range node.Children() {
		if file.Name != "file" {
			continue
		}
		for _, tn := range file.Children() {
			if tn.Name == "tempname" && len(tn.Data) > 0 {
				if err := addFilePart(w, string(tn.Data)); err != nil {
					return err
				}
			}
		}
	}
	for _, sub := range node.Children() {
		if sub.Name == "sub" {
			if err := addSubFiles(sub, w); err != nil {
				return err
			}
		}
	}
	return nil
}

func addFilePart(w *multipart.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		// the file may have been cleaned up or never written; skip it as curl
		// would when it cannot open the file.
		return nil
	}
	part, err := w.CreateFormFile(path, filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	return err
}
