package oauth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRefreshTokenSource exercises the full lifecycle: a first refresh with the
// bootstrap token, reuse of the cached access token without a second HTTP call,
// and a refresh after expiry that must send the rotated refresh token.
func TestRefreshTokenSource(t *testing.T) {
	var (
		mu         sync.Mutex
		calls      int
		gotRefresh []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "unexpected grant_type", http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls++
		n := calls
		gotRefresh = append(gotRefresh, r.Form.Get("refresh_token"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":"refresh-%d","expires_in":3600,"token_type":"Bearer"}`, n, n)
	}))
	defer srv.Close()

	cur := time.Unix(1_700_000_000, 0)
	ts := &RefreshTokenSource{
		TokenURL:     srv.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		RefreshToken: "bootstrap",
		Scope:        "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access",
		CachePath:    filepath.Join(t.TempDir(), "token.json"),
		HTTPClient:   srv.Client(),
		now:          func() time.Time { return cur },
	}

	// First call: no cache, refresh with the bootstrap token.
	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "access-1" {
		t.Fatalf("tok = %q, want access-1", tok)
	}

	// Second call while still valid: served from cache, no new HTTP request.
	tok, err = ts.Token()
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok != "access-1" {
		t.Fatalf("cached tok = %q, want access-1", tok)
	}
	mu.Lock()
	c := calls
	mu.Unlock()
	if c != 1 {
		t.Fatalf("calls = %d, want 1 (second call should hit the cache)", c)
	}

	// Advance past expiry: refresh again, and it must use the rotated token.
	cur = cur.Add(2 * time.Hour)
	tok, err = ts.Token()
	if err != nil {
		t.Fatalf("Token (after expiry): %v", err)
	}
	if tok != "access-2" {
		t.Fatalf("tok = %q, want access-2", tok)
	}
	mu.Lock()
	c = calls
	last := gotRefresh[len(gotRefresh)-1]
	mu.Unlock()
	if c != 2 {
		t.Fatalf("calls = %d, want 2", c)
	}
	if last != "refresh-1" {
		t.Fatalf("second refresh sent %q, want the rotated refresh-1", last)
	}
}

// TestRefreshTokenSourceNoCache verifies the source works without a cache path:
// every call refreshes, always using the bootstrap token.
func TestRefreshTokenSourceNoCache(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"access","refresh_token":"rotated","expires_in":3600}`)
	}))
	defer srv.Close()

	ts := &RefreshTokenSource{TokenURL: srv.URL, ClientID: "c", RefreshToken: "boot", HTTPClient: srv.Client()}
	for i := 0; i < 2; i++ {
		if tok, err := ts.Token(); err != nil || tok != "access" {
			t.Fatalf("Token() = %q, %v", tok, err)
		}
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (no cache means refresh each time)", calls)
	}
}

// TestRefreshTokenSourceError surfaces an OAuth error response as a Go error.
func TestRefreshTokenSourceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"refresh token expired"}`)
	}))
	defer srv.Close()

	ts := &RefreshTokenSource{TokenURL: srv.URL, ClientID: "c", RefreshToken: "expired", HTTPClient: srv.Client()}
	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected an error from invalid_grant")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error = %q, want it to mention invalid_grant", err)
	}
}

// TestRefreshTokenSourceNoToken errors when neither a cached nor a configured
// refresh token is available.
func TestRefreshTokenSourceNoToken(t *testing.T) {
	ts := &RefreshTokenSource{TokenURL: "http://unused", ClientID: "c"}
	if _, err := ts.Token(); err == nil {
		t.Fatal("expected an error when no refresh token is configured")
	}
}
