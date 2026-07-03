// Package oauth mints OAuth2 bearer tokens for IMAP XOAUTH2 authentication.
//
// It implements only what the parser needs to reach providers such as Microsoft
// 365 that require OAuth2 for IMAP: the refresh-token grant, hand-rolled over
// net/http so the module keeps its minimal dependency footprint. A short-lived
// access token is exchanged from a long-lived refresh token and, when a cache
// path is configured, persisted on disk together with the refresh token.
//
// Persisting the refresh token matters because Azure AD rotates it on every
// refresh (with offline_access): the endpoint returns a new refresh token each
// time and eventually retires the old one. Saving the newest token keeps an
// unattended tool working past the bootstrap token's sliding expiry window;
// without a cache the same bootstrap token is reused every run and will
// eventually stop working.
package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenSource returns a currently-valid OAuth2 access token, refreshing as needed.
type TokenSource interface {
	Token() (string, error)
}

// expirySkew is subtracted from a cached token's expiry so a token about to
// expire is refreshed rather than presented moments before the server rejects it.
const expirySkew = 60 * time.Second

// RefreshTokenSource mints access tokens from a refresh token via the OAuth2
// refresh-token grant. When CachePath is set the access token and the (possibly
// rotated) refresh token are persisted there and reused across runs.
type RefreshTokenSource struct {
	TokenURL     string // provider token endpoint
	ClientID     string
	ClientSecret string // empty for public clients
	RefreshToken string // bootstrap refresh token from config
	Scope        string // space-separated scopes

	CachePath string // optional on-disk token cache

	// HTTPClient performs the token request; defaults to http.DefaultClient.
	HTTPClient *http.Client
	// now returns the current time; overridable in tests. Defaults to time.Now.
	now func() time.Time
}

// Token returns a valid access token, refreshing via the token endpoint when the
// cached token is missing or within expirySkew of expiry.
func (s *RefreshTokenSource) Token() (string, error) {
	now := s.nowFn()
	cache := s.loadCache()
	if cache.AccessToken != "" && cache.Expiry.After(now.Add(expirySkew)) {
		return cache.AccessToken, nil
	}

	// Prefer the cached (rotated) refresh token over the config bootstrap one.
	refresh := s.RefreshToken
	if cache.RefreshToken != "" {
		refresh = cache.RefreshToken
	}
	if refresh == "" {
		return "", fmt.Errorf("oauth: no refresh token configured")
	}

	tok, err := s.refresh(refresh)
	if err != nil {
		return "", err
	}

	newCache := tokenCache{
		AccessToken:  tok.AccessToken,
		RefreshToken: refresh,
		Expiry:       now.Add(time.Duration(tok.ExpiresIn) * time.Second),
	}
	if tok.RefreshToken != "" {
		newCache.RefreshToken = tok.RefreshToken // the provider rotated it
	}
	if err := s.saveCache(newCache); err != nil {
		return "", fmt.Errorf("oauth: save token cache: %w", err)
	}
	return tok.AccessToken, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// refresh performs one refresh-token grant against the token endpoint.
func (s *RefreshTokenSource) refresh(refreshToken string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", s.ClientID)
	if s.ClientSecret != "" {
		form.Set("client_secret", s.ClientSecret)
	}
	if s.Scope != "" {
		form.Set("scope", s.Scope)
	}

	req, err := http.NewRequest(http.MethodPost, s.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth: read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oauth: parse token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		if tr.Error != "" {
			return nil, fmt.Errorf("oauth: token endpoint error %q: %s", tr.Error, tr.ErrorDesc)
		}
		return nil, fmt.Errorf("oauth: token endpoint returned status %d", resp.StatusCode)
	}
	return &tr, nil
}

// tokenCache is the on-disk cache: the access token, the newest refresh token,
// and the absolute access-token expiry. It holds secrets, so the file is written
// with the restrictive permissions os.CreateTemp uses.
type tokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// loadCache reads the cache file; a missing, empty, or corrupt file yields an
// empty cache (which forces a refresh) rather than an error.
func (s *RefreshTokenSource) loadCache() tokenCache {
	var c tokenCache
	if s.CachePath == "" {
		return c
	}
	data, err := os.ReadFile(s.CachePath)
	if err != nil || len(data) == 0 {
		return c
	}
	_ = json.Unmarshal(data, &c)
	return c
}

// saveCache atomically writes the cache (temp file + rename), mirroring
// imapstate.Save. It is a no-op when no cache path is configured.
func (s *RefreshTokenSource) saveCache(c tokenCache) error {
	if s.CachePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.CachePath)
	tmp, err := os.CreateTemp(dir, ".imap-token-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.CachePath)
}

func (s *RefreshTokenSource) nowFn() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}
