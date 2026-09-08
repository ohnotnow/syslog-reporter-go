package web

// Tests for the /api/ bearer stack (ait srg-Kj5Q8.4). Fictional users only.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// newAPIServer builds a server in the given auth mode over a fresh store,
// with one user and one live token, and returns the raw token.
func newAPIServer(t *testing.T, authMode string) (*httptest.Server, *reporter.LibraryStore, string) {
	t.Helper()
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	user, err := lib.UserByUsername("opsuser")
	if err != nil || user == nil {
		t.Fatalf("user: %v", err)
	}
	raw, _, err := lib.CreateAPIToken(user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AuthMode: authMode, Version: "test"}
	auth, err := NewAuthenticator(cfg, lib)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, auth, lib)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, lib, raw
}

func apiRequest(t *testing.T, method, url, token string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestAPIRefusesMissingBadRevokedAndExpiredTokens(t *testing.T) {
	ts, lib, raw := newAPIServer(t, "none")
	user, _ := lib.UserByUsername("opsuser")
	past := time.Now().Add(-time.Hour)
	expiredRaw, _, err := lib.CreateAPIToken(user.ID, &past)
	if err != nil {
		t.Fatal(err)
	}
	revokedRaw, revoked, err := lib.CreateAPIToken(user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.RevokeAPIToken(revoked.Prefix); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		token, wantMsg string
	}{
		"missing": {"", "missing bearer token"},
		"garbage": {"not-a-token", "invalid or expired token"},
		"expired": {expiredRaw, "invalid or expired token"},
		"revoked": {revokedRaw, "invalid or expired token"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := apiRequest(t, http.MethodGet, ts.URL+"/api/me", tc.token, "")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if resp.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Error("missing WWW-Authenticate: Bearer")
			}
			var body map[string]string
			decodeJSON(t, resp, &body)
			if body["error"] != tc.wantMsg {
				t.Errorf("error = %q, want %q", body["error"], tc.wantMsg)
			}
		})
	}
	// The good token still works and is untouched by the refusals above.
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/me", raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good token = %d, want 200", resp.StatusCode)
	}
}

func TestAPIGoodTokenNamesTheUserAndRecordsLastUse(t *testing.T) {
	ts, lib, raw := newAPIServer(t, "none")
	before := time.Now().Add(-time.Second)
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/me", raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var me struct {
		Username    string  `json:"username"`
		TokenPrefix string  `json:"token_prefix"`
		ExpiresAt   *string `json:"expires_at"`
	}
	decodeJSON(t, resp, &me)
	if me.Username != "opsuser" || me.TokenPrefix != raw[:8] || me.ExpiresAt != nil {
		t.Errorf("me = %+v", me)
	}
	tok, err := lib.APITokenByHash(reporter.HashAPIToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tok.LastUsedAt == nil || tok.LastUsedAt.Before(before) {
		t.Errorf("last_used_at = %v, want set after %v", tok.LastUsedAt, before)
	}
}

func TestAPIIgnoresSessionCookiesAndCSRF(t *testing.T) {
	ts, _, raw := newAPIServer(t, "local")
	// A bearer POST from a foreign site is fine: no CSRF on /api/.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// /api/me is GET-only, so 405 proves the request reached the mux
	// rather than being stopped by the CSRF guard (403) or auth (401).
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("cross-site bearer POST = %d, want 405 (reached the route)", resp.StatusCode)
	}

	// A logged-in browser session does NOT authenticate the API.
	client := sessionClient(t)
	login, err := client.PostForm(ts.URL+"/login",
		url.Values{"username": {"opsuser"}, "password": {"correct horse"}})
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.Request.URL.Path == "/login" {
		t.Fatal("login did not succeed")
	}
	resp, err = client.Get(ts.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("cookie-only API call = %d, want 401", resp.StatusCode)
	}
	// And the web UI still needs its cookie: the bearer token buys nothing there.
	resp = apiRequest(t, http.MethodGet, ts.URL+"/", raw, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Request.URL.Path, "/login") {
		t.Errorf("bearer-only web call landed on %s (%d), want the login redirect",
			resp.Request.URL.Path, resp.StatusCode)
	}
}
