package web

// Tests for the API access page (ait srg-xDjoC.5). Fictional users only.

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// signedIn creates username (if new) and returns a client logged in as them.
func signedIn(t *testing.T, ts string, lib *reporter.LibraryStore, username string) *http.Client {
	t.Helper()
	if u, _ := lib.UserByUsername(username); u == nil {
		createTestUser(t, lib, username, "correct horse")
	}
	client := sessionClient(t)
	resp, err := client.PostForm(ts+"/login", url.Values{
		"username": {username}, "password": {"correct horse"}, "next": {"/"}})
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); strings.Contains(body, "not recognised") {
		t.Fatalf("could not sign in as %s", username)
	}
	return client
}

var settingsBlock = regexp.MustCompile(`(?s)<pre><code>("env": \{.*?\})</code></pre>`)

func createToken(t *testing.T, client *http.Client, ts string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts+"/api-access", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, bodyOf(t, resp)
}

func TestAPIAccessCreateShowsTheTokenOnceAndItWorks(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	client := signedIn(t, ts.URL, lib, "opsuser")

	code, page := createToken(t, client, ts.URL, url.Values{})
	if code != http.StatusOK {
		t.Fatalf("create: %d\n%s", code, page)
	}
	m := settingsBlock.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no settings.json block:\n%s", page)
	}
	var settings struct {
		Env struct {
			URL   string `json:"SYSLOG_API_URL"`
			Token string `json:"SYSLOG_API_TOKEN"`
		} `json:"env"`
	}
	if err := json.Unmarshal([]byte("{"+html.UnescapeString(m[1])+"}"), &settings); err != nil {
		t.Fatalf("settings block is not valid JSON once wrapped: %v\n%s", err, m[1])
	}
	host := strings.TrimPrefix(ts.URL, "http://")
	if settings.Env.URL != "https://"+host {
		t.Errorf("SYSLOG_API_URL = %q, want https://%s (X-Forwarded-Proto)", settings.Env.URL, host)
	}
	if len(settings.Env.Token) != 64 {
		t.Fatalf("token %q", settings.Env.Token)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+settings.Env.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"opsuser"`) {
		t.Errorf("/api/me with the new token: %d %s", resp.StatusCode, body)
	}

	resp, err = client.Get(ts.URL + "/api-access")
	if err != nil {
		t.Fatal(err)
	}
	again := bodyOf(t, resp)
	if strings.Contains(again, settings.Env.Token) {
		t.Error("a later GET shows the raw token again")
	}
	if !strings.Contains(again, settings.Env.Token[:8]) {
		t.Error("the token's prefix is not listed")
	}
}

func TestAPIAccessRevokeIsOwnerOnly(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	alice := signedIn(t, ts.URL, lib, "alice")
	signedIn(t, ts.URL, lib, "bob")
	bob, _ := lib.UserByUsername("bob")
	raw, bobs, err := lib.CreateAPIToken(bob.ID, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := alice.Get(ts.URL + "/api-access")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodyOf(t, resp), bobs.Prefix) {
		t.Error("alice can see bob's token")
	}
	resp, err = alice.PostForm(ts.URL+"/api-access/"+itoa(bobs.ID)+"/revoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice revoking bob's token: %d, want 404", resp.StatusCode)
	}

	bobClient := signedIn(t, ts.URL, lib, "bob")
	resp, err = bobClient.PostForm(ts.URL+"/api-access/"+itoa(bobs.ID)+"/revoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "revoked") {
		t.Errorf("after revoke the list does not say revoked:\n%s", body)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token: %d, want 401", resp.StatusCode)
	}
}

func TestAPIAccessRefusesAPastExpiry(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	client := signedIn(t, ts.URL, lib, "opsuser")
	code, page := createToken(t, client, ts.URL, url.Values{"expires": {"2020-01-01"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(page, "already in the past") {
		t.Errorf("past expiry: %d\n%s", code, page)
	}
	if strings.Contains(page, "Your new token") {
		t.Error("a token was minted anyway")
	}
}

func TestAPIAccessInModeNoneNeedsALogin(t *testing.T) {
	s := newTestServer(t, Config{})
	rec := get(t, s, "/api-access")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "API tokens need a login") {
		t.Errorf("mode none: %d\n%s", rec.Code, rec.Body.String())
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
