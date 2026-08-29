package web

// Tests for the auth seam and the local driver (ait srg-2KY5X.4).
// Fictional hostnames and users only.

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func newAuthTestStore(t *testing.T) *reporter.LibraryStore {
	t.Helper()
	lib, err := reporter.OpenLibraryStore(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open library store: %v", err)
	}
	t.Cleanup(func() { lib.Close() })
	return lib
}

// createTestUser stores a user with a real (MinCost, for speed) bcrypt hash.
func createTestUser(t *testing.T, lib *reporter.LibraryStore, username, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.CreateUser(username, username+"@example.test", string(hash)); err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func newLocalServer(t *testing.T, lib *reporter.LibraryStore) *httptest.Server {
	t.Helper()
	cfg := Config{AuthMode: "local", Version: "test"}
	auth, err := NewAuthenticator(cfg, lib)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	s, err := New(cfg, auth, lib)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// sessionClient follows redirects and keeps cookies, like a browser.
func sessionClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestModeNoneSetsNoSessionCookie(t *testing.T) {
	s := newTestServer(t, Config{})
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("mode none set cookies: %v", cookies)
	}
}

func TestModeLocalRedirectsAnonymousToLogin(t *testing.T) {
	ts := newLocalServer(t, newAuthTestStore(t))
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET / = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?next=%2F" {
		t.Errorf("Location = %q", loc)
	}
}

func TestModeLocalLoginLogoutFlow(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	ts := newLocalServer(t, lib)
	client := sessionClient(t)

	// Anonymous GET / lands on the login form.
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Sign in") {
		t.Fatalf("expected the login form, got: %.200s", body)
	}

	// Correct credentials land back on the home page, signed in.
	resp, err = client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	for _, want := range []string{"Findings library", "opsuser", "Log out"} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-in home missing %q", want)
		}
	}

	// Logout drops the session: the next GET / is the login form again.
	resp, err = client.PostForm(ts.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); !strings.Contains(body, "Sign in") {
		t.Errorf("expected the login form after logout")
	}
}

func TestModeLocalFailedLoginsAreGenericAndIdentical(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	ts := newLocalServer(t, lib)

	attempt := func(username string) (int, string) {
		t.Helper()
		resp, err := http.PostForm(ts.URL+"/login", url.Values{
			"username": {username}, "password": {"wrong"}, "next": {"/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, bodyOf(t, resp)
	}
	knownStatus, knownBody := attempt("opsuser")
	unknownStatus, unknownBody := attempt("no-such-user")
	if knownStatus != http.StatusOK || unknownStatus != http.StatusOK {
		t.Fatalf("failed logins = %d / %d, want 200 / 200", knownStatus, unknownStatus)
	}
	if !strings.Contains(knownBody, "was not recognised") {
		t.Error("failed login should show the generic message")
	}
	// Identical responses for wrong-password and no-such-user: the form
	// cannot be used to enumerate usernames... except the echoed username.
	if strings.ReplaceAll(knownBody, "opsuser", "USER") !=
		strings.ReplaceAll(unknownBody, "no-such-user", "USER") {
		t.Error("failed-login responses differ between known and unknown user")
	}
}

func TestModeLocalNullPasswordUserCannotSignIn(t *testing.T) {
	lib := newAuthTestStore(t)
	// SSO-created user: NULL password hash.
	if _, err := lib.CreateUser("ssouser", "ssouser@example.test", ""); err != nil {
		t.Fatal(err)
	}
	ts := newLocalServer(t, lib)
	resp, err := http.PostForm(ts.URL+"/login", url.Values{
		"username": {"ssouser"}, "password": {""}, "next": {"/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "was not recognised") {
		t.Errorf("NULL-hash login = %d, want the generic 200 failure", resp.StatusCode)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	ts := newLocalServer(t, lib)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Secure {
		t.Error("Secure must be off when serving plain HTTP")
	}

	// Secure is decided once from the serve TLS config.
	tlsAuth := newLocalAuth(Config{CertFile: "/etc/certs/reporter.pem", KeyFile: "k"}, lib)
	if !tlsAuth.sessions.Cookie.Secure {
		t.Error("Secure must be on when a TLS pair is configured")
	}

	// SYSLOG_WEB_SECURE_COOKIES=1 covers proxy-terminated TLS: Secure on
	// even though this binary itself serves plain HTTP (srg-so8ja.9).
	proxyAuth := newLocalAuth(Config{SecureCookies: true}, lib)
	if !proxyAuth.sessions.Cookie.Secure {
		t.Error("Secure must be on when SecureCookies is set, TLS pair or not")
	}
}

// The risky-but-supported serve combinations warn at startup and loopback
// stays quiet; nothing refuses (srg-so8ja.9 - LAN plain HTTP is a
// deliberate first-class case).
func TestStartupWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want int
	}{
		{"loopback none is quiet", Config{Listen: "127.0.0.1:7373", AuthMode: "none"}, 0},
		{"localhost local is quiet", Config{Listen: "localhost:7373", AuthMode: "local"}, 0},
		{"lan none warns", Config{Listen: "192.0.2.7:7373", AuthMode: "none"}, 1},
		{"all-interfaces none warns", Config{Listen: ":7373", AuthMode: "none"}, 1},
		{"lan local plain http warns", Config{Listen: "192.0.2.7:7373", AuthMode: "local"}, 1},
		{"lan local with tls is quiet", Config{
			Listen: "192.0.2.7:7373", AuthMode: "local",
			CertFile: "/etc/certs/reporter.pem", KeyFile: "k"}, 0},
	} {
		if got := len(tc.cfg.StartupWarnings()); got != tc.want {
			t.Errorf("%s: %d warnings, want %d: %v",
				tc.name, got, tc.want, tc.cfg.StartupWarnings())
		}
	}
}

func TestCrossOriginPostIsRejected(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login",
		strings.NewReader("username=x&password=y"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", resp.StatusCode)
	}
}

func TestAuthModeConfigErrors(t *testing.T) {
	if _, err := NewAuthenticator(Config{AuthMode: "oidc"}, nil); err == nil ||
		!strings.Contains(err.Error(), "oidc") {
		t.Errorf("oidc mode: want a startup error naming the driver, got %v", err)
	}
	if _, err := NewAuthenticator(Config{AuthMode: "banana"}, nil); err == nil ||
		!strings.Contains(err.Error(), "banana") {
		t.Errorf("unknown mode: want an error naming the value, got %v", err)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "/",
		"/":                      "/",
		"/findings?host=a":       "/findings?host=a",
		"//evil.example.test":    "/",
		"http://evil.example.te": "/",
		"\\evil":                 "/",
		"/\\evil":                "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
