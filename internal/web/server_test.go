package web

// Tests for the serve-mode skeleton (ait srg-2KY5X.3). Fictional hostnames
// only.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	lib, err := reporter.OpenLibraryStore(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("open library store: %v", err)
	}
	t.Cleanup(func() { lib.Close() })
	auth, err := NewAuthenticator(cfg, nil)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	s, err := New(cfg, auth, lib)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestConfigFromEnvDefaultsToPlainHTTP(t *testing.T) {
	t.Setenv("SYSLOG_WEB_LISTEN", "")
	t.Setenv("SYSLOG_WEB_TLS_CERT", "")
	t.Setenv("SYSLOG_WEB_TLS_KEY", "")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:7373" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		t.Errorf("expected no TLS config, got %q / %q", cfg.CertFile, cfg.KeyFile)
	}
}

// Validate (not ConfigFromEnv) owns the TLS-pair check: serve's flags can
// complete a pair the environment only half-set, so the check runs after
// any overrides.
func TestValidateRejectsHalfATLSPair(t *testing.T) {
	for _, tc := range []struct{ cert, key string }{
		{"/etc/certs/reporter.pem", ""},
		{"", "/etc/certs/reporter.key"},
	} {
		cfg := Config{CertFile: tc.cert, KeyFile: tc.key}
		if err := cfg.Validate(); err == nil {
			t.Errorf("cert=%q key=%q: expected an error", tc.cert, tc.key)
		}
	}
}

func TestConfigFromEnvAcceptsAFullTLSPair(t *testing.T) {
	t.Setenv("SYSLOG_WEB_TLS_CERT", "/etc/certs/reporter.pem")
	t.Setenv("SYSLOG_WEB_TLS_KEY", "/etc/certs/reporter.key")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		t.Errorf("TLS pair lost: %q / %q", cfg.CertFile, cfg.KeyFile)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("full pair should validate: %v", err)
	}
}

func TestSecureCookiesEnvSpellings(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false}, {"0", false}, {"false", false}, {"no", false}, {"off", false},
		{"1", true}, {"true", true}, {"YES", true}, {"On", true},
	} {
		t.Setenv("SYSLOG_WEB_SECURE_COOKIES", tc.value)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Errorf("value %q: unexpected error %v", tc.value, err)
			continue
		}
		if cfg.SecureCookies != tc.want {
			t.Errorf("value %q: SecureCookies = %v, want %v", tc.value, cfg.SecureCookies, tc.want)
		}
	}
	// Junk must error, never silently mean off.
	t.Setenv("SYSLOG_WEB_SECURE_COOKIES", "definitely")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("junk SYSLOG_WEB_SECURE_COOKIES should error")
	}
}

func TestHomePageServesBaseLayout(t *testing.T) {
	s := newTestServer(t, Config{Version: "test-1.0"})
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<html lang="en-GB">`,
		"Skip to main content",
		"Findings library",
		"syslog-reporter test-1.0",
		"/static/app.css",
		"/static/htmx-2.0.10.min.js",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GET / body missing %q", want)
		}
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	s := newTestServer(t, Config{})
	for _, path := range []string{"/static/app.css", "/static/htmx-2.0.10.min.js"} {
		if rec := get(t, s, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	s := newTestServer(t, Config{})
	if rec := get(t, s, "/no-such-page"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /no-such-page = %d, want 404", rec.Code)
	}
}
