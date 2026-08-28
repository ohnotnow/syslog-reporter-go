package web

// Tests for the serve-mode skeleton (ait srg-2KY5X.3). Fictional hostnames
// only.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := New(cfg)
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
	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		t.Errorf("expected no TLS config, got %q / %q", cfg.CertFile, cfg.KeyFile)
	}
}

func TestConfigFromEnvRejectsHalfATLSPair(t *testing.T) {
	for _, tc := range []struct{ cert, key string }{
		{"/etc/certs/reporter.pem", ""},
		{"", "/etc/certs/reporter.key"},
	} {
		t.Setenv("SYSLOG_WEB_TLS_CERT", tc.cert)
		t.Setenv("SYSLOG_WEB_TLS_KEY", tc.key)
		if _, err := ConfigFromEnv(); err == nil {
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
