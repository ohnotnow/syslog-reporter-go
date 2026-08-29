package web

// Serve mode: the findings library web app (milestone 3, ait srg-2KY5X.3).
// One binary, one SQLite file: stdlib net/http with Go 1.22+ pattern
// routing, html/template, and go:embed for every asset (htmx vendored and
// pinned, no CDN). TLS is optional and hot-reloads its certificate (tls.go)
// so the corporate auto-renewal script never needs a restart. The library
// pages arrive in later issues; this is the skeleton and base layout.

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Config struct {
	Listen   string // SYSLOG_WEB_LISTEN, host:port
	CertFile string // SYSLOG_WEB_TLS_CERT; with KeyFile, serve HTTPS
	KeyFile  string // SYSLOG_WEB_TLS_KEY
	DBPath   string // SYSLOG_DB_PATH, the same file batch mode writes
	AuthMode string // SYSLOG_AUTH_MODE: none (default) | local | oidc
	Version  string // stamped binary version, shown in the footer
	// SecureCookies (SYSLOG_WEB_SECURE_COOKIES=1) forces the session
	// cookie's Secure flag on for the reverse-proxy deployment: the proxy
	// owns TLS, this binary serves plain HTTP on loopback, and without the
	// override the flag would be derived (wrongly, for the browser) from
	// the built-in TLS setting alone (srg-so8ja.9).
	SecureCookies bool
}

// ConfigFromEnv reads the SYSLOG_WEB_* settings. Plain HTTP (LAN and solo
// use) is a supported first-class case, so no TLS vars is fine; exactly one
// of the pair set is a configuration mistake and errors at startup.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		// Port 7373: 73 kilos is what Vila weighs (owner's choice, Blake's 7).
		Listen:        getenvDefault("SYSLOG_WEB_LISTEN", "127.0.0.1:7373"),
		CertFile:      os.Getenv("SYSLOG_WEB_TLS_CERT"),
		KeyFile:       os.Getenv("SYSLOG_WEB_TLS_KEY"),
		DBPath:        getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		AuthMode:      getenvDefault("SYSLOG_AUTH_MODE", "none"),
		SecureCookies: os.Getenv("SYSLOG_WEB_SECURE_COOKIES") == "1",
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return Config{}, errors.New(
			"SYSLOG_WEB_TLS_CERT and SYSLOG_WEB_TLS_KEY must be set together (or neither, for plain HTTP)")
	}
	return cfg, nil
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// StartupWarnings names the risky-but-supported combinations so they never
// start silently (srg-so8ja.9). Warnings, never refusals: plain HTTP on a
// LAN is a deliberate first-class case here, and the operator gets to make
// that call - out loud.
func (c Config) StartupWarnings() []string {
	if listenIsLoopback(c.Listen) {
		return nil
	}
	var w []string
	if c.AuthMode == "none" {
		w = append(w, fmt.Sprintf(
			"serving without authentication on %s; anyone who can reach it can read and vote on findings",
			c.Listen))
	}
	if c.AuthMode == "local" && c.CertFile == "" {
		w = append(w, fmt.Sprintf(
			"local auth over plain HTTP on %s; passwords and session cookies are visible to the network",
			c.Listen))
	}
	return w
}

// listenIsLoopback reports whether a host:port can only be reached from
// this machine. An empty host binds every interface, so it is NOT loopback.
func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// baseTemplate holds only the shared layout; each page's blocks are parsed
// into a clone at render time so pages never collide.
var baseTemplate = template.Must(template.New("").Funcs(template.FuncMap{
	// list lets a template range over an inline slice, e.g. select options.
	"list": func(items ...string) []string { return items },
	// verdictLabel keeps the stored verdict values out of the visible copy.
	"verdictLabel": func(verdict string) string {
		if verdict == "worked" {
			return "fixed it"
		}
		return "did not fix it"
	},
}).ParseFS(templateFS, "templates/base.html"))

// maxFormBytes bounds the request body on every form POST: the forms here
// are a login and a feedback vote, so Go's default megabytes-large form cap
// is two orders of magnitude more than needed (srg-so8ja.8).
const maxFormBytes = 16 << 10

// limitForm applies maxFormBytes to a request about to be form-parsed.
func limitForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
}

// pageData is what the base layout sees on every render.
type pageData struct {
	Version string
	Path    string         // the page's own path, for the nav's current marker
	User    *reporter.User // nil when anonymous (always, in auth mode none)
	Data    any
}

// render executes the base layout with the named page's blocks mixed in.
func render(w http.ResponseWriter, page string, d pageData) {
	renderBlockStatus(w, page, "base", http.StatusOK, d)
}

// renderBlock executes one named block from a page's template set, for
// htmx partials.
func renderBlock(w http.ResponseWriter, page, block string, d pageData) {
	renderBlockStatus(w, page, block, http.StatusOK, d)
}

// renderStatus is render with an explicit status code (error pages).
func renderStatus(w http.ResponseWriter, page string, status int, d pageData) {
	renderBlockStatus(w, page, "base", status, d)
}

func renderBlockStatus(w http.ResponseWriter, page, block string, status int, d pageData) {
	tpl, err := baseTemplate.Clone()
	if err == nil {
		_, err = tpl.ParseFS(templateFS, "templates/"+page)
	}
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tpl.ExecuteTemplate(w, block, d); err != nil {
		// Headers are gone already; nothing useful left to send.
		return
	}
}

type Server struct {
	cfg  Config
	auth Authenticator
	lib  *reporter.LibraryStore
	mux  *http.ServeMux
	csrf *http.CrossOriginProtection
}

func New(cfg Config, auth Authenticator, lib *reporter.LibraryStore) (*Server, error) {
	if auth == nil {
		return nil, fmt.Errorf("web.New needs an Authenticator (use NewAuthenticator)")
	}
	if lib == nil {
		return nil, fmt.Errorf("web.New needs a LibraryStore")
	}
	s := &Server{cfg: cfg, auth: auth, lib: lib, mux: http.NewServeMux(),
		csrf: http.NewCrossOriginProtection()}
	s.mux.HandleFunc("GET /{$}", s.handleFindings)
	s.mux.HandleFunc("GET /findings/{id}", s.handleFindingDetail)
	s.mux.HandleFunc("POST /findings/{id}/feedback", s.handleFeedback)
	s.mux.Handle("GET /static/", http.FileServerFS(staticFS))
	auth.Routes(s.mux)
	return s, nil
}

// Handler exposes the full stack (CSRF, auth middleware, routes) without
// the listener, for tests.
func (s *Server) Handler() http.Handler {
	return s.csrf.Handler(s.auth.Middleware(s.mux))
}

// Listen binds cfg.Listen, wrapped in TLS when a certificate pair is
// configured. The pair is loaded once up front so a bad configuration fails
// at startup rather than on the first connection.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return nil, err
	}
	if s.cfg.CertFile != "" {
		reloader := newCertReloader(s.cfg.CertFile, s.cfg.KeyFile)
		if _, err := reloader.GetCertificate(nil); err != nil {
			ln.Close()
			return nil, fmt.Errorf("loading TLS certificate pair: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{
			GetCertificate: reloader.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		})
	}
	return ln, nil
}

// Serve runs until ctx is cancelled, then shuts down gracefully, draining
// in-flight requests for up to five seconds.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Full-request and idle limits (srg-so8ja.8): every request this
		// app serves is tiny, so a slow body is a stuck or hostile client.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Run is Listen plus Serve, for the normal (non-test) path.
func (s *Server) Run(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}
