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
	"time"
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
	Version  string // stamped binary version, shown in the footer
}

// ConfigFromEnv reads the SYSLOG_WEB_* settings. Plain HTTP (LAN and solo
// use) is a supported first-class case, so no TLS vars is fine; exactly one
// of the pair set is a configuration mistake and errors at startup.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Listen:   getenvDefault("SYSLOG_WEB_LISTEN", "127.0.0.1:8080"),
		CertFile: os.Getenv("SYSLOG_WEB_TLS_CERT"),
		KeyFile:  os.Getenv("SYSLOG_WEB_TLS_KEY"),
		DBPath:   getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
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

type Server struct {
	cfg Config
	tpl *template.Template
	mux *http.ServeMux
}

func New(cfg Config) (*Server, error) {
	// Only the shared layout lives in the base set; each page's blocks are
	// parsed into a clone at render time so pages never collide.
	tpl, err := template.ParseFS(templateFS, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	s := &Server{cfg: cfg, tpl: tpl, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.Handle("GET /static/", http.FileServerFS(staticFS))
	return s, nil
}

// Handler exposes the routes without the listener, for tests.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.render(w, "home.html", nil)
}

// render executes the base layout with the named page's blocks mixed in.
// Cloning per request keeps page-specific {{define}}s from leaking between
// pages once there is more than one.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tpl, err := s.tpl.Clone()
	if err == nil {
		_, err = tpl.ParseFS(templateFS, "templates/"+page)
	}
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := tpl.ExecuteTemplate(w, "base", struct {
		Version string
		Data    any
	}{s.cfg.Version, data}); err != nil {
		// Headers are likely gone already; nothing useful left to send.
		return
	}
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
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 10 * time.Second}
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
