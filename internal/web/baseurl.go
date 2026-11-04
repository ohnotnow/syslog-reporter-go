package web

import "net/http"

// baseURL is the site's address as the browser used it, for links and
// paste-ready snippets the web UI shows (set-password links, the API
// access page). Behind the reverse proxy this binary sees plain HTTP on
// loopback, so the scheme also comes from --secure-cookies or the proxy's
// X-Forwarded-Proto (scripts/nginx-syslog-reporter.conf.example sends it,
// and Host). Only ever shown back to the person who made the request.
func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || s.cfg.SecureCookies || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
