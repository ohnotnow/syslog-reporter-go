package web

// Bearer-token auth for the sysadmin API (ait srg-Kj5Q8.4, ant ADR
// srg-yYpms). Every /api/ path takes this stack instead of the web UI's
// cookie session and CSRF guard: a curl from a laptop has neither. There
// is no tokenless mode whatever --auth says, because the token is what
// names the user on feedback and mutes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const tokenContextKey ctxKey = 1

// writeJSON sends v as the whole response body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// writeJSONError is the one error shape every API handler uses.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// bearerAuth resolves the Authorization header to a token and its user.
// Absent, revoked and expired tokens all get the same refusal, so the API
// is not a token oracle. A good token is touched (last_used_at) on every
// call: that is what 'token list' shows the uber-admin.
func (s *Server) bearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		raw = strings.TrimSpace(raw)
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok, err := s.lib.APITokenByHash(reporter.HashAPIToken(raw))
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusInternalServerError, "server error")
			return
		}
		now := time.Now()
		if err != nil || !tok.Usable(now) {
			s.cfg.logWarn("refused API token %s from %s", tokenLabel(tok, raw), clientIP(r.RemoteAddr))
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSONError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		user, err := s.lib.UserByID(tok.UserID)
		if err != nil || user == nil {
			writeJSONError(w, http.StatusInternalServerError, "server error")
			return
		}
		if err := s.lib.TouchAPIToken(tok.ID, now); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "server error")
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, tokenContextKey, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tokenLabel names a refused token for the warn log without echoing it:
// the stored prefix when it exists, otherwise the first characters of
// whatever was sent.
func tokenLabel(tok *reporter.APIToken, raw string) string {
	if tok != nil {
		return tok.Prefix
	}
	if len(raw) > 8 {
		raw = raw[:8]
	}
	return "unknown (" + raw + "...)"
}

// apiUser and apiToken read what bearerAuth stored; both are non-nil for
// any handler mounted under /api/.
func apiUser(r *http.Request) *reporter.User {
	user, _ := r.Context().Value(userContextKey).(*reporter.User)
	return user
}

func apiToken(r *http.Request) *reporter.APIToken {
	tok, _ := r.Context().Value(tokenContextKey).(*reporter.APIToken)
	return tok
}

// handleMe is the skill's "is my token set up?" probe.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, tok := apiUser(r), apiToken(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     user.Username,
		"token_prefix": tok.Prefix,
		"expires_at":   tok.ExpiresAt,
	})
}
