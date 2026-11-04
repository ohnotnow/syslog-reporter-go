package web

// The API access page (ait srg-xDjoC.5, ant ADR srg-nKiHN): a logged-in
// user mints, lists and revokes their own API tokens, and copies a
// paste-ready setup block, so nobody has to ssh to the box and pass a
// token through chat. A new token is shown once, in the response to the
// POST that made it; the store keeps only its hash.

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

type apiTokenRow struct {
	ID        int64
	Prefix    string
	CreatedAt string
	LastUsed  string
	Expires   string
	Status    string // active, revoked or expired
}

type apiAccessData struct {
	NeedsLogin bool
	BaseURL    string
	NewToken   string // set only on the response that minted it
	Tokens     []apiTokenRow
	Expires    string // the form's value, kept on an error
	Error      string
}

func (s *Server) renderAPIAccess(w http.ResponseWriter, r *http.Request, status int, d apiAccessData) {
	user := s.auth.CurrentUser(r)
	if user == nil {
		d = apiAccessData{NeedsLogin: true}
	} else {
		d.BaseURL = s.baseURL(r)
		tokens, err := s.lib.ListAPITokensForUser(user.ID)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		for _, t := range tokens {
			d.Tokens = append(d.Tokens, apiTokenRowFor(t, now))
		}
	}
	renderStatus(w, "apiaccess.html", status, pageData{
		Version: s.cfg.Version, Path: "/api-access", User: user, Data: d})
}

func apiTokenRowFor(t *reporter.APIToken, now time.Time) apiTokenRow {
	row := apiTokenRow{ID: t.ID, Prefix: t.Prefix,
		CreatedAt: t.CreatedAt.Format("2006-01-02"), LastUsed: "never", Expires: "never",
		Status: "active"}
	if t.LastUsedAt != nil {
		row.LastUsed = t.LastUsedAt.Format("2006-01-02 15:04")
	}
	if t.ExpiresAt != nil {
		row.Expires = t.ExpiresAt.Format("2006-01-02")
	}
	switch {
	case t.Revoked:
		row.Status = "revoked"
	case !t.Usable(now):
		row.Status = "expired"
	}
	return row
}

func (s *Server) handleAPIAccess(w http.ResponseWriter, r *http.Request) {
	s.renderAPIAccess(w, r, http.StatusOK, apiAccessData{})
}

func (s *Server) handleAPIAccessCreate(w http.ResponseWriter, r *http.Request) {
	user := s.auth.CurrentUser(r)
	if user == nil {
		http.Error(w, "API tokens need a login: run serve with --auth local.", http.StatusForbidden)
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	expiresText := r.PostFormValue("expires")
	expires, err := reporter.ParseTokenExpiry(expiresText, time.Now())
	if err != nil {
		s.renderAPIAccess(w, r, http.StatusUnprocessableEntity, apiAccessData{
			Expires: expiresText, Error: "Expiry date: " + err.Error() + "."})
		return
	}
	raw, tok, err := s.lib.CreateAPIToken(user.ID, expires)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.cfg.logWarn("API token %s created by %q from the web UI", tok.Prefix, user.Username)
	s.renderAPIAccess(w, r, http.StatusOK, apiAccessData{NewToken: raw})
}

func (s *Server) handleAPIAccessRevoke(w http.ResponseWriter, r *http.Request) {
	user := s.auth.CurrentUser(r)
	if user == nil {
		http.Error(w, "API tokens need a login: run serve with --auth local.", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.lib.RevokeAPITokenForUser(id, user.ID); errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.cfg.logWarn("API token id %d revoked by %q from the web UI", id, user.Username)
	http.Redirect(w, r, "/api-access", http.StatusSeeOther)
}
