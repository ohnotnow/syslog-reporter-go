package web

// The set-password page (ait srg-xDjoC.3): the public end of a one-time
// link an admin issued from the People page. It needs no login (the link
// is the credential), so authlocal.go's middleware lets /set-password/
// through, and it is only registered in auth mode local.
//
// The token rides in the URL path, so it lands in reverse-proxy access
// logs; acceptable because it works once and lapses after a week.
// Setting a password does not end the user's existing sessions: they are
// in-memory scs sessions with no per-user index.

import (
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

type setPasswordData struct {
	Invalid  bool   // unknown, used or expired link
	Done     bool   // password set
	Username string // whose password this is
	Token    string
	Error    string
	MinChars int
}

func (s *Server) renderSetPassword(w http.ResponseWriter, r *http.Request, status int, d setPasswordData) {
	d.MinChars = reporter.MinPasswordChars
	renderStatus(w, "setpassword.html", status, pageData{
		Version: s.cfg.Version, Path: "/set-password", User: s.auth.CurrentUser(r), Data: d})
}

func (s *Server) handleSetPasswordForm(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	user, _, err := s.lib.InviteByToken(token, time.Now())
	if errors.Is(err, reporter.ErrInviteInvalid) {
		s.renderSetPassword(w, r, http.StatusNotFound, setPasswordData{Invalid: true})
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.renderSetPassword(w, r, http.StatusOK, setPasswordData{Username: user.Username, Token: token})
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	now := time.Now()
	user, inviteID, err := s.lib.InviteByToken(token, now)
	if errors.Is(err, reporter.ErrInviteInvalid) {
		s.renderSetPassword(w, r, http.StatusNotFound, setPasswordData{Invalid: true})
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	password, again := r.PostFormValue("password"), r.PostFormValue("again")
	retry := setPasswordData{Username: user.Username, Token: token}
	if password != again {
		retry.Error = "The two passwords do not match."
		s.renderSetPassword(w, r, http.StatusUnprocessableEntity, retry)
		return
	}
	if err := reporter.CheckPassword(password, user.Username, user.Email); err != nil {
		retry.Error = err.Error()
		s.renderSetPassword(w, r, http.StatusUnprocessableEntity, retry)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if err := s.lib.ConsumeInvite(inviteID, string(hash), now); errors.Is(err, reporter.ErrInviteInvalid) {
		s.renderSetPassword(w, r, http.StatusNotFound, setPasswordData{Invalid: true})
		return
	} else if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.cfg.logWarn("password set for %q via a set-password link from %s", user.Username, clientIP(r.RemoteAddr))
	s.renderSetPassword(w, r, http.StatusOK, setPasswordData{Done: true, Username: user.Username})
}
