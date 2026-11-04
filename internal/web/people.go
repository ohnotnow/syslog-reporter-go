package web

// The People page (ait srg-xDjoC.4, ant ADR srg-nKiHN): admins add
// accounts and issue one-time set-password links, so onboarding needs no
// ssh. Adding a user never sets a password; the link shown once here goes
// to the new person, who chooses their own. The same link is the password
// reset for an existing account. Removing users and changing who is an
// admin stay on the CLI ('user remove', 'user admin').

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

type peopleData struct {
	NeedsLogin bool
	Forbidden  bool
	Users      []*reporter.User
	Link       string // a just-issued set-password link, shown once
	LinkFor    string
	Error      string
	Username   string // the add form's values, kept on an error
	Email      string
	Admin      bool
}

// renderPeople draws the page for the current user: the login notice in
// mode none, a 403 for a non-admin, else the list.
func (s *Server) renderPeople(w http.ResponseWriter, r *http.Request, status int, d peopleData) {
	user := s.auth.CurrentUser(r)
	switch {
	case user == nil:
		d = peopleData{NeedsLogin: true}
	case !user.IsAdmin:
		d, status = peopleData{Forbidden: true}, http.StatusForbidden
	default:
		users, err := s.lib.ListUsers()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		d.Users = users
	}
	renderStatus(w, "people.html", status, pageData{
		Version: s.cfg.Version, Path: "/people", User: user, Data: d})
}

// adminOnly returns the current admin, or draws the refusal and nil.
func (s *Server) adminOnly(w http.ResponseWriter, r *http.Request) *reporter.User {
	user := s.auth.CurrentUser(r)
	if user == nil || !user.IsAdmin {
		s.renderPeople(w, r, http.StatusOK, peopleData{})
		return nil
	}
	return user
}

func (s *Server) handlePeople(w http.ResponseWriter, r *http.Request) {
	s.renderPeople(w, r, http.StatusOK, peopleData{})
}

func (s *Server) handlePeopleAdd(w http.ResponseWriter, r *http.Request) {
	admin := s.adminOnly(w, r)
	if admin == nil {
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	d := peopleData{
		Username: strings.TrimSpace(r.PostFormValue("username")),
		Email:    strings.TrimSpace(r.PostFormValue("email")),
		Admin:    r.PostFormValue("admin") != "",
	}
	switch {
	case d.Username == "" || strings.ContainsFunc(d.Username, isSpace):
		d.Error = "Give a username with no spaces."
	case !strings.Contains(d.Email, "@"):
		d.Error = "Give an email address."
	}
	if d.Error != "" {
		s.renderPeople(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	id, err := s.lib.CreateUser(d.Username, d.Email, "")
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			d.Error = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
			s.renderPeople(w, r, http.StatusUnprocessableEntity, d)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if d.Admin {
		if err := s.lib.SetUserAdmin(d.Username, true); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	s.cfg.logWarn("user %q (admin %v) added by %q from the web UI", d.Username, d.Admin, admin.Username)
	s.issueLink(w, r, admin, id, d.Username)
}

func (s *Server) handlePeopleInvite(w http.ResponseWriter, r *http.Request) {
	admin := s.adminOnly(w, r)
	if admin == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	user, err := s.lib.UserByID(id)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.NotFound(w, r)
		return
	}
	s.issueLink(w, r, admin, user.ID, user.Username)
}

// issueLink mints a set-password link for userID and shows it once.
func (s *Server) issueLink(w http.ResponseWriter, r *http.Request, admin *reporter.User, userID int64, username string) {
	raw, err := s.lib.CreateInvite(userID, admin.ID, time.Now())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.cfg.logWarn("set-password link for %q issued by %q", username, admin.Username)
	s.renderPeople(w, r, http.StatusOK, peopleData{
		Link: s.baseURL(r) + "/set-password/" + raw, LinkFor: username})
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }
