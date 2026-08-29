package web

// The local auth driver: form login checking bcrypt against the users
// table, sessions held in memory via scs (everyone is logged out on
// restart; accepted for this tool).

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

type ctxKey int

const userContextKey ctxKey = 0

const sessionUserKey = "userID"

// dummyHash (bcrypt of an arbitrary string at DefaultCost) is compared
// against on the unknown-user and NULL-hash paths, so a failed login costs
// the same whether or not the username exists: without it the fast fail is
// a timing oracle for enumerating usernames.
const dummyHash = "$2a$10$sr17aG207Q6pHLLx7nLsXutTfPgwj0/h9QPNl0kb3VR0GTb24JBAy"

type localAuth struct {
	cfg      Config
	users    UserStore
	sessions *scs.SessionManager
	throttle *loginThrottle
}

func newLocalAuth(cfg Config, users UserStore) *localAuth {
	sm := scs.New()
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	// Decided once from the serve TLS config, not per-request from r.TLS;
	// SecureCookies covers TLS terminated at a reverse proxy (srg-so8ja.9).
	sm.Cookie.Secure = cfg.CertFile != "" || cfg.SecureCookies
	return &localAuth{cfg: cfg, users: users, sessions: sm,
		throttle: newLoginThrottle()}
}

// Middleware loads the session, resolves the current user into the request
// context, and bounces unauthenticated requests to /login with the original
// path in next. Only /login itself and the static assets are exempt.
func (a *localAuth) Middleware(next http.Handler) http.Handler {
	return a.sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if id := a.sessions.GetInt64(r.Context(), sessionUserKey); id != 0 {
			if user, err := a.users.UserByID(id); err == nil && user != nil {
				ctx := context.WithValue(r.Context(), userContextKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		q := url.Values{"next": {r.URL.RequestURI()}}
		http.Redirect(w, r, "/login?"+q.Encode(), http.StatusFound)
	}))
}

func (a *localAuth) CurrentUser(r *http.Request) *reporter.User {
	user, _ := r.Context().Value(userContextKey).(*reporter.User)
	return user
}

func (a *localAuth) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", a.handleLoginForm)
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.HandleFunc("POST /logout", a.handleLogout)
}

type loginData struct {
	Error    string
	Next     string
	Username string
}

func (a *localAuth) renderLogin(w http.ResponseWriter, d loginData) {
	render(w, "login.html", pageData{
		Version: a.cfg.Version,
		Path:    "/login",
		Data:    d,
	})
}

func (a *localAuth) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	a.renderLogin(w, loginData{Next: safeNext(r.FormValue("next"))})
}

func (a *localAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	// The lockout check comes before any parsing or bcrypt work: its whole
	// job is to stop an unauthenticated client burning CPU (srg-so8ja.8).
	ip := clientIP(r.RemoteAddr)
	if a.throttle.blocked(ip) {
		http.Error(w, "too many failed login attempts; try again shortly",
			http.StatusTooManyRequests)
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	// One generic message for every failure, so the form cannot be used to
	// enumerate usernames.
	fail := func() {
		a.throttle.fail(ip)
		a.renderLogin(w, loginData{
			Error:    "That username and password combination was not recognised.",
			Next:     next,
			Username: username,
		})
	}
	user, err := a.users.UserByUsername(username)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if user == nil || !user.PasswordHash.Valid {
		// Unknown username, or an SSO-created user with no local password
		// (who can never sign in here, deliberately). Pay the bcrypt cost
		// anyway so the response time does not leak which case this was.
		bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		fail()
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(password)) != nil {
		fail()
		return
	}
	a.throttle.success(ip)
	// Fresh session token on privilege change, then remember only the id;
	// the middleware loads the row on each request.
	if err := a.sessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.sessions.Put(r.Context(), sessionUserKey, user.ID)
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *localAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := a.sessions.Destroy(r.Context()); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// safeNext keeps the post-login redirect on this site: a single leading
// slash only, or the front page.
func safeNext(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\") {
		return "/"
	}
	return p
}
