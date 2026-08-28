package web

// The auth seam (ait srg-2KY5X.4). SYSLOG_AUTH_MODE selects a driver; the
// rest of the app only ever asks "who is the current user, if anyone?".
// Mode none is the solo-sysadmin case and the default; local is form login
// against the users table; oidc arrives in a later issue.

import (
	"fmt"
	"net/http"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// UserStore is the slice of the library store the auth drivers need.
type UserStore interface {
	UserByUsername(username string) (*reporter.User, error)
	UserByID(id int64) (*reporter.User, error)
}

type Authenticator interface {
	// Middleware wraps the whole route tree: sessions, the login redirect.
	Middleware(next http.Handler) http.Handler
	// CurrentUser is nil when unauthenticated (always, in mode none).
	CurrentUser(r *http.Request) *reporter.User
	// Routes registers the driver's own pages (login, logout).
	Routes(mux *http.ServeMux)
}

// NewAuthenticator selects the driver for cfg.AuthMode. Mode oidc errors at
// startup until that driver lands (ait srg-2KY5X.5); so does any
// unrecognised value.
func NewAuthenticator(cfg Config, users UserStore) (Authenticator, error) {
	switch cfg.AuthMode {
	case "", "none":
		return noneAuth{}, nil
	case "local":
		if users == nil {
			return nil, fmt.Errorf("SYSLOG_AUTH_MODE=local needs a user store")
		}
		return newLocalAuth(cfg, users), nil
	case "oidc":
		return nil, fmt.Errorf("SYSLOG_AUTH_MODE=oidc: the oidc driver is not built yet")
	default:
		return nil, fmt.Errorf("SYSLOG_AUTH_MODE=%q: unknown mode (none, local, oidc)", cfg.AuthMode)
	}
}

// noneAuth: no login routes, everyone anonymous, every page open.
type noneAuth struct{}

func (noneAuth) Middleware(next http.Handler) http.Handler { return next }
func (noneAuth) CurrentUser(*http.Request) *reporter.User  { return nil }
func (noneAuth) Routes(*http.ServeMux)                     {}
