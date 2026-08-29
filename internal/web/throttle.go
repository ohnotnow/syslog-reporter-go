package web

// A small in-memory per-IP failed-login throttle (srg-so8ja.8): without
// one, an unauthenticated client can burn a full bcrypt per request as
// fast as it can post the form. Fixed window, deliberately modest - this
// is a solo/small-team tool, not a distributed system.

import (
	"net"
	"sync"
	"time"
)

const (
	maxLoginFailures = 5
	loginLockout     = time.Minute
	// throttlePruneAt caps the map against an address-hopping client:
	// past this size, expired entries are dropped on the next failure.
	throttlePruneAt = 1024
)

type throttleEntry struct {
	count int
	until time.Time // lockout expiry, zero until the limit is reached
}

type loginThrottle struct {
	mu      sync.Mutex
	entries map[string]throttleEntry
	now     func() time.Time // swapped in tests
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{entries: map[string]throttleEntry{}, now: time.Now}
}

// blocked reports whether ip is inside a lockout window. An expired
// lockout clears the slate.
func (t *loginThrottle) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[ip]
	if !ok || e.until.IsZero() {
		return false
	}
	if t.now().After(e.until) {
		delete(t.entries, ip)
		return false
	}
	return true
}

// fail records one failed attempt; the Nth starts the lockout window.
func (t *loginThrottle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) > throttlePruneAt {
		now := t.now()
		for k, e := range t.entries {
			if !e.until.IsZero() && now.After(e.until) {
				delete(t.entries, k)
			}
		}
	}
	e := t.entries[ip]
	e.count++
	if e.count >= maxLoginFailures {
		e.until = t.now().Add(loginLockout)
	}
	t.entries[ip] = e
}

// success clears the IP's slate.
func (t *loginThrottle) success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
}

// clientIP is the host part of RemoteAddr only: this app never trusts
// forwarded headers (it has no configured proxy notion of them).
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
