package web

// A small in-memory fixed-window counter shared by the failed-login
// throttle (srg-so8ja.8: without one, an unauthenticated client can burn a
// full bcrypt per request as fast as it can post the form) and the
// sysadmin API's per-token mute cap (ait srg-Kj5Q8.4). Deliberately
// modest - this is a solo/small-team tool, not a distributed system.
// Shape lifted from the owner's csr-api rate limiter.

import (
	"net"
	"sync"
	"time"
)

const (
	maxLoginFailures = 5
	loginLockout     = time.Minute
	// counterPruneAt caps the map against a key-hopping client: past this
	// size, expired entries are dropped on the next record.
	counterPruneAt = 1024
)

type windowEntry struct {
	start time.Time // first event of the current window
	count int
}

// windowCounter allows at most limit events per key in each fixed window.
// A key's window starts at its first event and resets once it has
// elapsed. State lives in memory only, so a restart clears it.
type windowCounter struct {
	limit  int
	window time.Duration
	now    func() time.Time // swapped in tests

	mu      sync.Mutex
	entries map[string]windowEntry
}

func newWindowCounter(limit int, window time.Duration) *windowCounter {
	return &windowCounter{limit: limit, window: window, now: time.Now,
		entries: map[string]windowEntry{}}
}

func newLoginThrottle() *windowCounter {
	return newWindowCounter(maxLoginFailures, loginLockout)
}

// current returns the key's live entry, treating an elapsed window as
// absent. Callers hold the lock.
func (c *windowCounter) current(key string, now time.Time) (windowEntry, bool) {
	e, ok := c.entries[key]
	if !ok || now.Sub(e.start) >= c.window {
		return windowEntry{}, false
	}
	return e, true
}

// blocked reports whether key has reached the limit in its current window,
// and how long until that window resets.
func (c *windowCounter) blocked(key string) (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e, ok := c.current(key, now)
	if !ok || e.count < c.limit {
		return false, 0
	}
	return true, e.start.Add(c.window).Sub(now)
}

// record counts one event for key, starting a window if none is live.
func (c *windowCounter) record(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.entries) > counterPruneAt {
		for k, e := range c.entries {
			if now.Sub(e.start) >= c.window {
				delete(c.entries, k)
			}
		}
	}
	e, ok := c.current(key, now)
	if !ok {
		e = windowEntry{start: now}
	}
	e.count++
	c.entries[key] = e
}

// allow records an event for key if it is within the limit and reports
// whether it was; when refused, retryAfter is how long until the window
// resets. The mute cap uses this; the login path uses blocked and record
// separately because it must refuse before doing any work.
func (c *windowCounter) allow(key string) (ok bool, retryAfter time.Duration) {
	if blocked, wait := c.blocked(key); blocked {
		return false, wait
	}
	c.record(key)
	return true, 0
}

// reset clears the key's slate (a successful login).
func (c *windowCounter) reset(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// clientIP is the host part of RemoteAddr only: this app never trusts
// forwarded headers (it has no configured proxy notion of them).
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
