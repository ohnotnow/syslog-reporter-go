package llm

// Operator-supplied redaction (SYSLOG_REDACT; ant ADR srg-Mzvjf): literal
// strings stripped from every provider-bound user message, so an estate can
// keep its domain and hostnames out of API traffic. Deliberately minimal -
// an estate-identity courtesy, NOT a PII or compliance boundary; sites
// needing that should use a suitably contracted endpoint or --no-llm.
// System prompts are not redacted: they are ours, and the resolution stage
// legitimately carries the operator's own host/OS table.

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

const redactedMark = "[redacted]"

var (
	redactMu   sync.RWMutex
	redactList []string
)

// SetRedactions replaces the redaction list. Entries are trimmed; empties
// are dropped. main calls this once at startup with the parsed
// SYSLOG_REDACT value - this package never reads the environment itself.
func SetRedactions(values []string) {
	var list []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			list = append(list, v)
		}
	}
	redactMu.Lock()
	redactList = list
	redactMu.Unlock()
}

// redactUser applies the list to one outbound user message and reports the
// count on stderr (count only, never the values - the whole point is that
// they stay out of anything durable).
func redactUser(user string) string {
	redactMu.RLock()
	list := redactList
	redactMu.RUnlock()
	total := 0
	for _, needle := range list {
		var n int
		user, n = replaceFold(user, needle, redactedMark)
		total += n
	}
	if total > 0 {
		fmt.Fprintf(os.Stderr, "redaction: %d replacement(s) in outbound request\n", total)
	}
	return user
}

// replaceFold is strings.ReplaceAll with ASCII case-folding. ASCII-only on
// purpose: the targets are hostnames, domains and IPs, and asciiLower keeps
// byte offsets aligned between haystack and needle, which full Unicode
// folding does not guarantee.
func replaceFold(s, needle, repl string) (string, int) {
	if needle == "" {
		return s, 0
	}
	lower, ln := asciiLower(s), asciiLower(needle)
	var b strings.Builder
	n := 0
	for {
		i := strings.Index(lower, ln)
		if i < 0 {
			b.WriteString(s)
			return b.String(), n
		}
		b.WriteString(s[:i])
		b.WriteString(repl)
		s, lower = s[i+len(ln):], lower[i+len(ln):]
		n++
	}
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
