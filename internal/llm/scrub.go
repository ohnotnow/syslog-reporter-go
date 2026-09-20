package llm

// Outbound scrubbing (SYSLOG_SCRUB*; ant ADR srg-Sgdkm, supersedes the
// SYSLOG_REDACT literal strip of srg-Mzvjf). Everything the pipeline
// sends to a provider passes through here: email addresses become
// numbered tokens, configured domains and public IP prefixes become
// their fake counterparts, and the reply is swapped back before it is
// decoded, so no agent, prompt or downstream store ever sees the fakes.
// Deliberately narrow: three patterns cover machine-written syslog text.
// This is not general PII scrubbing and the docs must not claim it is;
// --no-llm remains the route for log classes that forbid external
// processing. System prompts are not scrubbed: they are ours.

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// EmailPattern is the one email regex shared with the reporter's message
// templater (internal/reporter/template.go), so the two never drift. The
// domain side is dotted labels only, so an address inside JSON or quotes
// stops at the closing punctuation instead of swallowing it.
var EmailPattern = regexp.MustCompile(`[\w.+%-]+@[\w-]+(?:\.[\w-]+)+`)

var emailToken = regexp.MustCompile(`<email-(\d+)>`)

type scrubPair struct {
	real, fake string
	out, in    *regexp.Regexp // real -> fake, fake -> real
}

type scrubConfig struct {
	on       bool
	domains  []scrubPair
	prefixes []scrubPair
}

var (
	scrubMu  sync.RWMutex
	scrubCfg scrubConfig
)

// LoadScrub reads SYSLOG_SCRUB, SYSLOG_SCRUB_DOMAINS and
// SYSLOG_SCRUB_IP_PREFIXES once at startup and validates them, so a bad
// deployment dies naming the variable rather than on the first LLM
// call. A set SYSLOG_REDACT is refused outright: a stale .env must not
// silently lose the redaction it used to have.
func LoadScrub() error {
	if os.Getenv("SYSLOG_REDACT") != "" {
		return fmt.Errorf("SYSLOG_REDACT was replaced by SYSLOG_SCRUB, SYSLOG_SCRUB_DOMAINS and SYSLOG_SCRUB_IP_PREFIXES (see TECHNICAL_OVERVIEW.md); unset it")
	}
	return setScrub(os.Getenv("SYSLOG_SCRUB"), os.Getenv("SYSLOG_SCRUB_DOMAINS"), os.Getenv("SYSLOG_SCRUB_IP_PREFIXES"))
}

func setScrub(toggle, domains, prefixes string) error {
	var cfg scrubConfig
	if toggle != "" {
		on, err := strconv.ParseBool(toggle)
		if err != nil {
			return fmt.Errorf("SYSLOG_SCRUB=%q is not a boolean; use 1 or 0", toggle)
		}
		cfg.on = on
	}
	var err error
	if cfg.domains, err = parseScrubPairs("SYSLOG_SCRUB_DOMAINS", domains, domainPair); err != nil {
		return err
	}
	if cfg.prefixes, err = parseScrubPairs("SYSLOG_SCRUB_IP_PREFIXES", prefixes, prefixPair); err != nil {
		return err
	}
	if cfg.on && len(cfg.domains) == 0 && len(cfg.prefixes) == 0 {
		return fmt.Errorf("SYSLOG_SCRUB is on but SYSLOG_SCRUB_DOMAINS and SYSLOG_SCRUB_IP_PREFIXES are both empty")
	}
	scrubMu.Lock()
	scrubCfg = cfg
	scrubMu.Unlock()
	return nil
}

// parseScrubPairs turns "real=fake,real=fake" into pairs ordered longest
// real first (so a sub-domain entry wins over its parent), refusing
// duplicate fakes and a fake that is also a real, either of which would
// make the reversal ambiguous.
func parseScrubPairs(name, value string, build func(real, fake string) scrubPair) ([]scrubPair, error) {
	var pairs []scrubPair
	reals, fakes := map[string]bool{}, map[string]bool{}
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		real, fake, ok := strings.Cut(entry, "=")
		real, fake = strings.ToLower(strings.TrimSpace(real)), strings.ToLower(strings.TrimSpace(fake))
		if !ok || real == "" || fake == "" {
			return nil, fmt.Errorf("%s entry %q is not real=fake", name, entry)
		}
		if name == "SYSLOG_SCRUB_IP_PREFIXES" {
			for _, side := range []string{real, fake} {
				if !isDottedPrefix(side) {
					return nil, fmt.Errorf("%s entry %q: %q is not one to three dotted octets", name, entry, side)
				}
			}
		}
		if fakes[fake] {
			return nil, fmt.Errorf("%s: fake %q is used more than once", name, fake)
		}
		fakes[fake], reals[real] = true, true
		pairs = append(pairs, build(real, fake))
	}
	for fake := range fakes {
		if reals[fake] {
			return nil, fmt.Errorf("%s: %q is both a real and a fake value", name, fake)
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool { return len(pairs[i].real) > len(pairs[j].real) })
	return pairs, nil
}

func isDottedPrefix(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// domainPair matches the domain case-insensitively at word boundaries, so
// host.gla.ac.uk and GLA.AC.UK both swap and gla.ac.uk.example does not.
func domainPair(real, fake string) scrubPair {
	return scrubPair{real: real, fake: fake,
		out: regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(real) + `\b`),
		in:  regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(fake) + `\b`)}
}

// prefixPair matches the prefix plus its trailing dot at the start of a
// dotted quad, so 130.209 swaps in 130.209.55.103 but not 130.2091.1.1.
func prefixPair(real, fake string) scrubPair {
	return scrubPair{real: real, fake: fake,
		out: regexp.MustCompile(`\b` + regexp.QuoteMeta(real) + `\.`),
		in:  regexp.MustCompile(`\b` + regexp.QuoteMeta(fake) + `\.`)}
}

// ScrubWarning reports when the toggle is off and any of models is bound
// for a provider without the estate's data-processing agreement (only
// azure/ has one). A warning, never a refusal: the operator may have a
// contracted endpoint under an openai/ base URL.
func ScrubWarning(models ...string) string {
	scrubMu.RLock()
	on := scrubCfg.on
	scrubMu.RUnlock()
	if on {
		return ""
	}
	var outside []string
	for _, m := range models {
		if provider, _, _ := strings.Cut(m, "/"); provider != "azure" {
			outside = append(outside, m)
		}
	}
	if len(outside) == 0 {
		return ""
	}
	return fmt.Sprintf("SYSLOG_SCRUB is off: raw log lines, email addresses included, will be sent to %s", strings.Join(outside, ", "))
}

// scrubSession is one request's reversal table: the email addresses
// tokenised on the way out, in the order first seen.
type scrubSession struct {
	emails []string
}

// scrubOut applies the outbound pass and returns the session that undoes
// it. Emails go first (ant ADR srg-FGSKN's exposure incident: masking the
// domain first splits the address and leaks the local part), then
// domains, then IP prefixes. One count line goes to stderr, never values.
func scrubOut(text string) (string, *scrubSession) {
	scrubMu.RLock()
	cfg := scrubCfg
	scrubMu.RUnlock()
	sess := &scrubSession{}
	if !cfg.on {
		return text, sess
	}
	index := map[string]int{}
	text = EmailPattern.ReplaceAllStringFunc(text, func(addr string) string {
		n, seen := index[addr]
		if !seen {
			sess.emails = append(sess.emails, addr)
			n = len(sess.emails)
			index[addr] = n
		}
		return fmt.Sprintf("<email-%d>", n)
	})
	swaps := 0
	for _, p := range cfg.domains {
		text = replaceCounted(p.out, text, p.fake, &swaps)
	}
	for _, p := range cfg.prefixes {
		text = replaceCounted(p.out, text, p.fake+".", &swaps)
	}
	fmt.Fprintf(os.Stderr, "scrub: %d email address(es), %d domain/IP replacement(s) in outbound request\n", len(sess.emails), swaps)
	return text, sess
}

// ScrubOut is the outbound pass alone, for callers whose reply carries
// nothing to reverse (internal/jev gets scores back, not prose).
func ScrubOut(text string) string {
	text, _ = scrubOut(text)
	return text
}

func replaceCounted(re *regexp.Regexp, text, repl string, count *int) string {
	return re.ReplaceAllStringFunc(text, func(string) string {
		*count++
		return repl
	})
}

// in reverses the outbound pass on a provider reply: tokens back to
// addresses, fakes back to reals. Model prose that happens to mention a
// fake domain is reversed too, which is the accepted consequence.
func (s *scrubSession) in(text string) string {
	scrubMu.RLock()
	cfg := scrubCfg
	scrubMu.RUnlock()
	if !cfg.on {
		return text
	}
	text = emailToken.ReplaceAllStringFunc(text, func(tok string) string {
		n, _ := strconv.Atoi(emailToken.FindStringSubmatch(tok)[1])
		if n < 1 || n > len(s.emails) {
			return tok
		}
		return s.emails[n-1]
	})
	for _, p := range byFakeLength(cfg.domains) {
		text = p.in.ReplaceAllString(text, p.real)
	}
	for _, p := range byFakeLength(cfg.prefixes) {
		text = p.in.ReplaceAllString(text, p.real+".")
	}
	return text
}

// byFakeLength orders pairs longest fake first, the reversal's mirror of
// the outbound longest-real-first order.
func byFakeLength(pairs []scrubPair) []scrubPair {
	sorted := append([]scrubPair(nil), pairs...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].fake) > len(sorted[j].fake) })
	return sorted
}
