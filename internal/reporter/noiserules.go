package reporter

// The bundled noise rules (ait srg-M3Yny.2, ant ADR srg-uHwCr). They used
// to be two lists compiled into the filter; now they ship as
// noise-rules.txt, embedded here so a fresh box and a self-updated binary
// both have them, and 'knowns seed' loads them into the known_knowns
// table as host * entries with source bundled. The file format is
// described at the top of noise-rules.txt. This package owns the parser
// so the filter tests can pin the rules' behaviour without reaching into
// the command package.

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"strings"
)

// noise-rules.txt is .txt for the same reason as the eval fixture: the
// repo gitignores *.log, and an ignored embed file vanishes from fresh
// clones and breaks the build.
//
//go:embed noise-rules.txt
var bundledNoiseRules string

// DefaultNoiseReason is the reason a rule gets when its line has none.
const DefaultNoiseReason = "bundled noise rule"

// NoiseRule is one parsed rule: a host glob (usually *), a match regex
// already checked by the run's compiler, a reason, and the file line it
// came from for error messages.
type NoiseRule struct {
	Host, Match, Reason string
	Line                int
}

// BundledNoiseRules parses the embedded rules file.
func BundledNoiseRules() ([]NoiseRule, error) {
	return ParseNoiseRules(strings.NewReader(bundledNoiseRules))
}

// ParseNoiseRules reads the rules file format: comments and blank lines
// are skipped, an optional 'host=GLOB ' prefix scopes a rule, and a '#'
// preceded by whitespace starts the rule's reason. Every pattern is
// compiled here so an error names the line and nothing reaches the store.
func ParseNoiseRules(r io.Reader) ([]NoiseRule, error) {
	var rules []NoiseRule
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		rule := NoiseRule{Host: "*", Reason: DefaultNoiseReason, Line: n}
		if i := reasonStart(text); i >= 0 {
			rule.Reason = strings.TrimSpace(strings.TrimPrefix(text[i:], "#"))
			text = strings.TrimSpace(text[:i])
		}
		if strings.HasPrefix(text, "host=") {
			host, rest, ok := strings.Cut(text[len("host="):], " ")
			if !ok || host == "" || strings.TrimSpace(rest) == "" {
				return nil, fmt.Errorf("line %d: 'host=GLOB' must be followed by a pattern", n)
			}
			rule.Host, text = host, strings.TrimSpace(rest)
		}
		if err := CheckLinePattern(text); err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		rule.Match = text
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// reasonStart returns the index of the '#' that begins a rule's reason: a
// '#' preceded by whitespace. A '#' glued to the pattern (named's
// '<ip>#<port>') stays part of the pattern. -1 when there is no reason.
func reasonStart(text string) int {
	for i := 1; i < len(text); i++ {
		if text[i] == '#' && (text[i-1] == ' ' || text[i-1] == '\t') {
			return i
		}
	}
	return -1
}
