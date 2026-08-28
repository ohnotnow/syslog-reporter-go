package reporter

// Port of agents/log_agent.py: deterministic noise removal ahead of the LLM
// issue path. The anomaly detectors deliberately run upstream of this filter.

import (
	"os"
	"regexp"
	"strings"
)

var pidBracketRe = regexp.MustCompile(`\[\d+\]`)

// compilePyPattern compiles a Python-re pattern for use on single lines that
// may retain their trailing newline. The (?m) flag makes Go's `$` match just
// before that newline, which is what Python's non-multiline `$` does with a
// final newline; no pattern in this codebase uses `^`, so the flag changes
// nothing else.
func compilePyPattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?m)" + pattern)
}

func mustCompilePyPatterns(patterns []string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		res[i] = regexp.MustCompile("(?m)" + p)
	}
	return res
}

var (
	compiledRegexIgnores = mustCompilePyPatterns(regexIgnoreList)
	compiledNormalise    = func() []*regexp.Regexp {
		res := make([]*regexp.Regexp, len(normaliseMap))
		for i, rule := range normaliseMap {
			res[i] = regexp.MustCompile("(?m)" + rule.pattern)
		}
		return res
	}()
)

type LogFilter struct {
	lines  []string
	knowns *KnownKnowns
	// Estate-specific ignore substrings (hostnames, internal IPs, local
	// usernames) live in the environment, not in this public codebase:
	// SYSLOG_BLANKET_IGNORE is a comma-separated list treated exactly
	// like ignoreList entries.
	BlanketIgnores []string
}

func NewLogFilter(lines []string, knowns *KnownKnowns) *LogFilter {
	var blanket []string
	for _, t := range strings.Split(os.Getenv("SYSLOG_BLANKET_IGNORE"), ",") {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			blanket = append(blanket, trimmed)
		}
	}
	return &LogFilter{lines: lines, knowns: knowns, BlanketIgnores: blanket}
}

func (f *LogFilter) Run() []string {
	lines := f.removeKnownLines(f.lines)
	lines = f.removeIgnoredLines(lines)
	lines = f.removeRegexIgnoredLines(lines)
	lines = f.normaliseLines(lines)
	lines = f.removeDuplicates(lines)
	return lines
}

func (f *LogFilter) removeKnownLines(lines []string) []string {
	// First step so the per-entry hit counts reflect the raw line volume,
	// before the general ignores and the dedupe cap thin things out.
	if f.knowns == nil {
		return lines
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		// Syslog format: "Month Day Time hostname message"
		parts := splitWS(line, 4)
		if len(parts) >= 5 && f.knowns.LineIgnored(parts[3], parts[4]) {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

func (f *LogFilter) removeIgnoredLines(lines []string) []string {
	ignores := append(append([]string{}, ignoreList...), f.BlanketIgnores...)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		ignored := false
		for _, ig := range ignores {
			if strings.Contains(line, ig) {
				ignored = true
				break
			}
		}
		if !ignored {
			kept = append(kept, line)
		}
	}
	return kept
}

func (f *LogFilter) removeRegexIgnoredLines(lines []string) []string {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		ignored := false
		for _, re := range compiledRegexIgnores {
			if re.MatchString(line) {
				ignored = true
				break
			}
		}
		if !ignored {
			kept = append(kept, line)
		}
	}
	return kept
}

func (f *LogFilter) normaliseLines(lines []string) []string {
	normalised := make([]string, 0, len(lines))
	for _, line := range lines {
		out := line
		for i, re := range compiledNormalise {
			if re.MatchString(out) {
				// example line: Nov  8 12:48:51 travis firefox[37746]: OnCloseSessionDone error:
				// we want to normalise it to: Nov  8 12:48:51 travis replacement
				parts := splitWS(out, 4)
				if len(parts) >= 5 {
					// Keep timestamp and hostname, replace message with replacement.
					// NB like the Python original this collapses the timestamp's
					// double space ("Nov  8" becomes "Nov 8") and drops the
					// line's trailing newline.
					out = strings.Join(parts[:4], " ") + " " + normaliseMap[i].replacement
				} else {
					out = normaliseMap[i].replacement
				}
				break
			}
		}
		normalised = append(normalised, out)
	}
	return normalised
}

func (f *LogFilter) removeDuplicates(lines []string) []string {
	// Ignoring the syslog timestamp, keep at most 3 occurrences of each
	// unique message (pids and kernel timestamps stripped so otherwise
	// identical messages count together).
	messageCounts := map[string]int{}
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		parts := splitWS(line, 4)
		var message string
		if len(parts) >= 5 {
			message = parts[4]
		} else {
			message = pyStrip(line)
		}
		normalisedMessage := pidBracketRe.ReplaceAllString(message, "")
		if messageCounts[normalisedMessage] < 3 {
			messageCounts[normalisedMessage]++
			result = append(result, line)
		}
	}
	return result
}
