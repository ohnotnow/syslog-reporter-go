package reporter

// Deterministic noise removal ahead of the LLM issue path. The anomaly
// detectors deliberately run upstream of this filter.

import (
	"regexp"
	"strings"
)

var pidBracketRe = regexp.MustCompile(`\[\d+\]`)

// StripPID removes every "[1234]" pid bracket, the normalisation the
// dedupe pass applies; 'knowns hits' groups caught lines by it too.
func StripPID(s string) string {
	return pidBracketRe.ReplaceAllString(s, "")
}

// compileLinePattern compiles a rule pattern for use on single lines that
// may retain their trailing newline: the (?m) flag makes `$` match just
// before that newline, so rules anchored at end-of-message still fire. No
// pattern in this codebase uses `^`, so the flag changes nothing else.
func compileLinePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?m)" + pattern)
}

// CompileLinePattern is compileLinePattern for callers outside the
// package that need the compiled regex ('knowns discover' checks each
// generated rule against its own example line).
func CompileLinePattern(pattern string) (*regexp.Regexp, error) {
	return compileLinePattern(pattern)
}

// CheckLinePattern reports whether pattern would be accepted as a
// known-known match, using the same compiler the run uses. For callers
// that want to fail with their own context (a file line number) before
// handing a batch to AddKnownEntries.
func CheckLinePattern(pattern string) error {
	_, err := compileLinePattern(pattern)
	return err
}

var (
	compiledNormalise = func() []*regexp.Regexp {
		res := make([]*regexp.Regexp, len(normaliseMap))
		for i, rule := range normaliseMap {
			res[i] = regexp.MustCompile("(?m)" + rule.pattern)
		}
		return res
	}()
)

// LogFilter drops known-known lines (the bundled noise rules and the
// operator's mutes, all rows of the known_knowns table), normalises what
// survives, and dedupes. A nil knowns means nothing is dropped.
type LogFilter struct {
	lines  []string
	knowns *KnownKnowns
	// spread is, per dedupe key, how many distinct hosts logged it before
	// the dedupe kept only three lines (see Spread).
	spread map[string]int
	// OnKnownDrop, when set, sees every line a known-known drops and the
	// entry that caught it. The run leaves it nil; 'knowns hits' uses it.
	OnKnownDrop func(e *KnownEntry, line string)
}

func NewLogFilter(lines []string, knowns *KnownKnowns) *LogFilter {
	return &LogFilter{lines: lines, knowns: knowns}
}

func (f *LogFilter) Run() []string {
	lines := f.removeKnownLines(f.lines)
	lines = f.normaliseLines(lines)
	lines = f.removeDuplicates(lines)
	return lines
}

func (f *LogFilter) removeKnownLines(lines []string) []string {
	// First step so the per-entry hit counts reflect the raw line volume,
	// before normalise and the dedupe cap thin things out.
	if f.knowns == nil {
		return lines
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		// Syslog format: "Month Day Time hostname message". ParseLine
		// supplies the program token for program-only entries; a line it
		// rejects still gets the host + message check for match entries.
		parts := splitWS(line, 4)
		if len(parts) < 5 {
			kept = append(kept, line)
			continue
		}
		program := ""
		if p := ParseLine(line); p != nil {
			program = p.Program
		}
		if e := f.knowns.IgnoringEntry(parts[3], program, parts[4]); e != nil {
			if f.OnKnownDrop != nil {
				f.OnKnownDrop(e, line)
			}
			continue
		}
		kept = append(kept, line)
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
					// NB this collapses the timestamp's double space ("Nov  8"
					// becomes "Nov 8") and drops the line's trailing newline.
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
	// Ignoring the syslog timestamp and host, keep at most 3 occurrences of
	// each unique message (pids and kernel timestamps stripped so otherwise
	// identical messages count together). Host is left out on purpose: a
	// bad config push that makes every host log the same error must not
	// send a thousand lines to the model. How many hosts logged it is kept
	// instead, for the issue detector (Spread).
	messageCounts := map[string]int{}
	hosts := map[string]map[string]bool{}
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		key, host := dedupeKey(line)
		if host != "" {
			if hosts[key] == nil {
				hosts[key] = map[string]bool{}
			}
			hosts[key][host] = true
		}
		if messageCounts[key] < 3 {
			messageCounts[key]++
			result = append(result, line)
		}
	}
	f.spread = make(map[string]int, len(hosts))
	for key, set := range hosts {
		f.spread[key] = len(set)
	}
	return result
}

// dedupeKey is the message removeDuplicates counts by (program and
// message, pid stripped) and the line's host, "" when it has none.
func dedupeKey(line string) (key, host string) {
	parts := splitWS(line, 4)
	if len(parts) < 5 {
		return pidBracketRe.ReplaceAllString(strings.TrimSpace(line), ""), ""
	}
	return pidBracketRe.ReplaceAllString(parts[4], ""), parts[3]
}

// Spread reports, after Run, how many distinct hosts logged each message
// the dedupe capped. The issue detector tags lines seen on more than one
// host with it, so three examples from one host still read as estate-wide
// when they are (ait srg-6Vsgx.6).
func (f *LogFilter) Spread() map[string]int {
	return f.spread
}
