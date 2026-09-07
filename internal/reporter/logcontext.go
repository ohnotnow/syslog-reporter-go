package reporter

// Surrounding-line context for the resolution writer: the deterministic
// equivalent of 'grep -C 5', but per host. The detector hands each issue
// one example log entry; on its own that line makes the resolution model
// guess. Here we find that line in the raw (pre-filter) log and collect
// the same host's neighbouring lines, so the model sees the restart, cron
// kick or retry storm around it rather than the other 200 hosts' chatter.
// Deterministic code chooses the lines; the model only reads them.

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultContextRadius is how many same-host lines to take either side of
// the example log entry unless SYSLOG_CONTEXT_LINES / --context-lines says
// otherwise. 0 disables context entirely.
const DefaultContextRadius = 5

// Context match outcomes, reported so a run can log its own score card.
const (
	MatchExact = "exact" // the example log entry was found verbatim
	MatchFuzzy = "fuzzy" // matched on host + program + shared message words
	MatchMiss  = "miss"  // no anchor found; no context sent
)

// LogContext is the surrounding-line window for one issue.
type LogContext struct {
	Host  string   // host the window was taken from; "" on a miss
	Match string   // MatchExact, MatchFuzzy or MatchMiss
	Lines []string // the window, example line included, in log order
}

// LogIndex indexes the raw log by host for context lookups. Build it once
// per run; lookups are then cheap.
type LogIndex struct {
	radius int
	lines  []string
	parsed []*ParsedLine // parallel to lines; nil where ParseLine failed
	byHost map[string][]int
	exact  map[string]int // trimmed line -> first index
}

// NewLogIndex indexes lines in the order given, which must be log order
// (the ELK dumper sorts by timestamp). radius is the number of same-host
// lines taken either side of the anchor.
func NewLogIndex(lines []string, radius int) *LogIndex {
	ix := &LogIndex{
		radius: radius,
		lines:  make([]string, len(lines)),
		parsed: make([]*ParsedLine, len(lines)),
		byHost: map[string][]int{},
		exact:  make(map[string]int, len(lines)),
	}
	for i, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		ix.lines[i] = line
		if _, seen := ix.exact[line]; !seen {
			ix.exact[line] = i
		}
		p := ParseLine(line)
		ix.parsed[i] = p
		if p != nil {
			ix.byHost[p.Host] = append(ix.byHost[p.Host], i)
		}
	}
	return ix
}

// ContextsFor returns one LogContext per issue, in issue order.
func (ix *LogIndex) ContextsFor(issues *IssueList) []LogContext {
	out := make([]LogContext, len(issues.Issues))
	for i, issue := range issues.Issues {
		out[i] = ix.ContextFor(issue)
	}
	return out
}

// ContextFor anchors the issue's example log entry in the raw log and
// returns the same-host window around it. An exact match wins; otherwise
// the example is parsed for host and program and the candidate line from
// that host and program sharing the most message words is used (the
// model sometimes reshapes the line slightly, or decorates it). No shared
// word at all is a miss.
func (ix *LogIndex) ContextFor(issue *Issue) LogContext {
	example := strings.TrimSpace(issue.ExampleLogEntry)
	if example == "" {
		return LogContext{Match: MatchMiss}
	}
	if idx, ok := ix.exact[example]; ok {
		return ix.window(idx, MatchExact)
	}
	p := ParseLine(example)
	if p == nil {
		return LogContext{Match: MatchMiss}
	}
	want := messageWords(example)
	best, bestScore := -1, 0
	for _, idx := range ix.byHost[p.Host] {
		q := ix.parsed[idx]
		if q.Program != p.Program {
			continue
		}
		score := 0
		for w := range messageWords(ix.lines[idx]) {
			if want[w] {
				score++
			}
		}
		if score > bestScore { // strict: ties keep the earliest line
			best, bestScore = idx, score
		}
	}
	if best < 0 {
		return LogContext{Match: MatchMiss}
	}
	return ix.window(best, MatchFuzzy)
}

// window collects ContextRadius same-host lines either side of idx.
func (ix *LogIndex) window(idx int, match string) LogContext {
	p := ix.parsed[idx]
	if p == nil {
		// An exact match on a line ParseLine cannot read: no host to
		// walk, so the example alone is the whole window.
		return LogContext{Match: match, Lines: []string{ix.lines[idx]}}
	}
	hostIdx := ix.byHost[p.Host]
	pos := sort.SearchInts(hostIdx, idx)
	lo, hi := pos-ix.radius, pos+ix.radius+1
	if lo < 0 {
		lo = 0
	}
	if hi > len(hostIdx) {
		hi = len(hostIdx)
	}
	ctx := LogContext{Host: p.Host, Match: match}
	for _, i := range hostIdx[lo:hi] {
		ctx.Lines = append(ctx.Lines, ix.lines[i])
	}
	return ctx
}

// messageWords is the set of whitespace-separated words after the
// 'program[pid]:' field, or of the whole line when it does not parse.
func messageWords(line string) map[string]bool {
	msg := line
	if parts := splitWS(line, 5); len(parts) == 6 {
		msg = parts[5]
	}
	words := map[string]bool{}
	for _, w := range strings.Fields(msg) {
		words[w] = true
	}
	return words
}

// ToMarkdown renders the window for the resolution payload, or "" when
// there is nothing to add.
func (c LogContext) ToMarkdown() string {
	if len(c.Lines) == 0 {
		return ""
	}
	return fmt.Sprintf("**Surrounding log lines** (host %s, immediately before and after "+
		"the example, may include unrelated activity):\n\n```\n%s\n```\n",
		c.Host, strings.Join(c.Lines, "\n"))
}
