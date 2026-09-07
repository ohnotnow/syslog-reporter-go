package reporter

import (
	"strings"
	"testing"
)

// A small raw log with two hosts interleaved; the window must follow one
// host and skip the other's lines. Hostnames are fictional.
var contextLog = []string{
	"Sep  1 03:00:01 alpha cron[100]: (root) CMD (run-parts /etc/cron.hourly)",
	"Sep  1 03:00:02 beta sshd[200]: Accepted publickey for ops from 10.0.0.9",
	"Sep  1 03:00:03 alpha systemd[1]: Starting backup.service...",
	"Sep  1 03:00:04 beta sshd[200]: pam_unix(sshd:session): session opened",
	"Sep  1 03:00:05 alpha backup[300]: connecting to store.example.test",
	"Sep  1 03:00:06 alpha backup[300]: ERROR: connection refused by store.example.test:873",
	"Sep  1 03:00:07 beta sshd[200]: session closed",
	"Sep  1 03:00:08 alpha systemd[1]: backup.service: Main process exited, code=exited, status=1",
	"Sep  1 03:00:09 alpha systemd[1]: backup.service: Failed with result 'exit-code'.",
	"Sep  1 03:00:10 gamma kernel: eth0: link is up",
}

func TestLogIndexExactMatchWindowFollowsOneHost(t *testing.T) {
	ix := NewLogIndex(contextLog, DefaultContextRadius)
	c := ix.ContextFor(&Issue{ExampleLogEntry: contextLog[5]})
	if c.Match != MatchExact || c.Host != "alpha" {
		t.Fatalf("want exact match on alpha, got %+v", c)
	}
	want := []string{contextLog[0], contextLog[2], contextLog[4], contextLog[5], contextLog[7], contextLog[8]}
	if strings.Join(c.Lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("window:\n%s\nwant:\n%s", strings.Join(c.Lines, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range c.Lines {
		if strings.Contains(l, " beta ") || strings.Contains(l, " gamma ") {
			t.Errorf("window leaked another host's line: %s", l)
		}
	}
}

func TestLogIndexExactMatchTrimsTrailingNewline(t *testing.T) {
	lines := []string{contextLog[0] + "\n", contextLog[5] + "\n"}
	c := NewLogIndex(lines, DefaultContextRadius).ContextFor(&Issue{ExampleLogEntry: contextLog[5] + "\n"})
	if c.Match != MatchExact || len(c.Lines) != 2 {
		t.Fatalf("want exact match with 2 lines, got %+v", c)
	}
}

func TestLogIndexFuzzyMatchSurvivesDecoration(t *testing.T) {
	ix := NewLogIndex(contextLog, DefaultContextRadius)
	// The detector reshaped the line and added an emoji (seen from a small
	// model): same host and program, most message words shared.
	c := ix.ContextFor(&Issue{ExampleLogEntry: "Sep  1 03:00:06 alpha backup[300]: 🔥 ERROR: connection refused by store.example.test:873"})
	if c.Match != MatchFuzzy || c.Host != "alpha" {
		t.Fatalf("want fuzzy match on alpha, got %+v", c)
	}
	if !strings.Contains(strings.Join(c.Lines, "\n"), contextLog[5]) {
		t.Errorf("window should contain the real line; got %v", c.Lines)
	}
}

func TestLogIndexFuzzyPicksBestOverlapNotFirstLine(t *testing.T) {
	ix := NewLogIndex(contextLog, DefaultContextRadius)
	// Both backup lines share host and program; the example's words match
	// the second one better.
	c := ix.ContextFor(&Issue{ExampleLogEntry: "Sep  1 03:00:06 alpha backup[300]: connection refused by store.example.test:873 (retrying)"})
	if c.Match != MatchFuzzy {
		t.Fatalf("want fuzzy, got %+v", c)
	}
	// Anchor at contextLog[5]: alpha lines are 0,2,4,5,7,8 so the window is
	// all six; anchor at contextLog[4] would give the same set, so check
	// through a log where it matters.
	short := []string{contextLog[4], contextLog[5], contextLog[7], contextLog[8],
		"Sep  1 03:00:11 alpha systemd[1]: backup.service: Scheduled restart job",
		"Sep  1 03:00:12 alpha systemd[1]: Stopped backup.service",
		"Sep  1 03:00:13 alpha systemd[1]: Started backup.service",
		"Sep  1 03:00:14 alpha systemd[1]: backup.service: Consumed 1s CPU",
		"Sep  1 03:00:15 alpha systemd[1]: backup.service: idle",
	}
	c = NewLogIndex(short, DefaultContextRadius).ContextFor(&Issue{ExampleLogEntry: "Sep  1 03:00:06 alpha backup[300]: connection refused by store.example.test:873 (retrying)"})
	if c.Lines[0] != contextLog[4] || c.Lines[len(c.Lines)-1] != short[6] {
		t.Errorf("window not centred on the refused line: %v", c.Lines)
	}
}

func TestLogIndexMisses(t *testing.T) {
	ix := NewLogIndex(contextLog, DefaultContextRadius)
	cases := map[string]string{
		"empty example":   "",
		"unparseable":     "something the model made up",
		"unknown host":    "Sep  1 03:00:06 delta backup[300]: ERROR: connection refused",
		"no shared words": "Sep  1 03:00:06 alpha backup[300]: disk full",
		"wrong program":   "Sep  1 03:00:06 alpha rsync[300]: ERROR: connection refused by store.example.test:873",
	}
	for name, example := range cases {
		c := ix.ContextFor(&Issue{ExampleLogEntry: example})
		if c.Match != MatchMiss || len(c.Lines) != 0 || c.Host != "" {
			t.Errorf("%s: want a miss, got %+v", name, c)
		}
	}
}

func TestLogIndexWindowAtLogEdges(t *testing.T) {
	ix := NewLogIndex(contextLog, DefaultContextRadius)
	c := ix.ContextFor(&Issue{ExampleLogEntry: contextLog[0]})
	if len(c.Lines) != 6 || c.Lines[0] != contextLog[0] {
		t.Errorf("window at start of log should begin at the anchor: %v", c.Lines)
	}
	c = ix.ContextFor(&Issue{ExampleLogEntry: contextLog[9]})
	if len(c.Lines) != 1 || c.Lines[0] != contextLog[9] {
		t.Errorf("lone gamma line should be its own window: %v", c.Lines)
	}
}

func TestLogContextMarkdown(t *testing.T) {
	if got := (LogContext{Match: MatchMiss}).ToMarkdown(); got != "" {
		t.Errorf("a miss renders nothing, got %q", got)
	}
	got := (LogContext{Host: "alpha", Match: MatchExact, Lines: []string{"one", "two"}}).ToMarkdown()
	for _, want := range []string{"**Surrounding log lines** (host alpha", "```\none\ntwo\n```"} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\u2014") || strings.Contains(got, "\u2013") {
		t.Errorf("no dashes in output: %q", got)
	}
}

func TestResolutionPayloadAppendsContextPerIssue(t *testing.T) {
	issues := &IssueList{Issues: []*Issue{
		{Issue: "Backup refused", ExampleLogEntry: contextLog[5]},
		{Issue: "Made up", ExampleLogEntry: "no such line"},
	}}
	contexts := NewLogIndex(contextLog, DefaultContextRadius).ContextsFor(issues)
	got := NewResolutionAgent(issues, contexts, "test/model", nil).payload()
	first := strings.Index(got, "## Backup refused")
	ctx := strings.Index(got, "**Surrounding log lines** (host alpha")
	second := strings.Index(got, "## Made up")
	if first < 0 || ctx < 0 || second < 0 || !(first < ctx && ctx < second) {
		t.Fatalf("context block should sit between its issue and the next:\n%s", got)
	}
	if strings.Count(got, "**Surrounding log lines**") != 1 {
		t.Errorf("the missed issue must not get a context block:\n%s", got)
	}
	// No contexts at all (older callers, tests) still renders the issues.
	plain := NewResolutionAgent(issues, nil, "test/model", nil).payload()
	if !strings.Contains(plain, "## Made up") || strings.Contains(plain, "Surrounding") {
		t.Errorf("payload without contexts is just the issues:\n%s", plain)
	}
}

func TestLogIndexRadiusIsConfigurable(t *testing.T) {
	c := NewLogIndex(contextLog, 1).ContextFor(&Issue{ExampleLogEntry: contextLog[5]})
	want := []string{contextLog[4], contextLog[5], contextLog[7]}
	if strings.Join(c.Lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("radius 1 window:\n%s\nwant:\n%s", strings.Join(c.Lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestResolutionPromptMentionsContextOnlyWhenSent(t *testing.T) {
	with := resolutionPrompt(nil, true)
	without := resolutionPrompt(nil, false)
	if !strings.Contains(with, "Surrounding log lines") {
		t.Error("prompt with context should explain the block")
	}
	if strings.Contains(without, "Surrounding log lines") {
		t.Error("prompt without context must not promise a block that never comes")
	}
	for _, p := range []string{with, without} {
		if !strings.Contains(p, "Simple beats clever") {
			t.Error("simplicity rule missing")
		}
	}
	// The agent derives the flag from whether any contexts were given.
	if got := (&ResolutionAgent{Issues: &IssueList{}}).Contexts; len(got) != 0 {
		t.Errorf("no contexts by default, got %v", got)
	}
}
