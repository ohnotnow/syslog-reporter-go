package reporter

// Tests for both report layouts (the SMTP EmailAgent tests live in
// emailer_test.go).

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func testIssue(title, severity string) *Issue {
	return &Issue{
		Issue: title, Severity: severity, Description: title + " desc",
		ExampleLogEntry: "...", AffectedHost: []string{"h1"}, AffectedService: "svc",
		TimestampFrequency: "all day", PotentialImpact: "bad",
		RecommendedAction: "fix " + title,
	}
}

func testResolution(title string) *Resolution {
	return &Resolution{
		Issue: title, RootCause: title + " cause",
		Investigate: "systemctl status " + title,
		LookFor:     "healthy is active (running); failed means " + title + " is down",
		FixCommands: []string{"systemctl restart " + title}, Notes: "might just be off",
	}
}

func testAnomaly() *ExplainedAnomaly {
	return &ExplainedAnomaly{
		Host: "hastings", Program: "kernel", Kind: "peer",
		Headline: "Louder than its peers",
		Detail:   "41,839 events vs a fleet median of 592 across peer hosts.",
		OSFamily: "RHEL-family", ExampleLine: "pulseaudio segfault",
		LikelyCauses:       "pulseaudio is crash-looping.",
		InvestigationSteps: []string{"check coredumpctl"},
		SuggestedCommands:  []string{"coredumpctl list"},
	}
}

func TestTopIssuesSortedBySeverityAndCapped(t *testing.T) {
	rep := &ReportAgent{
		Issues: &IssueList{Issues: []*Issue{
			testIssue("a-low", "low"),
			testIssue("b-critical", "critical"),
			testIssue("c-medium", "medium"),
			testIssue("d-high", "high"),
		}},
		Resolutions: &ResolutionList{},
	}
	top := rep.topIssues(2)
	if len(top) != 2 || top[0].Issue != "b-critical" || top[1].Issue != "d-high" {
		var names []string
		for _, i := range top {
			names = append(names, i.Issue)
		}
		t.Errorf("got %v, want [b-critical d-high]", names)
	}
}

func TestEmailBodyShowsTopIssuesWithCommandsAndHidesTheRest(t *testing.T) {
	rep := &ReportAgent{
		Issues: &IssueList{Issues: []*Issue{
			testIssue("disk-full", "critical"),
			testIssue("clock-skew", "high"),
			testIssue("cosmetic-thing", "low"),
		}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{
			testResolution("disk-full"), testResolution("clock-skew"),
		}},
		Anomalies: []*ExplainedAnomaly{testAnomaly()},
	}
	body := rep.emailBodyN(2, 1)

	for _, want := range []string{
		"disk-full",                  // critical: in body
		"clock-skew",                 // high: in body
		"systemctl status disk-full", // investigate command shown
		"**What to look for:** healthy is active (running); failed means disk-full is down",
		"systemctl restart disk-full", // fix command shown
		"```",                         // commands are in a code fence
		"of 3 issues",                 // signals there is more
		"hastings",                    // top anomaly included
		"coredumpctl list",            // anomaly command shown
		"email_attachment.md",         // points at the attachment
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, "cosmetic-thing") { // low, beyond top 2: not in body
		t.Error("body should not contain cosmetic-thing")
	}
}

// The digest shows each issue's verbatim example log line, placed after the
// description and before the resolution (which refers back to it), whether
// or not a resolution exists. An empty example writes nothing.
func TestEmailBodyShowsExampleLogEntry(t *testing.T) {
	withRes := testIssue("dnssec", "high")
	withRes.ExampleLogEntry = "Sep  6 16:58:17 barbados journal: Suppressed 9668 messages"
	noRes := testIssue("orphan", "medium")
	noRes.ExampleLogEntry = "Sep  6 17:00:01 tobago cron: orphan job"
	blank := testIssue("blank", "low")
	blank.ExampleLogEntry = ""
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{withRes, noRes, blank}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{testResolution("dnssec")}},
	}
	body := rep.EmailBody()

	for _, want := range []string{
		"dnssec desc\n\n**Example:**\n\n```\n" + withRes.ExampleLogEntry + "\n```\n\n**Likely cause:**",
		"orphan desc\n\n**Example:**\n\n```\n" + noRes.ExampleLogEntry + "\n```\n\n👉 fix orphan",
		"blank desc\n\n👉 fix blank",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestEmailBodyFallsBackToRecommendedActionWithoutResolution(t *testing.T) {
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{testIssue("orphan", "high")}},
		Resolutions: &ResolutionList{},
	}
	if body := rep.EmailBody(); !strings.Contains(body, "fix orphan") {
		t.Errorf("body missing recommended_action fallback: %q", body)
	}
}

func TestEmailBodyHandlesNoIssues(t *testing.T) {
	rep := &ReportAgent{Issues: &IssueList{}, Resolutions: &ResolutionList{}}
	if body := rep.EmailBody(); !strings.Contains(body, "quiet day") {
		t.Errorf("body missing quiet day note: %q", body)
	}
}

// A --no-llm run must never masquerade as a clean bill of health: the body
// and the full report both say the analysis was skipped, while anomaly facts
// from the deterministic detectors still render.

func TestNoLlmBodySaysSkippedNotQuietDay(t *testing.T) {
	rep := &ReportAgent{
		Issues: &IssueList{}, Resolutions: &ResolutionList{},
		Anomalies: []*ExplainedAnomaly{testAnomaly()}, LLMSkipped: true,
	}
	body := rep.EmailBody()
	if !strings.Contains(body, "skipped") {
		t.Error("body should say skipped")
	}
	if strings.Contains(body, "quiet day") {
		t.Error("body must not claim a quiet day")
	}
	if !strings.Contains(body, "hastings") { // anomaly facts still shown
		t.Error("body missing the anomaly facts")
	}
}

func TestNoLlmFullReportSaysSkippedInIssueSections(t *testing.T) {
	rep := &ReportAgent{
		Issues: &IssueList{}, Resolutions: &ResolutionList{},
		Anomalies: []*ExplainedAnomaly{testAnomaly()}, LLMSkipped: true,
	}
	report := rep.Run()
	if !strings.Contains(report, "--no-llm run") {
		t.Error("report should mention the --no-llm run")
	}
	if strings.Contains(report, "No resolutions generated") {
		t.Error("report should not fall through to the empty-resolutions note")
	}
	if !strings.Contains(report, "hastings") {
		t.Error("report missing the anomaly facts")
	}
}

func TestHostListTruncated(t *testing.T) {
	issue := testIssue("many-hosts", "high")
	issue.AffectedHost = nil
	for i := 0; i < 12; i++ {
		issue.AffectedHost = append(issue.AffectedHost, fmt.Sprintf("h%d", i))
	}
	if got := issue.HostsSummary(); !strings.Contains(got, "… and 7 more") {
		t.Errorf("got %q", got)
	}
}

func TestIssueOSRendersOnlyWhenKnown(t *testing.T) {
	withOS := testIssue("os-known", "high")
	withOS.OS = "Rocky Linux 9 x3, Ubuntu 22.04 x1"
	withoutOS := testIssue("os-absent", "high") // a library row captured before the field existed

	if md := withOS.ToMarkdown(); !strings.Contains(md, "- **OS:** Rocky Linux 9 x3, Ubuntu 22.04 x1\n") {
		t.Errorf("full report missing the OS line:\n%s", md)
	}
	if md := withoutOS.ToMarkdown(); strings.Contains(md, "OS:") {
		t.Errorf("full report should omit the OS line when empty:\n%s", md)
	}

	r := &ReportAgent{Issues: &IssueList{Issues: []*Issue{withOS, withoutOS}},
		Resolutions: &ResolutionList{}}
	body := r.EmailBody()
	if !strings.Contains(body, "**Affected:** h1 · **OS:** Rocky Linux 9 x3, Ubuntu 22.04 x1\n") {
		t.Errorf("digest missing the OS on the affected line:\n%s", body)
	}
	if strings.Count(body, "**OS:**") != 1 {
		t.Errorf("digest should show OS only for the issue that has one:\n%s", body)
	}
}

func TestIssueMarkdownHasBlankLineSeparation(t *testing.T) {
	// The blob bug: fields must be paragraph-separated, not glued together.
	md := testIssue("x", "high").ToMarkdown()
	if !strings.Contains(md, "\n\n") {
		t.Error("markdown missing blank-line separation")
	}
	if !strings.Contains(md, "```") { // example log entry fenced
		t.Error("markdown missing code fence")
	}
}

// Suppression must stay visible: a muted entry that never appears anywhere
// is how a known known quietly becomes an unwatched fault.

func knownsReport(knowns *KnownKnowns) *ReportAgent {
	return &ReportAgent{Issues: &IssueList{}, Resolutions: &ResolutionList{},
		Knowns: knowns}
}

func TestFiredKnownEntriesAppearInBodyAndFullReport(t *testing.T) {
	entry := mustEntry(t, "scopebox", "microscope kit", "port 1234", "", nil)
	knowns := NewKnownKnowns([]*KnownEntry{entry}, day(2026, 8, 27))
	knowns.LineIgnored("scopebox", "", "retry on port 1234")

	rep := knownsReport(knowns)
	for _, text := range []string{rep.EmailBody(), rep.Run()} {
		if !strings.Contains(text, "microscope kit (scopebox) ×1") {
			t.Errorf("missing suppression note in: %q", text)
		}
	}
}

func TestExpiredKnownEntriesAreFlagged(t *testing.T) {
	entry := mustEntry(t, "scopebox", "microscope kit", "port 1234", "", datePtr(2026, 1, 1))
	rep := knownsReport(NewKnownKnowns([]*KnownEntry{entry}, day(2026, 8, 27)))
	for _, text := range []string{rep.EmailBody(), rep.Run()} {
		if !strings.Contains(text, "1 known-known entry has expired") {
			t.Errorf("missing expiry note in: %q", text)
		}
	}
}

func TestSilentKnownsRenderNoFooter(t *testing.T) {
	entry := mustEntry(t, "scopebox", "microscope kit", "port 1234", "", nil)
	rep := knownsReport(NewKnownKnowns([]*KnownEntry{entry}, day(2026, 8, 27)))
	if strings.Contains(rep.EmailBody(), "Known knowns") {
		t.Error("email body should have no knowns footer")
	}
	if strings.Contains(rep.Run(), "Known Knowns") {
		t.Error("full report should have no knowns section")
	}
}

func TestNoKnownsAtAllIsFine(t *testing.T) {
	rep := knownsReport(nil)
	if strings.Contains(rep.EmailBody(), "Known knowns") {
		t.Error("email body should have no knowns footer")
	}
}

// The model footer names which model did the analysis, so teams comparing
// models can tell reports apart (owner decision 2026-08-28).
func TestModelFooterOnBothLayouts(t *testing.T) {
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{testIssue("disk-full", "critical")}},
		Resolutions: &ResolutionList{},
		Anomalies:   []*ExplainedAnomaly{testAnomaly()},
		Model:       "openai/gpt-5.6-luna",
	}
	footer := "_Analysis by openai/gpt-5.6-luna_\n"
	full := rep.Run()
	if !strings.HasSuffix(full, "---\n\n"+footer) {
		t.Errorf("full report should end with the model footer, ends: %q", tail(full))
	}
	body := rep.EmailBody()
	if !strings.HasSuffix(body, "\n"+footer) {
		t.Errorf("email body should end with the model footer, ends: %q", tail(body))
	}
}

// A run split across a scan model and an issue model is attributed to both,
// issue model first because that is the one whose prose the reader is
// looking at; a single-model run keeps the plain label so nothing changes
// for the default setup.
func TestModelLabelNamesBothModelsOnlyWhenTheyDiffer(t *testing.T) {
	if got := ModelLabel("openai/gpt-5.6-luna", "openai/gpt-5.6-luna"); got != "openai/gpt-5.6-luna" {
		t.Errorf("same model both stages: got %q", got)
	}
	got := ModelLabel("openai/gpt-5.6-luna", "anthropic/claude-fable-5-1")
	if want := "anthropic/claude-fable-5-1 (scan: openai/gpt-5.6-luna)"; got != want {
		t.Errorf("split models: got %q, want %q", got, want)
	}
}

func TestModelFooterOmittedWhenNoAnalysisRan(t *testing.T) {
	skipped := &ReportAgent{
		Issues: &IssueList{}, Resolutions: &ResolutionList{},
		LLMSkipped: true, Model: "openai/gpt-5.6-luna",
	}
	noModel := &ReportAgent{
		Issues: &IssueList{}, Resolutions: &ResolutionList{},
	}
	for name, rep := range map[string]*ReportAgent{"llm-skipped": skipped, "no-model": noModel} {
		for layout, text := range map[string]string{"full": rep.Run(), "body": rep.EmailBody()} {
			if strings.Contains(text, "_Analysis by") {
				t.Errorf("%s %s layout should have no model footer", name, layout)
			}
		}
	}
}

func tail(s string) string {
	if len(s) > 60 {
		return s[len(s)-60:]
	}
	return s
}

// The paste caution (srg-so8ja.5) appears exactly once per layout when the
// LLM stages ran, and never on a --no-llm run - there are no LLM commands
// to warn about then, and clutter is its own failure.
func TestCommandCautionOnBothLayoutsWhenLLMRan(t *testing.T) {
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{testIssue("stuck", "high")}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{testResolution("stuck")}},
		Anomalies:   []*ExplainedAnomaly{testAnomaly()},
		Model:       "openai/gpt-test",
	}
	for name, out := range map[string]string{"digest": rep.EmailBody(), "full": rep.Run()} {
		if got := strings.Count(out, "Review before pasting"); got != 1 {
			t.Errorf("%s layout: caution appears %d times, want exactly 1:\n%s", name, got, out)
		}
	}
}

func TestCommandCautionAbsentOnNoLLMRun(t *testing.T) {
	rep := &ReportAgent{
		Issues:      &IssueList{},
		Resolutions: &ResolutionList{},
		Anomalies:   []*ExplainedAnomaly{testAnomaly()},
		LLMSkipped:  true,
	}
	for name, out := range map[string]string{"digest": rep.EmailBody(), "full": rep.Run()} {
		if strings.Contains(out, "Review before pasting") {
			t.Errorf("%s layout: caution present on a --no-llm run:\n%s", name, out)
		}
	}
}

// Both titles carry the LOG day, not the run day, so a backfilled or
// re-run historical day is titled with the date its logs cover.

func TestReportTitlesUseLogDateNotRunDate(t *testing.T) {
	rep := &ReportAgent{
		Issues: &IssueList{}, Resolutions: &ResolutionList{},
		LogDate: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC),
	}
	if body := rep.EmailBody(); !strings.Contains(body, "# Syslog digest - 31/08/2026") {
		t.Errorf("digest title missing log date:\n%s", body)
	}
	if full := rep.Run(); !strings.Contains(full, "# Syslog Report for 31/08/2026") {
		t.Errorf("full report title missing log date:\n%s", full)
	}
}

func TestReportTitlesFallBackToNowWithoutLogDate(t *testing.T) {
	rep := &ReportAgent{Issues: &IssueList{}, Resolutions: &ResolutionList{}}
	want := time.Now().Format("02/01/2006")
	if body := rep.EmailBody(); !strings.Contains(body, "# Syslog digest - "+want) {
		t.Errorf("digest title missing fallback date %s:\n%s", want, body)
	}
}

// The resolution's look_for line sits between the investigate command and
// the fix in both layouts, and an empty one writes nothing (older library
// rows and runs from before the field existed have none).
func TestLookForRendersBetweenInvestigateAndFix(t *testing.T) {
	res := testResolution("clock-skew")
	md := res.ToMarkdown()
	inv := strings.Index(md, "systemctl status clock-skew")
	look := strings.Index(md, "**What to look for:** healthy is active (running)")
	fix := strings.Index(md, "**Fix:**")
	if inv < 0 || look < 0 || fix < 0 || !(inv < look && look < fix) {
		t.Errorf("attachment order wrong (investigate=%d lookfor=%d fix=%d):\n%s", inv, look, fix, md)
	}

	res.LookFor = ""
	if strings.Contains(res.ToMarkdown(), "What to look for") {
		t.Error("empty look_for should render nothing in the attachment")
	}
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{testIssue("clock-skew", "high")}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{res}},
	}
	if strings.Contains(rep.EmailBody(), "What to look for") {
		t.Error("empty look_for should render nothing in the digest")
	}
}

// Finding ids and the syslog-mute line (ait srg-Kj5Q8.7): shown on both
// layouts only for captured findings, with one footer line explaining the
// shell function; a run that captured nothing prints none of it.
func TestFindingIdsAndMuteLinesOnBothLayouts(t *testing.T) {
	issue := testIssue("disk-full", "critical")
	issue.ID = 1234
	anom := testAnomaly()
	anom.ID = 77
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{issue}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{testResolution("disk-full")}},
		Anomalies:   []*ExplainedAnomaly{anom},
		RepoURL:     "https://example.test/repo",
	}
	for name, body := range map[string]string{"email": rep.EmailBody(), "full": rep.Run()} {
		for _, want := range []string{
			"**Finding:** #1234",
			`syslog-mute 1234 "why it is expected"`,
			"(#77)",
			`syslog-mute 77 "why it is expected"`,
			"https://example.test/repo/blob/master/README.md#the-sysadmin-api",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s layout missing %q", name, want)
			}
		}
		if n := strings.Count(body, "syslog-mute is a shell function"); n != 1 {
			t.Errorf("%s layout has %d mute footers, want 1", name, n)
		}
	}
	// The email puts the mute line after the resolution, not before it.
	email := rep.EmailBody()
	if strings.Index(email, "systemctl restart disk-full") > strings.Index(email, "syslog-mute 1234") {
		t.Error("email mute line should follow the Try block")
	}
}

func TestNoIdsMeansNoMuteLinesOrFooter(t *testing.T) {
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{testIssue("disk-full", "critical")}},
		Resolutions: &ResolutionList{Resolutions: []*Resolution{testResolution("disk-full")}},
		Anomalies:   []*ExplainedAnomaly{testAnomaly()},
		RepoURL:     "https://example.test/repo",
	}
	for name, body := range map[string]string{"email": rep.EmailBody(), "full": rep.Run()} {
		for _, banned := range []string{"Finding:", "syslog-mute", "(#"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s layout with no ids contains %q", name, banned)
			}
		}
	}
}

func TestMuteFooterNeedsARepoURL(t *testing.T) {
	issue := testIssue("disk-full", "critical")
	issue.ID = 5
	rep := &ReportAgent{Issues: &IssueList{Issues: []*Issue{issue}},
		Resolutions: &ResolutionList{}}
	if body := rep.EmailBody(); strings.Contains(body, "shell function") || !strings.Contains(body, "syslog-mute 5") {
		t.Error("without a RepoURL the mute line stays but the footer link goes")
	}
}
