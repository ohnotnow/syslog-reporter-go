package reporter

// Port of tests/test_report.py from the Python original (the SMTP
// EmailAgent tests live in emailer_test.go).

import (
	"fmt"
	"strings"
	"testing"
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
		"disk-full",                   // critical: in body
		"clock-skew",                  // high: in body
		"systemctl status disk-full",  // investigate command shown
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
	knowns.LineIgnored("scopebox", "retry on port 1234")

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
// models can tell reports apart (owner decision 2026-08-28; a deliberate
// divergence from the Python report layout).
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
