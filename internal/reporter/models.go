package reporter

// The report's data models (issues, resolutions, explained anomalies) and
// their markdown rendering. The LLM stages in llmagents.go populate them;
// the JSON schemas there mirror these structs.

import (
	"fmt"
	"strings"
)

// SeverityRank orders issues for the short email body. Lower = more urgent.
var SeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// The json tags are the structured-output field names: the LLM response
// decodes straight into these, and the dedupe agent re-serialises them in
// declared field order.
type Issue struct {
	// ID is the findings-library row this issue was captured as, set by
	// CaptureRun before the report renders so the digest can print it and
	// a paste-ready mute line (ait srg-Kj5Q8.7). Zero when nothing was
	// captured (--no-store, or capture failed); never serialised.
	ID                 int64    `json:"-"`
	Issue              string   `json:"issue"`
	Severity           string   `json:"severity"` // critical / high / medium / low
	Description        string   `json:"description"`
	ExampleLogEntry    string   `json:"example_log_entry"`
	AffectedHost       []string `json:"affected_host"`
	OS                 string   `json:"os"` // e.g. "Rocky Linux 9 x3, Ubuntu 22.04 x1"; "" on library rows captured before it existed
	AffectedService    string   `json:"affected_service"`
	TimestampFrequency string   `json:"timestamp_frequency"`
	PotentialImpact    string   `json:"potential_impact"`
	RecommendedAction  string   `json:"recommended_action"`
}

// HostsSummary lists affected hosts, truncated so long lists don't swamp the
// report.
func (i *Issue) HostsSummary() string {
	const limit = 5
	hosts := i.AffectedHost
	if len(hosts) == 0 {
		return "n/a"
	}
	if len(hosts) <= limit {
		return strings.Join(hosts, ", ")
	}
	return strings.Join(hosts[:limit], ", ") +
		fmt.Sprintf(" … and %d more", len(hosts)-limit)
}

func (i *Issue) ToMarkdown() string {
	osLine := ""
	if i.OS != "" {
		osLine = "- **OS:** " + i.OS + "\n"
	}
	return fmt.Sprintf(
		"## %s\n\n"+
			"**Severity:** %s · **Service:** %s · **When:** %s%s\n\n"+
			"%s\n\n"+
			"- **Affected:** %s\n"+
			"%s"+
			"- **Impact:** %s\n"+
			"- **Recommended action:** %s\n\n"+
			"**Example log entry:**\n\n"+
			"```\n%s\n```\n"+
			"%s",
		i.Issue, i.Severity, i.AffectedService, i.TimestampFrequency, findingTag(i.ID),
		i.Description, i.HostsSummary(), osLine, i.PotentialImpact,
		i.RecommendedAction, i.ExampleLogEntry, muteParagraph(i.ID))
}

// findingTag is the " · **Finding:** #1234" suffix for a captured finding,
// empty when there is no id to show.
func findingTag(id int64) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf(" · **Finding:** #%d", id)
}

// muteParagraph is the paste-ready mute line under a captured finding. The
// syslog-mute shell function is documented in the README (owner's ask:
// the email should hand the sysadmin the exact command).
func muteParagraph(id int64) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("\nMute this on the affected hosts: `syslog-mute %d \"why it is expected\"`\n", id)
}

type IssueList struct {
	Issues []*Issue `json:"issues"`
}

func (l *IssueList) ToMarkdown() string {
	parts := make([]string, len(l.Issues))
	for i, issue := range l.Issues {
		parts[i] = issue.ToMarkdown()
	}
	return strings.Join(parts, "\n") + "\n"
}

type Resolution struct {
	Issue       string   `json:"issue"` // echoed back verbatim, so it pairs to its Issue
	RootCause   string   `json:"root_cause"`
	Investigate string   `json:"investigate"`  // one paste-ready diagnostic command
	LookFor     string   `json:"look_for"`     // what the investigate output means: healthy vs the problem
	FixCommands []string `json:"fix_commands"` // ordered, paste-ready shell commands
	Notes       string   `json:"notes"`        // optional one-line caveat
}

func (r *Resolution) ToMarkdown() string {
	fixes := "# (no commands suggested)"
	if len(r.FixCommands) > 0 {
		fixes = strings.Join(r.FixCommands, "\n")
	}
	md := fmt.Sprintf(
		"### %s\n\n"+
			"**Root cause:** %s\n\n"+
			"**Investigate:**\n\n```\n%s\n```\n\n",
		r.Issue, r.RootCause, r.Investigate)
	if r.LookFor != "" {
		md += fmt.Sprintf("**What to look for:** %s\n\n", r.LookFor)
	}
	md += fmt.Sprintf("**Fix:**\n\n```\n%s\n```\n", fixes)
	if r.Notes != "" {
		md += fmt.Sprintf("\n**Note:** %s\n", r.Notes)
	}
	return md
}

type ResolutionList struct {
	Resolutions []*Resolution `json:"resolutions"`
}

func (l *ResolutionList) ToMarkdown() string {
	if len(l.Resolutions) == 0 {
		return "No resolutions generated.\n"
	}
	parts := make([]string, len(l.Resolutions))
	for i, r := range l.Resolutions {
		parts[i] = r.ToMarkdown()
	}
	return strings.Join(parts, "\n") + "\n"
}

// ByIssue maps issue title to Resolution, for pairing with issues in the
// report.
func (l *ResolutionList) ByIssue() map[string]*Resolution {
	m := make(map[string]*Resolution, len(l.Resolutions))
	for _, r := range l.Resolutions {
		m[r.Issue] = r
	}
	return m
}

// Cap how many anomalies get the LLM treatment (and, on --no-llm runs, how
// many render at all). Keeps cost down and the report focused.
const DefaultMaxExplain = 15

// ExplainedAnomaly is the deterministic anomaly facts merged with the LLM
// explanation. Kind/Headline/Detail come from whichever detector flagged it,
// so the report renders all three kinds uniformly. The json tags are the
// findings library's stored payload format (librarystore.go); renaming any
// of them needs a migration story, so don't.
type ExplainedAnomaly struct {
	ID                 int64    `json:"-"` // findings-library row, as Issue.ID
	Host               string   `json:"host"`
	Program            string   `json:"program"`
	Kind               string   `json:"kind"`     // peer / baseline / temporal
	Headline           string   `json:"headline"` // short label, e.g. "Gone silent"
	Detail             string   `json:"detail"`   // the deterministic numbers sentence
	OSFamily           string   `json:"os_family"`
	ExampleLine        string   `json:"example_line"`
	LikelyCauses       string   `json:"likely_causes"`
	InvestigationSteps []string `json:"investigation_steps"`
	SuggestedCommands  []string `json:"suggested_commands"`
}

func (e *ExplainedAnomaly) ToMarkdown() string {
	steps := "- (none given)"
	if len(e.InvestigationSteps) > 0 {
		lines := make([]string, len(e.InvestigationSteps))
		for i, s := range e.InvestigationSteps {
			lines[i] = "- " + s
		}
		steps = strings.Join(lines, "\n")
	}
	cmdBlock := "_none given_"
	if len(e.SuggestedCommands) > 0 {
		cmdBlock = fmt.Sprintf("```\n%s\n```", strings.Join(e.SuggestedCommands, "\n"))
	}
	example := ""
	if e.ExampleLine != "" {
		example = fmt.Sprintf("**Example:** `%s`\n\n", e.ExampleLine)
	}
	return fmt.Sprintf(
		"### %s - %s%s\n"+
			"**%s** (%s)\n\n"+
			"%s\n\n"+
			"%s"+
			"**Likely causes:** %s\n\n"+
			"**Investigate:**\n%s\n\n"+
			"**Suggested commands:**\n%s\n"+
			"%s",
		e.Host, e.Program, headingID(e.ID), e.Headline, e.OSFamily, e.Detail, example,
		e.LikelyCauses, steps, cmdBlock, muteParagraph(e.ID))
}

// headingID is the " (#1234)" suffix on an anomaly heading.
func headingID(id int64) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf(" (#%d)", id)
}

// FactsOnly builds ExplainedAnomaly records without any LLM call (--no-llm
// runs). The deterministic facts still render in the report; the advice
// fields say no explanation was generated.
func FactsOnly(anomalies []Anomaly) []*ExplainedAnomaly {
	return FactsOnlyN(anomalies, DefaultMaxExplain)
}

// FactsOnlyN is FactsOnly with the caller's own cap (the weekly digest
// has already chosen how many groups it wants).
func FactsOnlyN(anomalies []Anomaly, n int) []*ExplainedAnomaly {
	top := anomalies
	if len(top) > n {
		top = top[:n]
	}
	return mergeExplanations(top, nil)
}
