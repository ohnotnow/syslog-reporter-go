package reporter

// Port of agents/report_agent.py plus the two Jinja layouts it renders
// (prompts/report.j2 and prompts/email_body.j2). The Python templates are
// rendered with trim_blocks and lstrip_blocks; the string building below
// reproduces that output byte for byte, with two deliberate exceptions
// (both owner's choice, 2026-08-28): the Python literals' em dashes are
// plain hyphens here (the parity diff normalises dashes before comparing),
// and a model-attribution footer is appended when the LLM stages ran.
//
// Rendered as Go code rather than text/template: the layouts are fixed by
// the compatibility contract, and exact whitespace is far easier to audit
// in string literals than through a second templating dialect.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// AttachmentName is the name of the full-report attachment referenced from
// the email body.
const AttachmentName = "email_attachment.md"

// llmSkippedNote is shown in place of issues/resolutions on a --no-llm run,
// so the report never reads as "all clear" when the analysis simply didn't
// happen.
const llmSkippedNote = "_Skipped - this was a --no-llm run, so no issue analysis was performed._\n"

type ReportAgent struct {
	Issues      *IssueList
	Resolutions *ResolutionList
	Anomalies   []*ExplainedAnomaly
	LLMSkipped  bool
	// Model is the litellm-style model string that did the analysis, shown
	// as a footer so teams comparing models can tell reports apart (owner
	// decision 2026-08-28, ant ADR: a deliberate divergence from the Python
	// report, like the dash change). Empty or --no-llm means no footer.
	Model string
	// Optional KnownKnowns: suppression must stay visible in the report, or
	// a muted entry can quietly become a real fault nobody looks at.
	Knowns *KnownKnowns
}

// modelFooter is the attribution line appended to both layouts, or "" when
// no model did any analysis.
func (r *ReportAgent) modelFooter() string {
	if r.LLMSkipped || r.Model == "" {
		return ""
	}
	return "_Analysis by " + r.Model + "_\n"
}

func todaysDate() string {
	return time.Now().Format("02/01/2006")
}

// Run renders the full report: every issue, the resolutions, and every
// anomaly. This is the email attachment (and what a debug eye reads first).
func (r *ReportAgent) Run() string {
	issues := llmSkippedNote
	resolutions := llmSkippedNote
	if !r.LLMSkipped {
		issues = r.Issues.ToMarkdown()
		resolutions = r.Resolutions.ToMarkdown()
	}

	var b strings.Builder
	b.WriteString("# Syslog Report for " + todaysDate() + "\n\n")
	b.WriteString("## Issues\n")
	b.WriteString(issues + "\n")
	b.WriteString("\n## Resolutions\n")
	b.WriteString(resolutions + "\n")
	b.WriteString("\n## Unusual Activity\n")
	b.WriteString(r.anomaliesMarkdown() + "\n")

	suppressed := r.suppressed()
	expired := r.expiredCount()
	if len(suppressed) > 0 || expired > 0 {
		b.WriteString("\n## Known Knowns\n\n")
		if len(suppressed) > 0 {
			b.WriteString("Suppressed today: " + strings.Join(suppressed, "; ") + ".\n\n")
		}
		if expired > 0 {
			b.WriteString(expiredSentence(expired) + "\n\n")
		}
	}
	if footer := r.modelFooter(); footer != "" {
		b.WriteString("\n---\n\n" + footer)
	}
	return b.String()
}

// EmailBody renders the short, scannable digest: the most urgent issues and
// anomalies, each with paste-ready commands.
func (r *ReportAgent) EmailBody() string {
	return r.emailBodyN(10, 3)
}

func (r *ReportAgent) emailBodyN(topIssues, topAnomalies int) string {
	issues := r.topIssues(topIssues)
	resolutions := r.Resolutions.ByIssue()
	anomalies := r.Anomalies
	if len(anomalies) > topAnomalies {
		anomalies = anomalies[:topAnomalies]
	}
	totalIssues := len(r.Issues.Issues)
	totalAnomalies := len(r.Anomalies)

	var b strings.Builder
	b.WriteString("# Syslog digest - " + todaysDate() + "\n\n")
	b.WriteString("Morning! Here's a quick look at what stood out")
	if totalIssues > len(issues) {
		fmt.Fprintf(&b, " - the %d most pressing of %d issues", len(issues), totalIssues)
	}
	b.WriteString(". Each comes with commands to dig straight in; the full breakdown is attached.\n\n")

	if len(issues) == 0 {
		if r.LLMSkipped {
			b.WriteString("_Issue analysis was skipped (--no-llm run) - only the deterministic anomaly checks ran._\n\n")
		} else {
			b.WriteString("Nothing flagged - quiet day. 🎉\n")
		}
	}
	for n, i := range issues {
		fmt.Fprintf(&b, "## %d. %s\n\n", n+1, i.Issue)
		fmt.Fprintf(&b, "**Severity:** %s · **Affected:** %s\n\n", i.Severity, i.HostsSummary())
		b.WriteString(i.Description + "\n\n")
		if res, ok := resolutions[i.Issue]; ok {
			b.WriteString("**Likely cause:** " + res.RootCause + "\n\n")
			b.WriteString("**Have a look:**\n\n")
			b.WriteString("```\n" + res.Investigate + "\n```\n\n")
			b.WriteString("**Try:**\n\n```\n")
			for _, c := range res.FixCommands {
				b.WriteString(c + "\n")
			}
			b.WriteString("```\n")
			if res.Notes != "" {
				b.WriteString("\n_Note: " + res.Notes + "_\n")
			}
		} else {
			b.WriteString("👉 " + i.RecommendedAction + "\n")
		}
		b.WriteString("\n")
	}

	if len(anomalies) > 0 {
		fmt.Fprintf(&b, "## Unusual activity (top %d)\n\n", len(anomalies))
		b.WriteString("Hosts behaving unlike their peers or their own recent normal - worth a glance.\n\n")
		for _, a := range anomalies {
			fmt.Fprintf(&b, "### %s / %s\n\n", a.Host, a.Program)
			fmt.Fprintf(&b, "_%s_ (%s)\n\n", a.Headline, a.OSFamily)
			b.WriteString(a.Detail + "\n\n")
			b.WriteString(a.LikelyCauses + "\n\n")
			if len(a.SuggestedCommands) > 0 {
				b.WriteString("```\n")
				for _, c := range a.SuggestedCommands {
					b.WriteString(c + "\n")
				}
				b.WriteString("```\n")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "Full findings - all %d issue%s, their resolutions, and %d anomal%s - are in the attached report (**%s**).\n",
		totalIssues, plural(totalIssues, "", "s"),
		totalAnomalies, plural(totalAnomalies, "y", "ies"),
		AttachmentName)

	suppressed := r.suppressed()
	if len(suppressed) > 0 {
		b.WriteString("\n_Known knowns suppressed: " + strings.Join(suppressed, "; ") + "._\n")
	}
	if expired := r.expiredCount(); expired > 0 {
		b.WriteString("\n_" + expiredSentence(expired) + "_\n")
	}
	if footer := r.modelFooter(); footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func expiredSentence(n int) string {
	if n == 1 {
		return fmt.Sprintf("%d known-known entry has expired; noise it covered may have reappeared above.", n)
	}
	return fmt.Sprintf("%d known-known entries have expired; noise they covered may have reappeared above.", n)
}

// suppressed returns one "reason (host) ×hits" string per known-known entry
// that fired today.
func (r *ReportAgent) suppressed() []string {
	if r.Knowns == nil {
		return nil
	}
	var out []string
	for _, e := range r.Knowns.HitEntries() {
		out = append(out, fmt.Sprintf("%s (%s) ×%d", e.Reason, e.Host, e.Hits))
	}
	return out
}

func (r *ReportAgent) expiredCount() int {
	if r.Knowns == nil {
		return 0
	}
	return len(r.Knowns.Expired)
}

// topIssues returns the n most urgent issues, most-severe first (stable
// within a severity).
func (r *ReportAgent) topIssues(n int) []*Issue {
	sorted := append([]*Issue{}, r.Issues.Issues...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRankOf(sorted[i].Severity) < severityRankOf(sorted[j].Severity)
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

func severityRankOf(severity string) int {
	if rank, ok := SeverityRank[severity]; ok {
		return rank
	}
	return 99
}

func (r *ReportAgent) anomaliesMarkdown() string {
	if len(r.Anomalies) == 0 {
		return "No unusual activity detected.\n"
	}
	parts := make([]string, len(r.Anomalies))
	for i, a := range r.Anomalies {
		parts[i] = a.ToMarkdown()
	}
	return strings.Join(parts, "\n") + "\n"
}
