package reporter

// The weekly digest's two layouts (ait srg-xiBoC.6): EmailBody is the short
// email (the top groups with the smart model's prose), FullReport the
// attachment (every group, facts first, prose where it was written). Both
// mirror the daily layouts in report.go so the two emails read as one
// tool: same caution line, same finding tags and mute lines, same footers.

import (
	"fmt"
	"strings"
	"time"
)

// DigestAttachmentName is the weekly digest's attachment; the daily email
// uses AttachmentName.
const DigestAttachmentName = "digest_attachment.md"

type DigestReport struct {
	Digest      *Digest
	Issues      *IssueList          // the top recurring groups (RecurringIssues), ids set by capture
	OneOffs     *IssueList          // the worst single-day groups (OneOffIssues), ids set by capture
	Resolutions *ResolutionList     // the writer's output plus the one-offs' daily resolutions
	Anomalies   []*ExplainedAnomaly // the top anomaly groups, explained or FactsOnly, rank order
	// Model is the model that wrote the prose, for the footer; "" or
	// LLMSkipped means no footer.
	Model      string
	LLMSkipped bool
	// RepoURL is where the README lives, for the mute-line footer; empty
	// suppresses it.
	RepoURL string
}

// DigestPeriodLabel renders the window as "Mon 1 Sep to Sun 7 Sep 2026",
// for the title and the email subject.
func DigestPeriodLabel(from, to string) string {
	year := ""
	if t, err := time.Parse("2006-01-02", to); err == nil {
		year = " " + t.Format("2006")
	}
	return DigestDay(from) + " to " + DigestDay(to) + year
}

func (r *DigestReport) title() string {
	return "# Syslog weekly digest - " + DigestPeriodLabel(r.Digest.From, r.Digest.To) + "\n\n"
}

// coverage is the factual line about the window: how many daily runs it
// found and which days had none. A stalled cron shows up here.
func (r *DigestReport) coverage() string {
	d := r.Digest
	var b strings.Builder
	fmt.Fprintf(&b, "Covers %d daily run%s.", len(d.RunDays), plural(len(d.RunDays), "", "s"))
	if len(d.MissingDays) > 0 {
		labels := make([]string, len(d.MissingDays))
		for i, day := range d.MissingDays {
			labels[i] = DigestDay(day)
		}
		fmt.Fprintf(&b, " No run was recorded for %s.", strings.Join(labels, ", "))
	}
	b.WriteString("\n\n")
	return b.String()
}

func (r *DigestReport) modelFooter() string {
	if r.LLMSkipped || r.Model == "" {
		return ""
	}
	return "_Analysis by " + r.Model + "_\n"
}

// EmailBody is the short email: the top issue and anomaly groups (those
// the command handed to the LLM) with their prose.
func (r *DigestReport) EmailBody() string {
	d := r.Digest
	issues := issuesOf(r.Issues)
	oneOffs := issuesOf(r.OneOffs)
	var resolutions map[string]*Resolution
	if r.Resolutions != nil {
		resolutions = r.Resolutions.ByIssue()
	}
	anomalies := r.Anomalies
	shownGroups := len(issues) + len(oneOffs) + len(anomalies)
	allGroups := len(d.Issues) + len(d.Anomalies)

	var b strings.Builder
	b.WriteString(r.title())
	b.WriteString(r.coverage())
	b.WriteString(r.tally())
	if allGroups > shownGroups {
		fmt.Fprintf(&b, "The %d most persistent", len(issues))
		if len(oneOffs) > 0 {
			fmt.Fprintf(&b, ", the %d worst one-off%s", len(oneOffs), plural(len(oneOffs), "", "s"))
		}
		if len(anomalies) > 0 {
			fmt.Fprintf(&b, " and the %d most persistent anomal%s", len(anomalies), plural(len(anomalies), "y", "ies"))
		}
		b.WriteString(" are below; the full list is attached.\n\n")
	}
	if !r.LLMSkipped && shownGroups > 0 {
		b.WriteString(commandCaution + "\n")
	}
	if allGroups == 0 {
		b.WriteString("Nothing was flagged - quiet week.\n")
	}

	for n, i := range issues {
		writeDigestIssue(&b, n+1, i, resolutions, "## ")
	}

	if len(oneOffs) > 0 {
		fmt.Fprintf(&b, "## Worst one-offs this week (%d)\n\n", len(oneOffs))
		b.WriteString("Seen on one day only, but critical or high: worth knowing about even though it did not recur. The advice is the daily report's.\n\n")
		for n, i := range oneOffs {
			writeDigestIssue(&b, n+1, i, resolutions, "### ")
		}
	}

	if len(anomalies) > 0 {
		fmt.Fprintf(&b, "## Recurring unusual activity (top %d)\n\n", len(anomalies))
		b.WriteString("Hosts that kept behaving unlike their peers or their own recent normal.\n\n")
		for _, a := range anomalies {
			writeAnomalyBrief(&b, a)
		}
	}

	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "Every finding this week - %d issue%s and %d anomal%s - is in the attached report (**%s**).\n",
		len(d.Issues), plural(len(d.Issues), "", "s"),
		len(d.Anomalies), plural(len(d.Anomalies), "y", "ies"),
		DigestAttachmentName)
	shown := &IssueList{Issues: append(append([]*Issue{}, issues...), oneOffs...)}
	if footer := muteFooterFor(r.RepoURL, shown, anomalies); footer != "" {
		b.WriteString("\n" + footer)
	}
	if footer := r.modelFooter(); footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

// tally is the honest count line: how many groups the week produced and
// how many of them actually recurred.
func (r *DigestReport) tally() string {
	d := r.Digest
	if len(d.Issues) == 0 {
		return ""
	}
	recurring := len(d.Recurring())
	if d.MinRecurringDays() < 2 {
		return fmt.Sprintf("%d issue%s this week; with a single run day nothing could recur.\n\n",
			len(d.Issues), plural(len(d.Issues), "", "s"))
	}
	return fmt.Sprintf("%d issue%s this week, %d seen on more than one day.\n\n",
		len(d.Issues), plural(len(d.Issues), "", "s"), recurring)
}

// writeDigestIssue is one issue entry in either digest layout: heading,
// facts line, the recurrence sentence, description, example, then the
// paired resolution or the recommended-action fallback, and the mute line.
func writeDigestIssue(b *strings.Builder, n int, i *Issue, resolutions map[string]*Resolution, heading string) {
	fmt.Fprintf(b, "%s%d. %s\n\n", heading, n, i.Issue)
	fmt.Fprintf(b, "**Severity:** %s · **Affected:** %s", i.Severity, i.HostsSummary())
	if i.OS != "" {
		fmt.Fprintf(b, " · **OS:** %s", i.OS)
	}
	b.WriteString(findingTag(i.ID) + "\n\n")
	b.WriteString("**" + i.TimestampFrequency + "**\n\n")
	b.WriteString(i.Description + "\n\n")
	if i.ExampleLogEntry != "" {
		b.WriteString("**Example:**\n\n```\n" + i.ExampleLogEntry + "\n```\n\n")
	}
	if res, ok := resolutions[i.Issue]; ok {
		writeResolutionBrief(b, res)
	} else {
		b.WriteString("👉 " + i.RecommendedAction + "\n")
	}
	b.WriteString(muteParagraph(i.ID) + "\n")
}

// FullReport is the attachment: every group in rank order, facts for all
// of them and the prose for the ones that got it.
func (r *DigestReport) FullReport() string {
	d := r.Digest
	runDays := len(d.RunDays)
	// Titles are unique across the digest (digestIssues), so the captured
	// ids pair by title from both lists.
	captured := map[string]int64{}
	for _, i := range append(issuesOf(r.Issues), issuesOf(r.OneOffs)...) {
		captured[i.Issue] = i.ID
	}
	var resolutions map[string]*Resolution
	if r.Resolutions != nil {
		resolutions = r.Resolutions.ByIssue()
	}
	explained := map[[2]string]*ExplainedAnomaly{}
	for _, a := range r.Anomalies {
		explained[[2]string{a.Host, a.Program}] = a
	}

	var b strings.Builder
	b.WriteString(r.title())
	b.WriteString(r.coverage())
	b.WriteString(r.tally())
	if !r.LLMSkipped && (len(r.Resolutions.resolutionsOrNil()) > 0 || len(r.Anomalies) > 0) {
		b.WriteString(commandCaution + "\n")
	}

	fmt.Fprintf(&b, "## All issues this week (%d), most days seen first\n\n", len(d.Issues))
	if len(d.Issues) == 0 {
		b.WriteString("None.\n\n")
	}
	for n, issue := range d.DigestIssues(runDays) {
		issue.ID = captured[issue.Issue]
		writeDigestIssue(&b, n+1, issue, resolutions, "### ")
	}

	fmt.Fprintf(&b, "## All unusual activity this week (%d), most days seen first\n\n", len(d.Anomalies))
	if len(d.Anomalies) == 0 {
		b.WriteString("None.\n\n")
	}
	for _, g := range d.Anomalies {
		a, ok := explained[[2]string{g.Host, g.Program}]
		if !ok {
			// Beyond the explained cap: the latest day's facts only, with
			// no id (nothing was captured for it) and no prose.
			latest := *g.Latest
			latest.ID = 0
			latest.Detail = g.digestDetail(runDays)
			latest.LikelyCauses = "_Not explained - beyond the digest's cap; see the daily reports._"
			latest.InvestigationSteps = nil
			latest.SuggestedCommands = nil
			a = &latest
		}
		writeAnomalyBrief(&b, a)
	}

	shown := &IssueList{Issues: append(append([]*Issue{}, issuesOf(r.Issues)...), issuesOf(r.OneOffs)...)}
	if footer := muteFooterFor(r.RepoURL, shown, r.Anomalies); footer != "" {
		b.WriteString("---\n\n" + footer)
	}
	if footer := r.modelFooter(); footer != "" {
		b.WriteString("\n" + footer)
	}
	return b.String()
}

func (l *ResolutionList) resolutionsOrNil() []*Resolution {
	if l == nil {
		return nil
	}
	return l.Resolutions
}
