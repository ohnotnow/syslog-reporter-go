package reporter

import (
	"strings"
	"testing"
)

// digestFixture is a three-run week with one issue recurring on all three
// days, one issue on one day, and one anomaly on two days. The command's
// cap is modelled by handing the report only the first issue and the
// anomaly, as the digest command would.
func digestFixture(t *testing.T) (*Digest, *DigestReport) {
	t.Helper()
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "medium", []string{"web01.example.test"}, "SSH brute force"),
		issueFinding(2, "2026-09-02", "sshd", "high", []string{"web01.example.test"}, "SSH brute force again"),
		issueFinding(3, "2026-09-03", "sshd", "high", []string{"web01.example.test"}, "SSH brute force continues"),
		issueFinding(4, "2026-09-02", "cron", "high", []string{"db01.example.test", "db02.example.test"}, "Backup job failed"),
		issueFinding(7, "2026-09-02", "ntpd", "low", []string{"db01.example.test"}, "Clock drift"),
		anomalyFinding(5, "2026-09-01", "db01.example.test", "postgres", "baseline", "Louder than usual"),
		anomalyFinding(6, "2026-09-03", "db01.example.test", "postgres", "baseline", "Louder than usual"),
	}
	runs := dailyRuns("2026-09-01", "2026-09-02", "2026-09-03")
	d := BuildDigest("2026-09-01", "2026-09-07", runs, findings)

	issue := d.RecurringIssues(10, len(d.RunDays))[0]
	issue.ID = 101 // as capture would set it
	oneOffIssues, oneOffResolutions := d.OneOffIssues(5, len(d.RunDays))
	oneOffIssues[0].ID = 103
	anom := &DigestAnomaly{Group: d.Anomalies[0], RunDays: len(d.RunDays)}
	explained := mergeExplanations([]Anomaly{anom}, []*AnomalyExplanation{{
		Host: "db01.example.test", Program: "postgres",
		LikelyCauses:      "Autovacuum storms every night this week.",
		SuggestedCommands: []string{"psql -c 'select * from pg_stat_progress_vacuum'"},
	}})
	explained[0].ID = 102
	r := &DigestReport{
		Digest:  d,
		Issues:  &IssueList{Issues: []*Issue{issue}},
		OneOffs: &IssueList{Issues: oneOffIssues},
		Resolutions: &ResolutionList{Resolutions: append([]*Resolution{{
			Issue: issue.Issue, RootCause: "Password auth still enabled",
			Investigate: "grep -i passwordauth /etc/ssh/sshd_config",
			FixCommands: []string{"sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"},
		}}, oneOffResolutions...)},
		Anomalies: explained,
		Model:     "openai/gpt-test",
		RepoURL:   "https://example.test/repo",
	}
	return d, r
}

func TestDigestEmailBodyShape(t *testing.T) {
	_, r := digestFixture(t)
	got := r.EmailBody()
	for _, want := range []string{
		"# Syslog weekly digest - Tue 1 Sep to Mon 7 Sep 2026\n",
		"Covers 3 daily runs. No run was recorded for Fri 4 Sep, Sat 5 Sep, Sun 6 Sep, Mon 7 Sep.\n",
		"3 issues this week, 1 seen on more than one day.\n",
		"The 1 most persistent, the 1 worst one-off and the 1 most persistent anomaly are below; the full list is attached.\n",
		commandCaution,
		"## 1. SSH brute force continues\n",
		"**Severity:** high · **Affected:** web01.example.test · **Finding:** #101\n",
		"**Seen on 3 of 3 run days: Tue 1 Sep, Wed 2 Sep, Thu 3 Sep**\n",
		"**Likely cause:** Password auth still enabled\n",
		"syslog-mute 101 ",
		"## Worst one-offs this week (1)\n",
		"### 1. Backup job failed\n",
		"**Severity:** high · **Affected:** db01.example.test, db02.example.test · **Finding:** #103\n",
		"**Seen on 1 of 3 run days: Wed 2 Sep**\n",
		"**Likely cause:** logrotate unit disabled\n", // the daily run's own resolution, no model call
		"syslog-mute 103 ",
		"## Recurring unusual activity (top 1)\n",
		"### db01.example.test / postgres",
		"Seen on 2 of 3 run days: Tue 1 Sep, Thu 3 Sep Latest: Louder than usual on 2026-09-03\n",
		"Autovacuum storms every night this week.\n",
		"syslog-mute 102 ",
		"Every finding this week - 3 issues and 1 anomaly - is in the attached report (**digest_attachment.md**).\n",
		"_syslog-mute is a shell function; see https://example.test/repo/blob/master/README.md#the-sysadmin-api",
		"_Analysis by openai/gpt-test_\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Clock drift") {
		t.Errorf("body shows a low single-day group:\n%s", got)
	}
	if n := strings.Count(got, "Seen on 2 of 3 run days"); n != 1 {
		t.Errorf("anomaly recurrence sentence printed %d times, want once:\n%s", n, got)
	}
	if strings.Contains(got, "\u2014") || strings.Contains(got, "\u2013") {
		t.Errorf("banned dash in body")
	}
}

func TestDigestFullReportListsEveryGroup(t *testing.T) {
	_, r := digestFixture(t)
	got := r.FullReport()
	for _, want := range []string{
		"## All issues this week (3), most days seen first\n",
		"### 1. SSH brute force continues\n",
		"**Finding:** #101",
		"**Likely cause:** Password auth still enabled\n",
		"### 2. Backup job failed\n",
		"**Finding:** #103",
		"**Likely cause:** logrotate unit disabled\n",
		"### 3. Clock drift\n",
		"**Seen on 1 of 3 run days: Wed 2 Sep**\n",
		"👉 Rotate and compress old logs.\n",
		"## All unusual activity this week (1), most days seen first\n",
		"Autovacuum storms every night this week.\n",
		"_Analysis by openai/gpt-test_\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("attachment missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "syslog-mute 0 ") || strings.Contains(got, "**Finding:** #0") {
		t.Errorf("uncaptured group rendered a zero id:\n%s", got)
	}
	if strings.Contains(got, "\u2014") || strings.Contains(got, "\u2013") {
		t.Errorf("banned dash in attachment")
	}
}

func TestDigestLLMSkippedRendersFactsOnly(t *testing.T) {
	d, _ := digestFixture(t)
	issue := d.RecurringIssues(10, len(d.RunDays))[0]
	r := &DigestReport{
		Digest:     d,
		Issues:     &IssueList{Issues: []*Issue{issue}},
		Anomalies:  FactsOnly([]Anomaly{&DigestAnomaly{Group: d.Anomalies[0], RunDays: 3}}),
		LLMSkipped: true,
		Model:      "openai/gpt-test",
	}
	got := r.EmailBody()
	if strings.Contains(got, commandCaution) || strings.Contains(got, "_Analysis by") {
		t.Errorf("--no-llm body carries the caution or the model footer:\n%s", got)
	}
	if !strings.Contains(got, "👉 Rotate and compress old logs.\n") {
		t.Errorf("--no-llm body lacks the recommended action fallback:\n%s", got)
	}
	if strings.Contains(got, "**Finding:**") || strings.Contains(got, "syslog-mute") {
		t.Errorf("uncaptured digest rendered ids or mute lines:\n%s", got)
	}
	if strings.Contains(r.FullReport(), commandCaution) {
		t.Errorf("--no-llm attachment carries the caution")
	}
}

func TestDigestQuietWeek(t *testing.T) {
	d := BuildDigest("2026-09-01", "2026-09-03", dailyRuns("2026-09-01", "2026-09-03"), nil)
	r := &DigestReport{Digest: d, Model: "openai/gpt-test"}
	got := r.EmailBody()
	for _, want := range []string{
		"Covers 2 daily runs. No run was recorded for Wed 2 Sep.\n",
		"Nothing was flagged - quiet week.\n",
		"Every finding this week - 0 issues and 0 anomalies - is in the attached report",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("quiet body missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, commandCaution) {
		t.Errorf("quiet week has no commands to caution about")
	}
	if !strings.Contains(r.FullReport(), "## All issues this week (0), most days seen first\n\nNone.\n") {
		t.Errorf("quiet attachment:\n%s", r.FullReport())
	}
}
