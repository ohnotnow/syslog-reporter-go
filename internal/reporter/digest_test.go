package reporter

import (
	"reflect"
	"testing"
)

// finding builds a daily issue FindingDetail the way DailyFindings decodes
// one: hosts and service on the row, the full record in the payload.
func issueFinding(id int64, date, service, severity string, hosts []string, title string) *FindingDetail {
	issue := sampleIssuePayload()
	issue.Issue.Issue = title
	issue.Issue.Severity = severity
	issue.Issue.AffectedService = service
	issue.Issue.AffectedHost = hosts
	return &FindingDetail{ID: id, LogDate: date, RunKind: RunKindDaily, Kind: "issue",
		Severity: severity, Title: title, Service: service, Hosts: hosts, Issue: &issue}
}

func anomalyFinding(id int64, date, host, program, kind, headline string) *FindingDetail {
	a := sampleAnomaly()
	a.Host, a.Program, a.Kind, a.Headline = host, program, kind, headline
	a.Detail = headline + " on " + date
	return &FindingDetail{ID: id, LogDate: date, RunKind: RunKindDaily, Kind: kind,
		Title: headline, Service: program, Hosts: []string{host}, Anomaly: a}
}

func dailyRuns(dates ...string) []*RunSummary {
	var runs []*RunSummary
	for i, d := range dates {
		runs = append(runs, &RunSummary{ID: int64(i + 1), LogDate: d, Kind: RunKindDaily})
	}
	return runs
}

func TestBuildDigestGroupsIssuesByServiceAndHostSet(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "medium", []string{"web01.example.test", "web02.example.test"}, "SSH noise"),
		issueFinding(2, "2026-09-02", "sshd", "high", []string{"web02.example.test", "web01.example.test"}, "SSH brute force"),
		issueFinding(3, "2026-09-03", "sshd", "low", []string{"web01.example.test", "web02.example.test"}, "SSH still noisy"),
		issueFinding(4, "2026-09-03", "sshd", "critical", []string{"db01.example.test"}, "SSH on the db box"),
		issueFinding(5, "2026-09-02", "cron", "low", []string{"db01.example.test"}, "Cron whinge"),
	}
	d := BuildDigest("2026-09-01", "2026-09-07", dailyRuns("2026-09-01", "2026-09-02", "2026-09-03"), findings)

	if len(d.Issues) != 3 {
		t.Fatalf("issue groups = %d, want 3", len(d.Issues))
	}
	top := d.Issues[0]
	if top.Service != "sshd" || !reflect.DeepEqual(top.Hosts, []string{"web01.example.test", "web02.example.test"}) {
		t.Errorf("top group = %s on %v", top.Service, top.Hosts)
	}
	if !reflect.DeepEqual(top.Days, []string{"2026-09-01", "2026-09-02", "2026-09-03"}) {
		t.Errorf("top days = %v", top.Days)
	}
	if top.Severity != "high" {
		t.Errorf("top severity = %q, want the most severe seen (high)", top.Severity)
	}
	if top.LatestID != 3 || top.Latest.Issue.Issue != "SSH still noisy" {
		t.Errorf("latest = #%d %q, want the newest day's record", top.LatestID, top.Latest.Issue.Issue)
	}
	// One day each: severity breaks the tie, critical before low.
	if d.Issues[1].Service != "sshd" || d.Issues[1].Severity != "critical" {
		t.Errorf("second group = %s/%s, want sshd/critical", d.Issues[1].Service, d.Issues[1].Severity)
	}
	if d.Issues[2].Service != "cron" {
		t.Errorf("third group = %s, want cron", d.Issues[2].Service)
	}
}

func TestBuildDigestGroupsAnomaliesByHostAndProgram(t *testing.T) {
	findings := []*FindingDetail{
		anomalyFinding(1, "2026-09-01", "db01.example.test", "postgres", "baseline", "Louder than usual"),
		anomalyFinding(2, "2026-09-02", "db01.example.test", "postgres", "peer", "Chattier than its peers"),
		anomalyFinding(3, "2026-09-02", "db01.example.test", "postgres", "baseline", "Louder than usual"),
		anomalyFinding(4, "2026-09-04", "app01.example.test", "nginx", "temporal", "Busy at 03:00"),
	}
	d := BuildDigest("2026-09-01", "2026-09-07", dailyRuns("2026-09-01", "2026-09-02", "2026-09-04"), findings)

	if len(d.Anomalies) != 2 {
		t.Fatalf("anomaly groups = %d, want 2", len(d.Anomalies))
	}
	top := d.Anomalies[0]
	if top.Host != "db01.example.test" || top.Program != "postgres" {
		t.Errorf("top = %s/%s", top.Host, top.Program)
	}
	if !reflect.DeepEqual(top.Kinds, []string{"baseline", "peer"}) {
		t.Errorf("kinds = %v, want both detectors, sorted", top.Kinds)
	}
	if !reflect.DeepEqual(top.Days, []string{"2026-09-01", "2026-09-02"}) {
		t.Errorf("days = %v, want the two distinct days", top.Days)
	}
	if top.LatestID != 3 {
		t.Errorf("latest id = %d, want 3 (same day, higher id wins)", top.LatestID)
	}
}

// Identical findings in a different slice order rank identically.
func TestBuildDigestIsOrderIndependent(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "low", []string{"b.example.test"}, "b"),
		issueFinding(2, "2026-09-01", "sshd", "low", []string{"a.example.test"}, "a"),
		issueFinding(3, "2026-09-01", "cron", "low", []string{"c.example.test"}, "c"),
		anomalyFinding(4, "2026-09-01", "z.example.test", "sshd", "peer", "z"),
		anomalyFinding(5, "2026-09-01", "y.example.test", "sshd", "peer", "y"),
	}
	runs := dailyRuns("2026-09-01")
	forward := BuildDigest("2026-09-01", "2026-09-01", runs, findings)
	reversed := make([]*FindingDetail, len(findings))
	for i, f := range findings {
		reversed[len(findings)-1-i] = f
	}
	backward := BuildDigest("2026-09-01", "2026-09-01", runs, reversed)

	var want, got []string
	for _, g := range forward.Issues {
		want = append(want, g.Service+"/"+g.Hosts[0])
	}
	for _, g := range backward.Issues {
		got = append(got, g.Service+"/"+g.Hosts[0])
	}
	if !reflect.DeepEqual(got, want) || want[0] != "cron/c.example.test" || want[1] != "sshd/a.example.test" {
		t.Errorf("issue order forward %v backward %v", want, got)
	}
	if forward.Anomalies[0].Host != "y.example.test" || backward.Anomalies[0].Host != "y.example.test" {
		t.Errorf("anomaly tie-break should be host order: %s / %s",
			forward.Anomalies[0].Host, backward.Anomalies[0].Host)
	}
}

func TestBuildDigestReportsMissingDays(t *testing.T) {
	runs := dailyRuns("2026-09-01", "2026-09-02", "2026-09-04")
	runs = append(runs, &RunSummary{ID: 9, LogDate: "2026-09-03", Kind: RunKindDigest})
	d := BuildDigest("2026-09-01", "2026-09-05", runs, nil)
	if !reflect.DeepEqual(d.RunDays, []string{"2026-09-01", "2026-09-02", "2026-09-04"}) {
		t.Errorf("run days = %v", d.RunDays)
	}
	if !reflect.DeepEqual(d.MissingDays, []string{"2026-09-03", "2026-09-05"}) {
		t.Errorf("missing days = %v, want the digest-only day and the gap", d.MissingDays)
	}
	if len(d.Issues) != 0 || len(d.Anomalies) != 0 {
		t.Errorf("empty window produced groups: %+v", d)
	}
}

func TestRecurrenceSentenceBritishShortForm(t *testing.T) {
	got := RecurrenceSentence([]string{"2026-09-01", "2026-09-02", "2026-09-04"}, 7)
	want := "Seen on 3 of 7 run days: Tue 1 Sep, Wed 2 Sep, Fri 4 Sep"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if DigestDay("not-a-date") != "not-a-date" {
		t.Errorf("unparseable day should pass through")
	}
}

func TestDigestAdaptersCarryTheRecurrence(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(11, "2026-09-01", "sshd", "low", []string{"web01.example.test"}, "SSH noise"),
		issueFinding(12, "2026-09-03", "sshd", "high", []string{"web01.example.test"}, "SSH brute force"),
		anomalyFinding(13, "2026-09-01", "db01.example.test", "postgres", "baseline", "Louder than usual"),
		anomalyFinding(14, "2026-09-02", "db01.example.test", "postgres", "baseline", "Louder than usual"),
	}
	d := BuildDigest("2026-09-01", "2026-09-07", dailyRuns("2026-09-01", "2026-09-02", "2026-09-03"), findings)

	issue := d.Issues[0].DigestIssue(len(d.RunDays))
	if issue.ID != 0 {
		t.Errorf("digest issue id = %d, want 0 until captured", issue.ID)
	}
	if issue.Issue != "SSH brute force" || issue.Severity != "high" {
		t.Errorf("digest issue = %q/%s, want the latest title and the worst severity", issue.Issue, issue.Severity)
	}
	if issue.TimestampFrequency != "Seen on 2 of 3 run days: Tue 1 Sep, Thu 3 Sep" {
		t.Errorf("timing = %q", issue.TimestampFrequency)
	}
	if d.Issues[0].Latest.Issue.ID != 0 && d.Issues[0].Latest.Issue.TimestampFrequency == issue.TimestampFrequency {
		t.Errorf("DigestIssue must copy, not mutate the group's Latest record")
	}

	anom := &DigestAnomaly{Group: d.Anomalies[0], RunDays: len(d.RunDays)}
	if anom.Host() != "db01.example.test" || anom.Program() != "postgres" || anom.Kind() != "baseline" {
		t.Errorf("anomaly identity = %s/%s/%s", anom.Host(), anom.Program(), anom.Kind())
	}
	if anom.Score() != 2 {
		t.Errorf("score = %v, want the day count", anom.Score())
	}
	want := "Seen on 2 of 3 run days: Tue 1 Sep, Wed 2 Sep Latest: Louder than usual on 2026-09-02"
	if anom.Summary() != want {
		t.Errorf("summary = %q\nwant %q", anom.Summary(), want)
	}
}

// Two groups with the same LLM title must not collapse onto one resolution
// or one finding id (every downstream join is by title), so DigestIssues
// disambiguates a colliding title with the group's first host.
func TestDigestIssuesMakeTitlesUnique(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "cron", "high", []string{"web01.example.test"}, "Disk filling on /var"),
		issueFinding(2, "2026-09-02", "cron", "high", []string{"web01.example.test"}, "Disk filling on /var"),
		issueFinding(3, "2026-09-03", "cron", "low", []string{"db01.example.test"}, "Disk filling on /var"),
		issueFinding(4, "2026-09-03", "sshd", "low", []string{"db01.example.test"}, "SSH noise"),
	}
	d := BuildDigest("2026-09-01", "2026-09-03", dailyRuns("2026-09-01", "2026-09-02", "2026-09-03"), findings)
	issues := d.DigestIssues(3)
	got := []string{issues[0].Issue, issues[1].Issue, issues[2].Issue}
	want := []string{"Disk filling on /var (web01.example.test)", "Disk filling on /var (db01.example.test)", "SSH noise"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("titles = %q, want %q", got, want)
	}
}

// The main list is groups seen on two or more days; single-day critical
// and high groups are the one-offs, worst first then widest; single-day
// medium and low groups are attachment-only. With one run day nothing
// could recur, so everything is "recurring" and there are no one-offs.
func TestDigestRecurringAndOneOffs(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "low", []string{"web01.example.test"}, "SSH noise"),
		issueFinding(2, "2026-09-02", "sshd", "low", []string{"web01.example.test"}, "SSH noise again"),
		issueFinding(3, "2026-09-02", "backup", "high", []string{"a.example.test", "b.example.test", "c.example.test"}, "Backup failed on three"),
		issueFinding(4, "2026-09-03", "backup", "critical", []string{"d.example.test"}, "Backup failed on one"),
		issueFinding(5, "2026-09-03", "backup", "high", []string{"e.example.test"}, "Backup failed on another"),
		issueFinding(6, "2026-09-03", "cron", "medium", []string{"f.example.test"}, "Cron whinge"),
	}
	d := BuildDigest("2026-09-01", "2026-09-03", dailyRuns("2026-09-01", "2026-09-02", "2026-09-03"), findings)

	recurring := d.Recurring()
	if len(recurring) != 1 || recurring[0].Service != "sshd" {
		t.Errorf("recurring = %+v, want just the two-day sshd group", recurring)
	}
	var got []string
	for _, g := range d.OneOffs() {
		got = append(got, g.Latest.Issue.Issue)
	}
	want := []string{"Backup failed on one", "Backup failed on three", "Backup failed on another"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("one-offs = %q, want critical first, then high by host count: %q", got, want)
	}
	issues, resolutions := d.OneOffIssues(2, 3)
	if len(issues) != 2 || len(resolutions) != 2 || resolutions[0].Issue != issues[0].Issue {
		t.Errorf("OneOffIssues(2) = %d issues, %d resolutions (paired by title: %v)", len(issues), len(resolutions),
			len(resolutions) > 0 && resolutions[0].Issue == issues[0].Issue)
	}
	if resolutions[0].RootCause != "logrotate unit disabled" {
		t.Errorf("one-off resolution should be the daily run's own, got %q", resolutions[0].RootCause)
	}

	single := BuildDigest("2026-09-03", "2026-09-03", dailyRuns("2026-09-03"), findings[3:])
	if single.MinRecurringDays() != 1 || len(single.Recurring()) != 3 || len(single.OneOffs()) != 0 {
		t.Errorf("single run day: min %d, recurring %d, one-offs %d; want 1/3/0",
			single.MinRecurringDays(), len(single.Recurring()), len(single.OneOffs()))
	}
}
