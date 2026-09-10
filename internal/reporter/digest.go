package reporter

// The weekly digest's deterministic heart (ait srg-xiBoC.4, ant ADR
// srg-WtzbG): group a window's daily findings across days and rank the
// groups by how many days they recurred. No database, no LLM. The keys are
// the stable fields only - service plus the sorted host set for issues,
// host plus program for anomalies - never the title, which is LLM prose
// that drifts from day to day. Ordering is explicit everywhere so the
// digest never depends on map iteration order.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// IssueGroup is one recurring issue: the same service on the same host set
// on one or more days of the window.
type IssueGroup struct {
	Service  string
	Hosts    []string      // sorted; with Service, the group key
	Days     []string      // ISO dates seen, ascending, distinct
	Severity string        // the most severe seen across Days
	Latest   *IssuePayload // the most recent day's record
	LatestID int64         // that finding's library id

	latestDate string // log_date of Latest, for the newest-wins pick
}

// AnomalyGroup is one recurring anomaly: a host and program flagged on one
// or more days, whichever detector(s) flagged it.
type AnomalyGroup struct {
	Host, Program string   // the group key
	Kinds         []string // distinct detector kinds seen, sorted
	Days          []string // ISO dates seen, ascending, distinct
	Latest        *ExplainedAnomaly
	LatestID      int64

	latestDate string
}

// Digest is a window of daily runs rolled up: which days ran, which did
// not, and the recurring issues and anomalies ranked.
type Digest struct {
	From, To    string   // ISO, inclusive
	RunDays     []string // window dates with a daily run, ascending
	MissingDays []string // window dates with no daily run, ascending
	Issues      []*IssueGroup
	Anomalies   []*AnomalyGroup
}

// BuildDigest groups findings (DailyFindings output) by the keys above and
// ranks the groups. runs is ListRuns output for the window; only daily
// runs count as run days. from and to are ISO dates, inclusive.
func BuildDigest(from, to string, runs []*RunSummary, findings []*FindingDetail) *Digest {
	d := &Digest{From: from, To: to}
	ran := map[string]bool{}
	for _, r := range runs {
		if r.Kind == RunKindDaily {
			ran[r.LogDate] = true
		}
	}
	for _, day := range windowDays(from, to) {
		if ran[day] {
			d.RunDays = append(d.RunDays, day)
		} else {
			d.MissingDays = append(d.MissingDays, day)
		}
	}

	issues := map[string]*IssueGroup{}
	anomalies := map[string]*AnomalyGroup{}
	for _, f := range findings {
		switch {
		case f.Kind == "issue" && f.Issue != nil:
			hosts := append([]string{}, f.Issue.AffectedHost...)
			sort.Strings(hosts)
			key := f.Service + "\x00" + strings.Join(hosts, "\x00")
			g, ok := issues[key]
			if !ok {
				g = &IssueGroup{Service: f.Service, Hosts: hosts, Severity: f.Severity}
				issues[key] = g
			}
			g.Days = appendDay(g.Days, f.LogDate)
			if severityRankOf(f.Severity) < severityRankOf(g.Severity) {
				g.Severity = f.Severity
			}
			if g.Latest == nil || f.LogDate > g.latestDate || (f.LogDate == g.latestDate && f.ID > g.LatestID) {
				g.Latest, g.LatestID = f.Issue, f.ID
				g.latestDate = f.LogDate
			}
		case f.Anomaly != nil:
			key := f.Anomaly.Host + "\x00" + f.Anomaly.Program
			g, ok := anomalies[key]
			if !ok {
				g = &AnomalyGroup{Host: f.Anomaly.Host, Program: f.Anomaly.Program}
				anomalies[key] = g
			}
			g.Days = appendDay(g.Days, f.LogDate)
			g.Kinds = appendDistinct(g.Kinds, f.Kind)
			if g.Latest == nil || f.LogDate > g.latestDate || (f.LogDate == g.latestDate && f.ID > g.LatestID) {
				g.Latest, g.LatestID = f.Anomaly, f.ID
				g.latestDate = f.LogDate
			}
		}
	}

	for _, g := range issues {
		sort.Strings(g.Days)
		d.Issues = append(d.Issues, g)
	}
	sort.Slice(d.Issues, func(i, j int) bool {
		a, b := d.Issues[i], d.Issues[j]
		if len(a.Days) != len(b.Days) {
			return len(a.Days) > len(b.Days)
		}
		if ra, rb := severityRankOf(a.Severity), severityRankOf(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return strings.Join(a.Hosts, ",") < strings.Join(b.Hosts, ",")
	})
	for _, g := range anomalies {
		sort.Strings(g.Days)
		sort.Strings(g.Kinds)
		d.Anomalies = append(d.Anomalies, g)
	}
	sort.Slice(d.Anomalies, func(i, j int) bool {
		a, b := d.Anomalies[i], d.Anomalies[j]
		if len(a.Days) != len(b.Days) {
			return len(a.Days) > len(b.Days)
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Program < b.Program
	})
	return d
}

// windowDays lists every ISO date from from to to inclusive; an unparseable
// or inverted range yields nothing, so the digest simply reports no run
// days rather than looping.
func windowDays(from, to string) []string {
	start, err1 := time.Parse("2006-01-02", from)
	end, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil || end.Before(start) {
		return nil
	}
	var days []string
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		days = append(days, day.Format("2006-01-02"))
	}
	return days
}

func appendDay(days []string, day string) []string {
	return appendDistinct(days, day)
}

func appendDistinct(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// DigestIssue is the group as an Issue for the resolution writer and
// capture: the latest day's record with the recurrence sentence in place
// of the single day's timing, and ID zeroed so capture assigns the digest
// finding's own id. runDays is the window's daily run count.
func (g *IssueGroup) DigestIssue(runDays int) *Issue {
	issue := g.Latest.Issue
	issue.ID = 0
	issue.Severity = g.Severity
	issue.TimestampFrequency = RecurrenceSentence(g.Days, runDays)
	return &issue
}

// MinRecurringDays is how many distinct days a group needs to count as
// recurring: two, or one when the window only has one run day (then
// nothing could recur and everything is shown).
func (d *Digest) MinRecurringDays() int {
	return min(2, len(d.RunDays))
}

// Recurring is the issue groups seen on MinRecurringDays or more, in rank
// order: the digest's main list.
func (d *Digest) Recurring() []*IssueGroup {
	var out []*IssueGroup
	for _, g := range d.Issues {
		if len(g.Days) >= d.MinRecurringDays() {
			out = append(out, g)
		}
	}
	return out
}

// OneOffs is the critical and high issue groups seen on a single day,
// most severe first and then by how many hosts were hit (owner, 2026-09-10:
// a once-weekly backup failing on ten hosts is not less important for
// happening once). Empty when MinRecurringDays is 1, since then every
// group is in Recurring.
func (d *Digest) OneOffs() []*IssueGroup {
	if d.MinRecurringDays() < 2 {
		return nil
	}
	var out []*IssueGroup
	for _, g := range d.Issues {
		if len(g.Days) == 1 && severityRankOf(g.Severity) <= SeverityRank["high"] {
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := severityRankOf(a.Severity), severityRankOf(b.Severity); ra != rb {
			return ra < rb
		}
		if len(a.Hosts) != len(b.Hosts) {
			return len(a.Hosts) > len(b.Hosts)
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return strings.Join(a.Hosts, ",") < strings.Join(b.Hosts, ",")
	})
	return out
}

// DigestIssues is every issue group as an Issue, in rank order, with titles
// made unique: every downstream pairing (ResolutionList.ByIssue, capture,
// the layouts) joins on the title, and two groups can share one LLM title
// (the same fault on two host sets). The daily deduplicator merges those;
// the digest keeps them apart, so a colliding title gets its first host.
func (d *Digest) DigestIssues(runDays int) []*Issue {
	return d.digestIssues(d.Issues, runDays)
}

// digestIssues renders the given groups, with titles made unique across
// ALL of d.Issues (not just the subset), so the recurring list, the
// one-offs and the attachment agree on every title.
func (d *Digest) digestIssues(groups []*IssueGroup, runDays int) []*Issue {
	seen := map[string]int{}
	for _, g := range d.Issues {
		seen[g.Latest.Issue.Issue]++
	}
	out := make([]*Issue, 0, len(groups))
	for _, g := range groups {
		issue := g.DigestIssue(runDays)
		if seen[issue.Issue] > 1 && len(g.Hosts) > 0 {
			issue.Issue += " (" + g.Hosts[0] + ")"
		}
		out = append(out, issue)
	}
	return out
}

// RecurringIssues and OneOffIssues are Recurring / OneOffs as Issues, at
// most n each, titles unique. OneOffIssues also returns each one-off's
// daily resolution (the one the daily run wrote, re-titled to match, so
// ByIssue pairs it) - the digest never asks the model about one-offs.
func (d *Digest) RecurringIssues(n, runDays int) []*Issue {
	groups := d.Recurring()
	return d.digestIssues(groups[:min(n, len(groups))], runDays)
}

func (d *Digest) OneOffIssues(n, runDays int) ([]*Issue, []*Resolution) {
	groups := d.OneOffs()
	groups = groups[:min(n, len(groups))]
	issues := d.digestIssues(groups, runDays)
	var resolutions []*Resolution
	for i, g := range groups {
		if g.Latest.Resolution == nil {
			continue
		}
		res := *g.Latest.Resolution
		res.Issue = issues[i].Issue
		resolutions = append(resolutions, &res)
	}
	return issues, resolutions
}

// DigestAnomaly presents an AnomalyGroup as an Anomaly for the explainer,
// so the smart model hears the week's pattern rather than one day's
// numbers. Score is the day count (the only recurrence measure the library
// keeps; per-day scores are not persisted).
type DigestAnomaly struct {
	Group   *AnomalyGroup
	RunDays int
}

var _ Anomaly = (*DigestAnomaly)(nil)

func (a *DigestAnomaly) Host() string        { return a.Group.Host }
func (a *DigestAnomaly) Program() string     { return a.Group.Program }
func (a *DigestAnomaly) Kind() string        { return a.Group.Latest.Kind }
func (a *DigestAnomaly) Score() float64      { return float64(len(a.Group.Days)) }
func (a *DigestAnomaly) Headline() string    { return a.Group.Latest.Headline }
func (a *DigestAnomaly) ExampleLine() string { return a.Group.Latest.ExampleLine }
func (a *DigestAnomaly) OSFamily() string    { return a.Group.Latest.OSFamily }
func (a *DigestAnomaly) SetOSFamily(string)  {}

// Summary is the recurrence sentence followed by the latest day's detail:
// what the explainer's payload quotes as "detail=", and what becomes the
// explained anomaly's Detail, so the layouts print it once.
func (a *DigestAnomaly) Summary() string {
	return a.Group.digestDetail(a.RunDays)
}

func (g *AnomalyGroup) digestDetail(runDays int) string {
	return RecurrenceSentence(g.Days, runDays) + " Latest: " + g.Latest.Detail
}

// RecurrenceSentence renders "Seen on 5 of 7 run days: Mon 1 Sep, Tue 2
// Sep, ..." in the British short form the digest uses everywhere.
func RecurrenceSentence(days []string, runDays int) string {
	labels := make([]string, len(days))
	for i, day := range days {
		labels[i] = DigestDay(day)
	}
	return fmt.Sprintf("Seen on %d of %d run days: %s", len(days), runDays, strings.Join(labels, ", "))
}

// DigestDay renders an ISO date as "Mon 1 Sep"; an unparseable date is
// returned as given rather than lost.
func DigestDay(iso string) string {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return iso
	}
	return t.Format("Mon 2 Jan")
}
