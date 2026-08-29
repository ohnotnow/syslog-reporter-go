package reporter

// The management report (ait srg-YHETx): a periodic HTML email of headline
// numbers and a volume trend for senior IT management, distinct from the
// daily sysadmin digest. It is a PURE READER of tables that survive the
// aggregate store's prune - runs, findings, feedback (ant ADR srg-9X77J).
// The one exception: days inside the period that predate the runs stats
// columns borrow an approximate volume from the aggregates table while it
// still holds them, so the trend chart is not empty on day one.
//
// The HTML is email-safe by design: tables for layout, every style inline,
// no SVG, no JavaScript, no webfonts - Outlook's Word renderer and Gmail
// both eat anything cleverer. Charts are nested-table horizontal bars.

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"
)

//go:embed templates/mgmt_report.html
var mgmtTemplateSrc string

// MgmtDay is one day of the period. RawLines/FilteredLines are -1 when not
// recorded (no run that day, or a pre-stats-column run with nothing to
// borrow from the aggregates).
type MgmtDay struct {
	Date          string // ISO YYYY-MM-DD
	RawLines      int64
	FilteredLines int64
	Approx        bool // volume borrowed from the aggregates table
	Findings      int
}

// ServiceCount is one row of the "most flagged services" table.
type ServiceCount struct {
	Service string
	Count   int
}

// MgmtStats is everything the management report shows, gathered in one
// pass so rendering and tests share a single source of numbers.
type MgmtStats struct {
	From, To       string // ISO, inclusive
	Days           []MgmtDay
	DaysWithData   int
	ApproxDays     int
	TotalRaw       int64
	TotalFiltered  int64
	HaveFiltered   bool // false when every day in range lacked filtered counts
	TotalFindings  int
	SeverityCounts map[string]int // issue findings only, keyed critical/high/medium/low
	AnomalyCount   int            // peer/baseline/temporal findings
	TopServices    []ServiceCount
	FeedbackWorked int
	FeedbackDidnt  int
}

// GatherMgmtStats collects the period's numbers from the findings library,
// borrowing per-day volume from the aggregate store for days whose run row
// has no raw_lines. from/to are inclusive log dates.
func GatherMgmtStats(lib *LibraryStore, agg *AggregateStore, from, to time.Time) (*MgmtStats, error) {
	fromISO, toISO := isoDate(from), isoDate(to)
	stats := &MgmtStats{
		From:           fromISO,
		To:             toISO,
		SeverityCounts: map[string]int{},
	}

	type runRow struct {
		raw, filtered int64
		haveRaw       bool
		haveFiltered  bool
	}
	runs := map[string]runRow{}
	rows, err := lib.db.Query(
		"SELECT log_date, raw_lines, filtered_lines FROM runs WHERE log_date BETWEEN ? AND ?",
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var date string
		var raw, filtered *int64
		if err := rows.Scan(&date, &raw, &filtered); err != nil {
			rows.Close()
			return nil, err
		}
		r := runRow{}
		if raw != nil {
			r.raw, r.haveRaw = *raw, true
		}
		if filtered != nil {
			r.filtered, r.haveFiltered = *filtered, true
		}
		runs[date] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Approximate volume for days without recorded stats: total parsed
	// lines from the aggregates baseline, while the prune window still
	// covers them. Slightly under the true raw count (unparseable lines
	// never reach the aggregates), which is fine for a trend line.
	aggTotals := map[string]int64{}
	rows, err = agg.db.Query(
		"SELECT date, SUM(count) FROM aggregates WHERE date BETWEEN ? AND ? GROUP BY date",
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var date string
		var total int64
		if err := rows.Scan(&date, &total); err != nil {
			rows.Close()
			return nil, err
		}
		aggTotals[date] = total
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	findingsByDate := map[string]int{}
	rows, err = lib.db.Query(
		`SELECT r.log_date, COUNT(*) FROM findings f
		 JOIN runs r ON r.id = f.run_id
		 WHERE r.log_date BETWEEN ? AND ? GROUP BY r.log_date`,
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var date string
		var n int
		if err := rows.Scan(&date, &n); err != nil {
			rows.Close()
			return nil, err
		}
		findingsByDate[date] = n
		stats.TotalFindings += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		iso := isoDate(d)
		day := MgmtDay{Date: iso, RawLines: -1, FilteredLines: -1,
			Findings: findingsByDate[iso]}
		if r, ok := runs[iso]; ok && r.haveRaw {
			day.RawLines = r.raw
			if r.haveFiltered {
				day.FilteredLines = r.filtered
			}
		} else if total, ok := aggTotals[iso]; ok {
			day.RawLines = total
			day.Approx = true
			stats.ApproxDays++
		}
		if day.RawLines >= 0 {
			stats.DaysWithData++
			stats.TotalRaw += day.RawLines
		}
		if day.FilteredLines >= 0 {
			stats.TotalFiltered += day.FilteredLines
			stats.HaveFiltered = true
		}
		stats.Days = append(stats.Days, day)
	}

	rows, err = lib.db.Query(
		`SELECT f.kind, f.severity, COUNT(*) FROM findings f
		 JOIN runs r ON r.id = f.run_id
		 WHERE r.log_date BETWEEN ? AND ? GROUP BY f.kind, f.severity`,
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kind, severity string
		var n int
		if err := rows.Scan(&kind, &severity, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if kind == "issue" {
			stats.SeverityCounts[strings.ToLower(severity)] += n
		} else {
			stats.AnomalyCount += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = lib.db.Query(
		`SELECT f.service, COUNT(*) AS n FROM findings f
		 JOIN runs r ON r.id = f.run_id
		 WHERE r.log_date BETWEEN ? AND ? AND f.service <> ''
		 GROUP BY f.service ORDER BY n DESC, f.service LIMIT 5`,
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sc ServiceCount
		if err := rows.Scan(&sc.Service, &sc.Count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TopServices = append(stats.TopServices, sc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = lib.db.Query(
		`SELECT fb.verdict, COUNT(*) FROM feedback fb
		 JOIN findings f ON f.id = fb.finding_id
		 JOIN runs r ON r.id = f.run_id
		 WHERE r.log_date BETWEEN ? AND ? GROUP BY fb.verdict`,
		fromISO, toISO)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var verdict string
		var n int
		if err := rows.Scan(&verdict, &n); err != nil {
			rows.Close()
			return nil, err
		}
		switch verdict {
		case "worked":
			stats.FeedbackWorked = n
		case "didnt_work":
			stats.FeedbackDidnt = n
		}
	}
	rows.Close()
	return stats, rows.Err()
}

// mgmtDayView is one bar of the volume chart, display-ready.
type mgmtDayView struct {
	DateLabel string
	HasData   bool
	Approx    bool
	Percent   int // bar width, 0-100
	Rest      int // 100 - Percent, for the empty cell
	VolLabel  string
	Findings  int
}

type mgmtSevView struct {
	Name   string
	Count  int
	Colour string
}

type mgmtView struct {
	PeriodLabel   string
	GeneratedAt   string
	Version       string
	TotalRaw      string
	TotalFiltered string
	Reduction     string // e.g. "99.2% filtered out as routine noise"
	HaveFiltered  bool
	TotalFindings string
	AnomalyCount  string
	Days          []mgmtDayView
	DaysWithData  int
	TotalDays     int
	ApproxDays    int
	Severities    []mgmtSevView
	TopServices   []ServiceCount
	FeedbackTotal int
	FeedbackLabel string
}

// mgmtDateLabel renders an ISO date as "Mon 28 Aug".
func mgmtDateLabel(iso string) string {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return iso
	}
	return t.Format("Mon 02 Jan")
}

// MgmtPeriodLabel renders the inclusive period as "30 Jul to 28 Aug 2026".
func MgmtPeriodLabel(fromISO, toISO string) string {
	from, err1 := time.Parse("2006-01-02", fromISO)
	to, err2 := time.Parse("2006-01-02", toISO)
	if err1 != nil || err2 != nil {
		return fromISO + " to " + toISO
	}
	if from.Year() == to.Year() {
		return from.Format("02 Jan") + " to " + to.Format("02 Jan 2006")
	}
	return from.Format("02 Jan 2006") + " to " + to.Format("02 Jan 2006")
}

func buildMgmtView(stats *MgmtStats, version string) *mgmtView {
	v := &mgmtView{
		PeriodLabel:   MgmtPeriodLabel(stats.From, stats.To),
		GeneratedAt:   time.Now().Format("02 Jan 2006"),
		Version:       version,
		TotalRaw:      pyThousands(int(stats.TotalRaw)),
		TotalFiltered: pyThousands(int(stats.TotalFiltered)),
		HaveFiltered:  stats.HaveFiltered,
		TotalFindings: pyThousands(stats.TotalFindings),
		AnomalyCount:  pyThousands(stats.AnomalyCount),
		DaysWithData:  stats.DaysWithData,
		TotalDays:     len(stats.Days),
		ApproxDays:    stats.ApproxDays,
		TopServices:   stats.TopServices,
	}
	if stats.HaveFiltered && stats.TotalRaw > 0 {
		pct := 100 * float64(stats.TotalRaw-stats.TotalFiltered) / float64(stats.TotalRaw)
		v.Reduction = fmt.Sprintf("%.1f%% filtered out as routine noise", pct)
	}

	var maxRaw int64
	for _, d := range stats.Days {
		if d.RawLines > maxRaw {
			maxRaw = d.RawLines
		}
	}
	for _, d := range stats.Days {
		dv := mgmtDayView{
			DateLabel: mgmtDateLabel(d.Date),
			Findings:  d.Findings,
		}
		if d.RawLines >= 0 {
			dv.HasData = true
			dv.Approx = d.Approx
			dv.VolLabel = pyThousands(int(d.RawLines))
			if maxRaw > 0 {
				dv.Percent = int(100 * d.RawLines / maxRaw)
				if dv.Percent < 1 && d.RawLines > 0 {
					dv.Percent = 1
				}
			}
		}
		dv.Rest = 100 - dv.Percent
		v.Days = append(v.Days, dv)
	}

	// Fixed order, zero counts included: a month with no criticals is a
	// headline, not a blank.
	for _, sev := range []struct{ name, label, colour string }{
		{"critical", "Critical", "#D4351C"},
		{"high", "High", "#005398"},
		{"medium", "Medium", "#677297"},
		{"low", "Low", "#999999"},
	} {
		v.Severities = append(v.Severities, mgmtSevView{
			Name:   sev.label,
			Count:  stats.SeverityCounts[sev.name],
			Colour: sev.colour,
		})
	}

	v.FeedbackTotal = stats.FeedbackWorked + stats.FeedbackDidnt
	if v.FeedbackTotal > 0 {
		v.FeedbackLabel = fmt.Sprintf(
			"%d of %d reviewed findings marked as useful by the team",
			stats.FeedbackWorked, v.FeedbackTotal)
	}
	return v
}

var mgmtTemplate = template.Must(template.New("mgmt").Parse(mgmtTemplateSrc))

// RenderMgmtHTML renders the management report as a self-contained,
// email-safe HTML document.
func RenderMgmtHTML(stats *MgmtStats, version string) (string, error) {
	var buf bytes.Buffer
	if err := mgmtTemplate.Execute(&buf, buildMgmtView(stats, version)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderMgmtText renders the plain-text alternative body: the headline
// numbers only, for clients that refuse HTML.
func RenderMgmtText(stats *MgmtStats) string {
	v := buildMgmtView(stats, "")
	var b strings.Builder
	fmt.Fprintf(&b, "Syslog management summary, %s\n\n", v.PeriodLabel)
	fmt.Fprintf(&b, "Lines ingested: %s (%d of %d days with data)\n",
		v.TotalRaw, v.DaysWithData, v.TotalDays)
	if v.HaveFiltered {
		fmt.Fprintf(&b, "After filtering: %s (%s)\n", v.TotalFiltered, v.Reduction)
	}
	fmt.Fprintf(&b, "Findings surfaced: %s (plus %s anomalies)\n", v.TotalFindings, v.AnomalyCount)
	if v.FeedbackLabel != "" {
		fmt.Fprintf(&b, "Feedback: %s\n", v.FeedbackLabel)
	}
	return b.String()
}
