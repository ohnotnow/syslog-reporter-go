package reporter

// The management report (ait srg-YHETx): a periodic HTML email of headline
// numbers and a volume trend for senior IT management, distinct from the
// daily sysadmin digest. It is a PURE READER of tables that survive the
// aggregate store's prune - runs, findings, feedback (ant ADR srg-9X77J).
// Two exceptions read the aggregates table, and so reach back only as far
// as its prune window: days inside the period that predate the runs stats
// columns borrow an approximate volume from it, so the trend chart is not
// empty on day one, and the host counts, noisiest-hosts and biggest-changes
// tables need its per-host line counts.
//
// The HTML is email-safe by design: tables for layout, every style inline,
// no SVG, no JavaScript, no webfonts - Outlook's Word renderer and Gmail
// both eat anything cleverer. Charts are nested-table horizontal bars.

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"math"
	"sort"
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
	Hosts         int // hosts with volume in the aggregates; 0 = none recorded
}

// ServiceCount is one row of the "most flagged services" table.
type ServiceCount struct {
	Service string
	Count   int
}

// mgmtTopN caps every ranked table: a manager reads five rows, not fifty.
const mgmtTopN = 5

// moverFloor is the lines-per-day a host must reach in at least one of the
// two mover windows to be ranked, so 10 lines becoming 200 is not "20x".
const moverFloor = 1000

// HostFlagged is one row of the "most flagged hosts" table. Days is the
// headline: the same problem recurs daily, so the finding count inflates.
type HostFlagged struct {
	Host     string
	Days     int
	Findings int
}

// HostVolume is one row of the "noisiest hosts" table. PerDay averages
// over the period's days with volume data, so a host that stopped
// logging part-way through is averaged down, not flattered.
type HostVolume struct {
	Host       string
	PerDay     float64
	TopProgram string  // the program sending most of its lines
	TopShare   float64 // TopProgram's share of the host's lines, 0-1
}

// HostMover is one row of the "biggest changes" table: average lines per
// day over the period's first and last MoverWindow days. Before 0 is a
// host that started logging, After 0 one that stopped.
type HostMover struct {
	Host          string
	Before, After float64
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

	RecentDays    int    // length of the hosts-sending-logs window, up to a week
	RecentHosts   int    // hosts that sent logs in the period's last RecentDays
	PrevHosts     int    // the same window a period earlier; 0 = no data then
	PrevTo        string // ISO end of that earlier window
	RunDays       int    // days with a daily run: the most a host can be flagged
	TopHosts      []HostFlagged
	NoisiestHosts []HostVolume
	VolumeHosts   int     // hosts with any volume in the period
	MedianPerDay  float64 // the typical host's lines per day
	Movers        []HostMover
	MoverWindow   int // days in each mover window; 0 = period too short
}

// GatherMgmtStats collects the period's numbers from the findings library,
// borrowing per-day volume from the aggregate store for days whose run row
// has no raw_lines. from/to are inclusive log dates. The per-host volume
// tables read the aggregates too, so they cover at most the prune window
// (SYSLOG_DB_KEEP_DAYS, 90 by default).
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
		"SELECT log_date, raw_lines, filtered_lines FROM runs WHERE kind = 'daily' AND log_date BETWEEN ? AND ?",
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
	stats.RunDays = len(runs)
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
		 WHERE r.kind = 'daily' AND r.log_date BETWEEN ? AND ? GROUP BY r.log_date`,
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
		 WHERE r.kind = 'daily' AND r.log_date BETWEEN ? AND ? GROUP BY f.kind, f.severity`,
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
		 WHERE r.kind = 'daily' AND r.log_date BETWEEN ? AND ? AND f.service <> ''
		 GROUP BY f.service ORDER BY n DESC, f.service LIMIT ?`,
		fromISO, toISO, mgmtTopN)
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
		 WHERE r.kind = 'daily' AND r.log_date BETWEEN ? AND ? GROUP BY fb.verdict`,
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := gatherFlaggedHosts(lib, stats); err != nil {
		return nil, err
	}
	if err := gatherHostVolumes(agg, stats); err != nil {
		return nil, err
	}
	if err := gatherHostsReporting(agg, stats, to); err != nil {
		return nil, err
	}
	return stats, nil
}

// gatherHostsReporting counts the hosts that sent logs in the period's last
// week, and in the same week a period earlier. With the ELK rollout far
// from complete this is a headline in its own right. A week, not a day:
// hosts miss the odd day, and a day-on-day comparison would show that
// wobble as progress or decline; a dead host still drops out within a week.
func gatherHostsReporting(agg *AggregateStore, stats *MgmtStats, to time.Time) error {
	stats.RecentDays = min(7, len(stats.Days))
	count := func(end time.Time) (int, error) {
		var n int
		err := agg.db.QueryRow(
			"SELECT COUNT(DISTINCT host) FROM aggregates WHERE date BETWEEN ? AND ?",
			isoDate(end.AddDate(0, 0, -(stats.RecentDays-1))), isoDate(end)).Scan(&n)
		return n, err
	}
	var err error
	if stats.RecentHosts, err = count(to); err != nil {
		return err
	}
	prevTo := to.AddDate(0, 0, -len(stats.Days))
	stats.PrevTo = isoDate(prevTo)
	stats.PrevHosts, err = count(prevTo)
	return err
}

// gatherFlaggedHosts ranks hosts by how many days of the period they were
// named in a finding, then by finding count.
func gatherFlaggedHosts(lib *LibraryStore, stats *MgmtStats) error {
	rows, err := lib.db.Query(
		`SELECT fh.host, COUNT(DISTINCT r.log_date) AS days, COUNT(DISTINCT f.id) AS n
		 FROM finding_hosts fh
		 JOIN findings f ON f.id = fh.finding_id
		 JOIN runs r ON r.id = f.run_id
		 WHERE r.kind = 'daily' AND r.log_date BETWEEN ? AND ?
		 GROUP BY fh.host ORDER BY days DESC, n DESC, fh.host LIMIT ?`,
		stats.From, stats.To, mgmtTopN)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var h HostFlagged
		if err := rows.Scan(&h.Host, &h.Days, &h.Findings); err != nil {
			return err
		}
		stats.TopHosts = append(stats.TopHosts, h)
	}
	return rows.Err()
}

// gatherHostVolumes fills the noisiest-hosts and biggest-changes tables
// from the aggregates' raw per-host line counts. Averages divide by the
// days that have ANY volume data (fleet-wide), so a day the pipeline did
// not run counts against nobody, while a host absent on a day the rest of
// the fleet logged counts as zero.
func gatherHostVolumes(agg *AggregateStore, stats *MgmtStats) error {
	type hostDay struct{ host, date string }
	daily := map[hostDay]int64{}
	dataDays := map[string]bool{}
	rows, err := agg.db.Query(
		`SELECT host, date, SUM(count) FROM aggregates
		 WHERE date BETWEEN ? AND ? GROUP BY host, date`,
		stats.From, stats.To)
	if err != nil {
		return err
	}
	for rows.Next() {
		var hd hostDay
		var n int64
		if err := rows.Scan(&hd.host, &hd.date, &n); err != nil {
			rows.Close()
			return err
		}
		daily[hd] = n
		dataDays[hd.date] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(dataDays) == 0 {
		return nil
	}

	hostsOn := map[string]int{}
	for hd := range daily {
		hostsOn[hd.date]++
	}
	for i := range stats.Days {
		stats.Days[i].Hosts = hostsOn[stats.Days[i].Date]
	}

	// Each host's biggest program over the period. Ties go to the
	// alphabetically first program so the output never depends on row order.
	type progTotal struct {
		program string
		n       int64
	}
	topProg := map[string]progTotal{}
	rows, err = agg.db.Query(
		`SELECT host, program, SUM(count) FROM aggregates
		 WHERE date BETWEEN ? AND ? GROUP BY host, program`,
		stats.From, stats.To)
	if err != nil {
		return err
	}
	for rows.Next() {
		var host string
		var p progTotal
		if err := rows.Scan(&host, &p.program, &p.n); err != nil {
			rows.Close()
			return err
		}
		cur, seen := topProg[host]
		if !seen || p.n > cur.n || (p.n == cur.n && p.program < cur.program) {
			topProg[host] = p
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	totals := map[string]int64{}
	for hd, n := range daily {
		totals[hd.host] += n
	}
	var volumes []HostVolume
	var perDays []float64
	for host, total := range totals {
		v := HostVolume{Host: host, PerDay: float64(total) / float64(len(dataDays))}
		if p := topProg[host]; total > 0 {
			v.TopProgram = p.program
			v.TopShare = float64(p.n) / float64(total)
		}
		volumes = append(volumes, v)
		perDays = append(perDays, v.PerDay)
	}
	sort.Slice(volumes, func(i, j int) bool {
		if volumes[i].PerDay != volumes[j].PerDay {
			return volumes[i].PerDay > volumes[j].PerDay
		}
		return volumes[i].Host < volumes[j].Host
	})
	stats.VolumeHosts = len(volumes)
	stats.MedianPerDay = median(perDays)
	stats.NoisiestHosts = volumes[:min(mgmtTopN, len(volumes))]

	// Movers: the first and last week of the period, or its halves when
	// the period is shorter than a fortnight.
	window := min(7, len(stats.Days)/2)
	if window < 1 {
		return nil
	}
	windowAvg := func(days []MgmtDay) map[string]float64 {
		var n int
		for _, d := range days {
			if dataDays[d.Date] {
				n++
			}
		}
		if n == 0 {
			return nil
		}
		avg := map[string]float64{}
		for host := range totals {
			var sum int64
			for _, d := range days {
				sum += daily[hostDay{host, d.Date}]
			}
			avg[host] = float64(sum) / float64(n)
		}
		return avg
	}
	before := windowAvg(stats.Days[:window])
	after := windowAvg(stats.Days[len(stats.Days)-window:])
	if before == nil || after == nil {
		return nil
	}
	stats.MoverWindow = window
	var movers []HostMover
	for host := range totals {
		m := HostMover{Host: host, Before: before[host], After: after[host]}
		if max(m.Before, m.After) >= moverFloor && m.Before != m.After {
			movers = append(movers, m)
		}
	}
	// Rank by the size of the change either way (log ratio, so 10x up and
	// 10x down score alike); a host that started or stopped logging
	// outranks any ratio. Ties: the bigger volume, then the host name.
	score := func(m HostMover) float64 {
		if m.Before == 0 || m.After == 0 {
			return math.Inf(1)
		}
		return math.Abs(math.Log(m.After / m.Before))
	}
	sort.Slice(movers, func(i, j int) bool {
		si, sj := score(movers[i]), score(movers[j])
		if si != sj {
			return si > sj
		}
		vi := max(movers[i].Before, movers[i].After)
		vj := max(movers[j].Before, movers[j].After)
		if vi != vj {
			return vi > vj
		}
		return movers[i].Host < movers[j].Host
	})
	stats.Movers = movers[:min(mgmtTopN, len(movers))]
	return nil
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
	Hosts     string // "34 hosts"; empty when none recorded
}

type mgmtSevView struct {
	Name   string
	Count  int
	Colour string
}

type mgmtFlaggedView struct {
	Host      string
	DaysLabel string // "12 of 30 days"
	Findings  string
}

type mgmtNoisyView struct {
	Host   string
	PerDay string
	Times  string // multiple of the typical (median) host, "85x"
	Source string // "rsyslogd (99%)"
}

type mgmtMoverView struct {
	Host   string
	Before string
	After  string
	Change string // "up 70x", "down 3.8x", "new" or "stopped"
}

type mgmtView struct {
	PeriodLabel   string
	GeneratedAt   string
	Version       string
	RepoURL       string // footer link, so a forwarded copy leads to the project
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
	TopHosts      []mgmtFlaggedView
	NoisiestHosts []mgmtNoisyView
	TypicalLabel  string // the median host, for the noisiest table's footnote
	RecentHosts   int
	HostsWindow   string // "in the 7 days to Mon 28 Sep"
	HostsCompare  string // "compared to 33 in the 7 days to Sat 29 Aug"
	HostsPeriod   string // "36 different hosts over the period"
	Movers        []mgmtMoverView
	MoverLabel    string // what the two mover columns compare
}

// mgmtWindow names a window of days ending on endISO: "the 7 days to
// Mon 28 Sep", or just the date for a one-day window.
func mgmtWindow(days int, endISO string) string {
	if days == 1 {
		return mgmtDateLabel(endISO)
	}
	return fmt.Sprintf("the %d days to %s", days, mgmtDateLabel(endISO))
}

// timesLabel renders a ratio as "85x" or, below ten, "3.8x".
func timesLabel(r float64) string {
	if r >= 10 {
		return fmt.Sprintf("%.0fx", r)
	}
	return fmt.Sprintf("%.1fx", r)
}

// moverChange describes a mover symmetrically, so a tenfold drop reads
// as "down 10x" rather than a hard-to-picture "0.1x".
func moverChange(m HostMover) string {
	switch {
	case m.Before == 0:
		return "new"
	case m.After == 0:
		return "stopped"
	case m.After > m.Before:
		return "up " + timesLabel(m.After/m.Before)
	default:
		return "down " + timesLabel(m.Before/m.After)
	}
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
		TotalRaw:      thousands(int(stats.TotalRaw)),
		TotalFiltered: thousands(int(stats.TotalFiltered)),
		HaveFiltered:  stats.HaveFiltered,
		TotalFindings: thousands(stats.TotalFindings),
		AnomalyCount:  thousands(stats.AnomalyCount),
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
		if d.Hosts > 0 {
			dv.Hosts = fmt.Sprintf("%d %s", d.Hosts, plural(d.Hosts, "host", "hosts"))
		}
		if d.RawLines >= 0 {
			dv.HasData = true
			dv.Approx = d.Approx
			dv.VolLabel = thousands(int(d.RawLines))
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

	for _, h := range stats.TopHosts {
		v.TopHosts = append(v.TopHosts, mgmtFlaggedView{
			Host:      h.Host,
			DaysLabel: fmt.Sprintf("%d of %d %s", h.Days, stats.RunDays, plural(stats.RunDays, "day", "days")),
			Findings:  thousands(h.Findings),
		})
	}
	for _, h := range stats.NoisiestHosts {
		nv := mgmtNoisyView{Host: h.Host, PerDay: thousandsFloat(h.PerDay)}
		if stats.MedianPerDay > 0 {
			nv.Times = timesLabel(h.PerDay / stats.MedianPerDay)
		}
		if h.TopProgram != "" {
			nv.Source = fmt.Sprintf("%s (%.0f%%)", h.TopProgram, 100*h.TopShare)
		}
		v.NoisiestHosts = append(v.NoisiestHosts, nv)
	}
	if stats.VolumeHosts > 0 {
		v.RecentHosts = stats.RecentHosts
		prep := "in "
		if stats.RecentDays == 1 {
			prep = "on "
		}
		v.HostsWindow = prep + mgmtWindow(stats.RecentDays, stats.To)
		v.HostsPeriod = fmt.Sprintf("%d different %s over the period",
			stats.VolumeHosts, plural(stats.VolumeHosts, "host", "hosts"))
		prev := mgmtWindow(stats.RecentDays, stats.PrevTo)
		switch {
		case stats.PrevHosts == 0:
			// no data a period earlier: say nothing rather than "compared to 0"
		case stats.PrevHosts == stats.RecentHosts:
			v.HostsCompare = "same as " + prev
		default:
			v.HostsCompare = fmt.Sprintf("compared to %d %s", stats.PrevHosts, prep+prev)
		}
	}
	if stats.VolumeHosts > 0 {
		v.TypicalLabel = fmt.Sprintf(
			"A typical host logs %s lines a day (the median across %d %s).",
			thousandsFloat(stats.MedianPerDay), stats.VolumeHosts, plural(stats.VolumeHosts, "host", "hosts"))
	}
	for _, m := range stats.Movers {
		v.Movers = append(v.Movers, mgmtMoverView{
			Host:   m.Host,
			Before: thousandsFloat(m.Before),
			After:  thousandsFloat(m.After),
			Change: moverChange(m),
		})
	}
	if stats.MoverWindow > 0 {
		v.MoverLabel = fmt.Sprintf(
			"Average lines a day over the first and last %d days of the period.",
			stats.MoverWindow)
	}

	v.FeedbackTotal = stats.FeedbackWorked + stats.FeedbackDidnt
	if v.FeedbackTotal > 0 {
		// Rows are votes, one per person per finding, so several people
		// reviewing one finding count several times: say votes, not
		// findings (ait srg-6Vsgx.9).
		votes := "votes"
		if v.FeedbackTotal == 1 {
			votes = "vote"
		}
		v.FeedbackLabel = fmt.Sprintf("%d of %d feedback %s said the fix worked",
			stats.FeedbackWorked, v.FeedbackTotal, votes)
	}
	return v
}

var mgmtTemplate = template.Must(template.New("mgmt").Parse(mgmtTemplateSrc))

// RenderMgmtHTML renders the management report as a self-contained,
// email-safe HTML document. repoURL links the footer's tool name; empty
// leaves it plain text.
func RenderMgmtHTML(stats *MgmtStats, version, repoURL string) (string, error) {
	v := buildMgmtView(stats, version)
	v.RepoURL = repoURL
	var buf bytes.Buffer
	if err := mgmtTemplate.Execute(&buf, v); err != nil {
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
	if v.HostsWindow != "" {
		fmt.Fprintf(&b, "Hosts sending logs: %d %s", v.RecentHosts, v.HostsWindow)
		if v.HostsCompare != "" {
			fmt.Fprintf(&b, " (%s)", v.HostsCompare)
		}
		fmt.Fprintf(&b, "; %s\n", v.HostsPeriod)
	}
	fmt.Fprintf(&b, "Lines ingested: %s (%d of %d %s with data)\n",
		v.TotalRaw, v.DaysWithData, v.TotalDays, plural(v.TotalDays, "day", "days"))
	if v.HaveFiltered {
		fmt.Fprintf(&b, "After filtering: %s (%s)\n", v.TotalFiltered, v.Reduction)
	}
	// "including", not "plus": TotalFindings already counts the anomalies.
	fmt.Fprintf(&b, "Findings surfaced: %s (including %s anomalies)\n", v.TotalFindings, v.AnomalyCount)
	if v.FeedbackLabel != "" {
		fmt.Fprintf(&b, "Feedback: %s\n", v.FeedbackLabel)
	}
	if len(v.TopHosts) > 0 {
		b.WriteString("\nMost flagged hosts:\n")
		for _, h := range v.TopHosts {
			fmt.Fprintf(&b, "  %s: flagged on %s (%s findings)\n", h.Host, h.DaysLabel, h.Findings)
		}
	}
	if len(v.NoisiestHosts) > 0 {
		b.WriteString("\nNoisiest hosts (lines a day):\n")
		for _, h := range v.NoisiestHosts {
			fmt.Fprintf(&b, "  %s: %s, %s typical, mostly %s\n", h.Host, h.PerDay, h.Times, h.Source)
		}
		fmt.Fprintf(&b, "  %s\n", v.TypicalLabel)
	}
	if len(v.Movers) > 0 {
		b.WriteString("\nBiggest changes in volume:\n")
		for _, m := range v.Movers {
			fmt.Fprintf(&b, "  %s: %s to %s lines a day (%s)\n", m.Host, m.Before, m.After, m.Change)
		}
		fmt.Fprintf(&b, "  %s\n", v.MoverLabel)
	}
	return b.String()
}
