package reporter

// Peer-comparison anomaly detection over the RAW syslog, upstream of the
// denylist so it can see the high-volume programs the filter deletes.
// Deliberately stdlib-style: parse the program field, count per (host,
// program, window), and flag hosts doing far more of a program than their
// fleet peers via a robust (median/MAD) z-score.
//
// Output ordering is deterministic by construction: every ranked list is
// sorted by score with an explicit lexicographic (host, program) tie-break,
// never by map iteration order.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Conservative defaults: we rank here; the report (later) caps length.
const (
	DefaultMinHosts = 5  // only peer-compare programs seen on >= this many hosts
	DefaultMinCount = 50 // ignore a (host, program) quieter than this
	BucketMinutes   = 10 // time-window granularity for the aggregate store
)

// Program-name fingerprints for a rough OS-family guess. Deliberately small
// and high-confidence; ambiguous hosts fall back to "unknown".
var (
	rhelHints   = []string{"dnf", "yum", "rpm", "setroubleshoot", "subscription-manager", "firewalld"}
	debianHints = []string{"apt", "dpkg", "snapd", "unattended-upgrades", "ufw"}
)

type AggKey struct {
	Host    string
	Program string
	Window  string
}

type PairKey struct {
	Host    string
	Program string
}

// Anomaly is the common interface shared by every anomaly type (peer /
// baseline / temporal) so the explainer and report can treat them uniformly.
// Headline is the short label; Summary is the deterministic numbers sentence.
type Anomaly interface {
	Host() string
	Program() string
	Kind() string
	Score() float64
	Headline() string
	Summary() string
	ExampleLine() string
	OSFamily() string
	SetOSFamily(string)
}

type PeerAnomaly struct {
	host        string
	program     string
	Count       int
	FleetMedian float64
	score       float64 // robust z-score vs the fleet
	exampleLine string
	osFamily    string
}

func (a *PeerAnomaly) Host() string          { return a.host }
func (a *PeerAnomaly) Program() string       { return a.program }
func (a *PeerAnomaly) Kind() string          { return "peer" }
func (a *PeerAnomaly) Score() float64        { return a.score }
func (a *PeerAnomaly) ExampleLine() string   { return a.exampleLine }
func (a *PeerAnomaly) OSFamily() string      { return a.osFamily }
func (a *PeerAnomaly) SetOSFamily(os string) { a.osFamily = os }

func (a *PeerAnomaly) Headline() string { return "Louder than its peers" }

func (a *PeerAnomaly) Summary() string {
	return fmt.Sprintf("%s events vs a fleet median of %s across peer hosts.",
		thousands(a.Count), compactFloat(a.FleetMedian))
}

// ParsedLine is the (host, program, window, raw) tuple parse_line returns.
type ParsedLine struct {
	Host    string
	Program string
	Window  string
	Raw     string
}

// ParseLine extracts (host, program, window, raw) from a standard syslog
// line ('Mon DD HH:MM:SS host program[pid]: message'), or nil if the line
// doesn't fit. The whitespace split mirrors LogFilter.
func ParseLine(line string) *ParsedLine {
	parts := splitWS(line, 4)
	if len(parts) < 5 {
		return nil
	}
	tstamp, host, rest := parts[2], parts[3], parts[4]
	if len(tstamp) < 5 || tstamp[2] != ':' {
		return nil
	}
	program := splitWS(rest, 1)[0]               // 'puppet-agent[1545710]:'
	program = strings.SplitN(program, "[", 2)[0] // drop '[pid]...' and any path's '[...]'
	program = strings.TrimRight(program, ":")
	if program == "" {
		return nil
	}
	minute, err := strconv.Atoi(tstamp[3:5])
	if err != nil {
		// A non-numeric minute after a plausible-looking timestamp: treat
		// the line as unparseable rather than guessing a window.
		return nil
	}
	window := fmt.Sprintf("%s:%02d", tstamp[:2], (minute/BucketMinutes)*BucketMinutes)
	return &ParsedLine{Host: host, Program: program, Window: window,
		Raw: strings.TrimRight(line, "\n")}
}

func median(population []float64) float64 {
	s := append([]float64(nil), population...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// RobustZ is the modified z-score (median + MAD), falling back from MAD to
// mean-absolute-deviation when MAD is 0 (common with integer counts), so a
// lone spike against an otherwise-identical baseline still ranks instead of
// dividing by zero. Returns 0 when every value is identical.
func RobustZ(value float64, population []float64) float64 {
	med := median(population)
	deviations := make([]float64, len(population))
	for i, v := range population {
		deviations[i] = math.Abs(v - med)
	}
	mad := median(deviations)
	if mad > 0 {
		return 0.6745 * (value - med) / mad
	}
	var sum float64
	for _, d := range deviations {
		sum += d
	}
	meanAD := sum / float64(len(deviations))
	if meanAD > 0 {
		return (value - med) / (1.253 * meanAD)
	}
	return 0.0
}

// CollapseToPairs collapses window-keyed counts to per-(host, program) day
// totals. Shared by the peer detector and the day-over-day baseline detector.
func CollapseToPairs(counts map[AggKey]int) map[PairKey]int {
	pairs := map[PairKey]int{}
	for k, n := range counts {
		pairs[PairKey{Host: k.Host, Program: k.Program}] += n
	}
	return pairs
}

// rankAnomalies sorts by the given score key, highest first, breaking ties
// lexicographically by (host, program) so the order never depends on map
// iteration.
func rankAnomalies(anomalies []Anomaly, key func(Anomaly) float64) {
	sort.Slice(anomalies, func(i, j int) bool {
		a, b := anomalies[i], anomalies[j]
		if ka, kb := key(a), key(b); ka != kb {
			return ka > kb
		}
		if a.Host() != b.Host() {
			return a.Host() < b.Host()
		}
		return a.Program() < b.Program()
	})
}

// CombineAnomalies merges anomalies from several detectors into one ranked
// list. Each detector can flag the same (host, program); alert fatigue is the
// enemy, so we collapse to one entry per (host, program), keeping the
// strongest signal. Scores are all modified z-scores, so their magnitudes are
// comparable across detectors and the union ranks by |score|.
func CombineAnomalies(lists ...[]Anomaly) []Anomaly {
	merged := map[PairKey]Anomaly{}
	for _, list := range lists {
		for _, a := range list {
			key := PairKey{Host: a.Host(), Program: a.Program()}
			existing, ok := merged[key]
			if !ok || math.Abs(a.Score()) > math.Abs(existing.Score()) {
				merged[key] = a
			}
		}
	}
	result := make([]Anomaly, 0, len(merged))
	for _, a := range merged {
		result = append(result, a)
	}
	rankAnomalies(result, func(a Anomaly) float64 { return math.Abs(a.Score()) })
	return result
}

// GuessOSFamily makes a rough RHEL-family / Debian-family / unknown guess
// from the set of programs seen on a host.
func GuessOSFamily(programs map[string]struct{}) string {
	rhel, debian := false, false
	for p := range programs {
		lower := strings.ToLower(p)
		for _, h := range rhelHints {
			if strings.Contains(lower, h) {
				rhel = true
			}
		}
		for _, h := range debianHints {
			if strings.Contains(lower, h) {
				debian = true
			}
		}
	}
	if rhel && !debian {
		return "RHEL-family"
	}
	if debian && !rhel {
		return "Debian-family"
	}
	return "unknown"
}

func osFamilies(hostPrograms map[string]map[string]struct{}) map[string]string {
	families := make(map[string]string, len(hostPrograms))
	for host, programs := range hostPrograms {
		families[host] = GuessOSFamily(programs)
	}
	return families
}

// Aggregate is what PeerDetector.Aggregate returns: window-keyed counts, the
// first raw line seen per (host, program), and each host's program set.
type Aggregate struct {
	Counts       map[AggKey]int
	Examples     map[PairKey]string
	HostPrograms map[string]map[string]struct{}
}

// PeerDetector is the peer-comparison anomaly detector. Operates on RAW
// syslog lines.
type PeerDetector struct {
	lines    []string
	MinHosts int
	MinCount int
	agg      *Aggregate
}

func NewPeerDetector(lines []string) *PeerDetector {
	return &PeerDetector{lines: lines, MinHosts: DefaultMinHosts, MinCount: DefaultMinCount}
}

// Aggregate parses the raw lines once and caches the result, so callers that
// want the raw counts (the SQLite store, the history-based detectors) and
// Run don't reparse the log twice.
func (d *PeerDetector) Aggregate() *Aggregate {
	if d.agg != nil {
		return d.agg
	}
	agg := &Aggregate{
		Counts:       map[AggKey]int{},
		Examples:     map[PairKey]string{},
		HostPrograms: map[string]map[string]struct{}{},
	}
	for _, line := range d.lines {
		rec := ParseLine(line)
		if rec == nil {
			continue
		}
		agg.Counts[AggKey{Host: rec.Host, Program: rec.Program, Window: rec.Window}]++
		pair := PairKey{Host: rec.Host, Program: rec.Program}
		if _, ok := agg.Examples[pair]; !ok {
			agg.Examples[pair] = rec.Raw
		}
		if agg.HostPrograms[rec.Host] == nil {
			agg.HostPrograms[rec.Host] = map[string]struct{}{}
		}
		agg.HostPrograms[rec.Host][rec.Program] = struct{}{}
	}
	d.agg = agg
	return agg
}

// Run returns the peer anomalies, highest score first.
func (d *PeerDetector) Run() []Anomaly {
	agg := d.Aggregate()

	// Collapse windows to (host, program) day totals, then group host totals
	// by program so each program is its own peer group. Iteration order is
	// arbitrary here; the final rankAnomalies sort fixes the output order.
	pairTotals := CollapseToPairs(agg.Counts)

	type hostCount struct {
		host string
		n    int
	}
	byProgram := map[string][]hostCount{}
	for pair, n := range pairTotals {
		byProgram[pair.Program] = append(byProgram[pair.Program], hostCount{pair.Host, n})
	}

	families := osFamilies(agg.HostPrograms)

	var anomalies []Anomaly
	for program, hostCounts := range byProgram {
		if len(hostCounts) < d.MinHosts {
			continue
		}
		population := make([]float64, len(hostCounts))
		for i, hc := range hostCounts {
			population[i] = float64(hc.n)
		}
		med := median(population)
		for _, hc := range hostCounts {
			if hc.n < d.MinCount {
				continue
			}
			score := RobustZ(float64(hc.n), population)
			if score <= 0 {
				continue
			}
			family, ok := families[hc.host]
			if !ok {
				family = "unknown"
			}
			anomalies = append(anomalies, &PeerAnomaly{
				host:        hc.host,
				program:     program,
				Count:       hc.n,
				FleetMedian: med,
				score:       score,
				exampleLine: agg.Examples[PairKey{Host: hc.host, Program: program}],
				osFamily:    family,
			})
		}
	}
	rankAnomalies(anomalies, Anomaly.Score)
	return anomalies
}
