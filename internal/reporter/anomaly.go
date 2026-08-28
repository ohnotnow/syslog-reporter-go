package reporter

// Port of agents/anomaly_agent.py: peer-comparison anomaly detection over the
// RAW syslog, upstream of the denylist so it can see the high-volume programs
// the filter deletes. Deliberately stdlib-style: parse the program field,
// count per (host, program, window), and flag hosts doing far more of a
// program than their fleet peers via a robust (median/MAD) z-score.
//
// Where the Python original relied on dict insertion order, the ordered
// structures below preserve it, so tie-breaks in the stable sorts land the
// same way.

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

// Counts is an insertion-ordered map of (host, program, window) to a count,
// mirroring a Python dict's ordering guarantees.
type Counts struct {
	keys []AggKey
	m    map[AggKey]int
}

func NewCounts() *Counts {
	return &Counts{m: map[AggKey]int{}}
}

func (c *Counts) Add(k AggKey, n int) {
	if _, ok := c.m[k]; !ok {
		c.keys = append(c.keys, k)
	}
	c.m[k] += n
}

func (c *Counts) Get(k AggKey) (int, bool) {
	n, ok := c.m[k]
	return n, ok
}

func (c *Counts) Len() int { return len(c.keys) }

// Keys returns the keys in first-seen order. Callers must not mutate it.
func (c *Counts) Keys() []AggKey { return c.keys }

// PairTotals is an insertion-ordered map of (host, program) to a day total.
type PairTotals struct {
	keys []PairKey
	m    map[PairKey]int
}

func NewPairTotals() *PairTotals {
	return &PairTotals{m: map[PairKey]int{}}
}

func (p *PairTotals) Add(k PairKey, n int) {
	if _, ok := p.m[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.m[k] += n
}

func (p *PairTotals) Get(k PairKey) (int, bool) {
	n, ok := p.m[k]
	return n, ok
}

func (p *PairTotals) Keys() []PairKey { return p.keys }

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
		pyThousands(a.Count), pyG(a.FleetMedian))
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
		// The Python original would crash on a non-numeric minute after a
		// plausible-looking timestamp; treat it as unparseable instead.
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
func CollapseToPairs(counts *Counts) *PairTotals {
	pairs := NewPairTotals()
	for _, k := range counts.Keys() {
		n, _ := counts.Get(k)
		pairs.Add(PairKey{Host: k.Host, Program: k.Program}, n)
	}
	return pairs
}

// CombineAnomalies merges anomalies from several detectors into one ranked
// list. Each detector can flag the same (host, program); alert fatigue is the
// enemy, so we collapse to one entry per (host, program), keeping the
// strongest signal. Scores are all modified z-scores, so their magnitudes are
// comparable across detectors and the union ranks by |score|.
func CombineAnomalies(lists ...[]Anomaly) []Anomaly {
	var order []PairKey
	merged := map[PairKey]Anomaly{}
	for _, list := range lists {
		for _, a := range list {
			key := PairKey{Host: a.Host(), Program: a.Program()}
			existing, ok := merged[key]
			if !ok {
				order = append(order, key)
				merged[key] = a
			} else if math.Abs(a.Score()) > math.Abs(existing.Score()) {
				merged[key] = a
			}
		}
	}
	result := make([]Anomaly, len(order))
	for i, key := range order {
		result[i] = merged[key]
	}
	sort.SliceStable(result, func(i, j int) bool {
		return math.Abs(result[i].Score()) > math.Abs(result[j].Score())
	})
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
	Counts       *Counts
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
		Counts:       NewCounts(),
		Examples:     map[PairKey]string{},
		HostPrograms: map[string]map[string]struct{}{},
	}
	for _, line := range d.lines {
		rec := ParseLine(line)
		if rec == nil {
			continue
		}
		agg.Counts.Add(AggKey{Host: rec.Host, Program: rec.Program, Window: rec.Window}, 1)
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
	// by program so each program is its own peer group. Insertion order is
	// preserved throughout to match Python's dict semantics.
	pairTotals := CollapseToPairs(agg.Counts)

	type hostCount struct {
		host string
		n    int
	}
	var programOrder []string
	byProgram := map[string][]hostCount{}
	for _, pair := range pairTotals.Keys() {
		n, _ := pairTotals.Get(pair)
		if _, ok := byProgram[pair.Program]; !ok {
			programOrder = append(programOrder, pair.Program)
		}
		byProgram[pair.Program] = append(byProgram[pair.Program], hostCount{pair.Host, n})
	}

	families := osFamilies(agg.HostPrograms)

	var anomalies []Anomaly
	for _, program := range programOrder {
		hostCounts := byProgram[program]
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
	sort.SliceStable(anomalies, func(i, j int) bool {
		return anomalies[i].Score() > anomalies[j].Score()
	})
	return anomalies
}
