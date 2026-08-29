package reporter

// Temporal burst detection WITH seasonality handling.
// Naive within-day burst detection is dominated by expected
// seasonality (labs rebooting at ~10:00 dump kernel logs every morning), so
// we compare like with like: today's count in a time-of-day window against
// the SAME window on prior days, per (host, program). A normal morning
// reboot sits right on its own 10:00 baseline and never flags.
//
// Needs accumulated per-window history, so it is a no-op until the store
// holds at least MinHistoryDays for a (host, program, window). Window
// granularity is BucketMinutes in anomaly.go.

import (
	"fmt"
	"sort"
	"time"
)

const (
	TemporalLookbackDays   = 14  // trailing window of same-time-of-day history
	TemporalMinHistoryDays = 7   // days of that-window history needed before we score it
	TemporalThreshold      = 3.5 // |modified z| to flag
	TemporalMinCount       = 30  // ignore quiet windows: a burst worth a glance is busy
)

type TemporalAnomaly struct {
	host           string
	program        string
	Window         string  // 'HH:MM' time-of-day bucket that burst
	Count          int     // today's count in that window
	BaselineMedian float64 // this host's own median for that window historically
	score          float64 // modified z vs the same window on prior days
	DaysSeen       int
	exampleLine    string
	osFamily       string
}

func (a *TemporalAnomaly) Host() string          { return a.host }
func (a *TemporalAnomaly) Program() string       { return a.program }
func (a *TemporalAnomaly) Kind() string          { return "temporal" }
func (a *TemporalAnomaly) Score() float64        { return a.score }
func (a *TemporalAnomaly) ExampleLine() string   { return a.exampleLine }
func (a *TemporalAnomaly) OSFamily() string      { return a.osFamily }
func (a *TemporalAnomaly) SetOSFamily(os string) { a.osFamily = os }

func (a *TemporalAnomaly) Headline() string {
	return fmt.Sprintf("Burst in the %s window", a.Window)
}

func (a *TemporalAnomaly) Summary() string {
	return fmt.Sprintf(
		"%s events in the %s window today vs an own median of %s for that "+
			"time of day (over %d days) - a burst beyond its usual rhythm.",
		thousands(a.Count), a.Window, thousandsFloat(a.BaselineMedian), a.DaysSeen)
}

// TemporalDetector flags (host, program, window) counts unusual for that
// time of day.
type TemporalDetector struct {
	agg     *Aggregate
	store   *AggregateStore
	logDate time.Time

	LookbackDays   int
	MinHistoryDays int
	Threshold      float64
	MinCount       int
}

func NewTemporalDetector(agg *Aggregate, store *AggregateStore, logDate time.Time) *TemporalDetector {
	return &TemporalDetector{
		agg:            agg,
		store:          store,
		logDate:        logDate,
		LookbackDays:   TemporalLookbackDays,
		MinHistoryDays: TemporalMinHistoryDays,
		Threshold:      TemporalThreshold,
		MinCount:       TemporalMinCount,
	}
}

func (d *TemporalDetector) Run() ([]Anomaly, error) {
	history, err := d.store.HistoryWindowCounts(d.logDate, d.LookbackDays)
	if err != nil {
		return nil, err
	}
	families := osFamilies(d.agg.HostPrograms)

	var anomalies []*TemporalAnomaly
	for key, todayCount := range d.agg.Counts {
		if todayCount < d.MinCount {
			continue
		}
		days := history[key]
		if len(days) < d.MinHistoryDays {
			continue
		}
		population := make([]float64, 0, len(days))
		for _, total := range days {
			population = append(population, float64(total))
		}
		baselineMedian := median(population)
		score := RobustZ(float64(todayCount), population)
		if score < d.Threshold {
			continue
		}
		family, ok := families[key.Host]
		if !ok {
			family = "unknown"
		}
		anomalies = append(anomalies, &TemporalAnomaly{
			host:           key.Host,
			program:        key.Program,
			Window:         key.Window,
			Count:          todayCount,
			BaselineMedian: baselineMedian,
			score:          score,
			DaysSeen:       len(days),
			exampleLine:    d.agg.Examples[PairKey{Host: key.Host, Program: key.Program}],
			osFamily:       family,
		})
	}

	// Highest score first; ties break lexicographically by (host, program,
	// window) - a (host, program) can burst in several windows, so the
	// window is part of the tie-break.
	sort.Slice(anomalies, func(i, j int) bool {
		a, b := anomalies[i], anomalies[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if a.host != b.host {
			return a.host < b.host
		}
		if a.program != b.program {
			return a.program < b.program
		}
		return a.Window < b.Window
	})
	out := make([]Anomaly, len(anomalies))
	for i, a := range anomalies {
		out[i] = a
	}
	return out, nil
}
