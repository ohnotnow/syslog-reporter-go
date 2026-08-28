package reporter

// Port of agents/baseline_agent.py: day-over-day per-host baseline anomaly
// detection. Where the peer detector asks "is this host unlike its fleet
// peers?", this asks "is this host unlike its own recent normal?", scoring
// today's per-(host, program) volume against that host's trailing-N-day
// history from the SQLite aggregate store. It catches what peer comparison
// can't: a host gone loud, gone quiet, or gone silent entirely.
//
// Needs accumulated history, so it is a no-op until the store has at least
// MinHistoryDays of data for a series.

import (
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	BaselineLookbackDays   = 14  // trailing window to build each host's own baseline from
	BaselineMinHistoryDays = 7   // need at least this many days of history to score a series
	BaselineThreshold      = 3.5 // |modified z| to flag (Iglewicz & Hoaglin's outlier cut)
	MinBaseline            = 50  // ignore tiny series: a jump from 2 to 10 is just noise
	MinSilentBaseline      = 100 // only call a host "silent" if it was genuinely chatty
)

type BaselineAnomaly struct {
	host           string
	program        string
	Count          int     // today's total for this (host, program)
	BaselineMedian float64 // this host's own trailing-N-day median
	score          float64 // signed modified z vs own history (negative = quieter)
	Direction      string  // "louder" | "quieter" | "silent"
	DaysSeen       int     // how many days of history informed the baseline
	exampleLine    string
	osFamily       string
}

func (a *BaselineAnomaly) Host() string          { return a.host }
func (a *BaselineAnomaly) Program() string       { return a.program }
func (a *BaselineAnomaly) Kind() string          { return "baseline" }
func (a *BaselineAnomaly) Score() float64        { return a.score }
func (a *BaselineAnomaly) ExampleLine() string   { return a.exampleLine }
func (a *BaselineAnomaly) OSFamily() string      { return a.osFamily }
func (a *BaselineAnomaly) SetOSFamily(os string) { a.osFamily = os }

func (a *BaselineAnomaly) Headline() string {
	switch a.Direction {
	case "louder":
		return "Louder than its own baseline"
	case "quieter":
		return "Quieter than its own baseline"
	default:
		return "Gone silent"
	}
}

func (a *BaselineAnomaly) Summary() string {
	if a.Direction == "silent" {
		return fmt.Sprintf(
			"No events today - this host normally emits about %s/day of %s "+
				"(median over %d days). It has gone silent.",
			pyCommaF0(a.BaselineMedian), a.program, a.DaysSeen)
	}
	verb := "up from"
	if a.Direction == "quieter" {
		verb = "down from"
	}
	return fmt.Sprintf("%s events today, %s an own %d-day median of %s.",
		pyThousands(a.Count), verb, a.DaysSeen, pyCommaF0(a.BaselineMedian))
}

// BaselineDetector scores today's per-(host, program) volume against each
// host's own history.
type BaselineDetector struct {
	agg     *Aggregate
	store   *AggregateStore
	logDate time.Time

	LookbackDays      int
	MinHistoryDays    int
	Threshold         float64
	MinBaseline       float64
	MinSilentBaseline float64
}

func NewBaselineDetector(agg *Aggregate, store *AggregateStore, logDate time.Time) *BaselineDetector {
	return &BaselineDetector{
		agg:               agg,
		store:             store,
		logDate:           logDate,
		LookbackDays:      BaselineLookbackDays,
		MinHistoryDays:    BaselineMinHistoryDays,
		Threshold:         BaselineThreshold,
		MinBaseline:       MinBaseline,
		MinSilentBaseline: MinSilentBaseline,
	}
}

func (d *BaselineDetector) Run() ([]Anomaly, error) {
	today := CollapseToPairs(d.agg.Counts)
	history, err := d.store.HistoryPairTotals(d.logDate, d.LookbackDays)
	if err != nil {
		return nil, err
	}
	families := osFamilies(d.agg.HostPrograms)

	// Union of series seen in history or today: a series present in history
	// but absent today is exactly the "gone silent" case. (The Python
	// original iterates this union as a set, so its order there is
	// arbitrary; here it is history order then today-only order, with the
	// stable score sort below deciding what actually surfaces.)
	union := append([]PairKey{}, history.Keys()...)
	seen := map[PairKey]struct{}{}
	for _, k := range history.Keys() {
		seen[k] = struct{}{}
	}
	for _, k := range today.Keys() {
		if _, ok := seen[k]; !ok {
			union = append(union, k)
		}
	}

	var anomalies []Anomaly
	for _, key := range union {
		var population []float64
		if days, ok := history.Get(key); ok {
			population = make([]float64, 0, len(days))
			for _, total := range days {
				population = append(population, float64(total))
			}
		}
		if len(population) < d.MinHistoryDays {
			continue
		}
		baselineMedian := median(population)
		todayCount, _ := today.Get(key)

		if todayCount == 0 {
			if baselineMedian >= d.MinSilentBaseline {
				anomalies = append(anomalies, d.make(key, 0, baselineMedian,
					RobustZ(0, population), "silent", len(population), families))
			}
			continue
		}

		if baselineMedian < d.MinBaseline {
			continue
		}
		score := RobustZ(float64(todayCount), population)
		var direction string
		switch {
		case score >= d.Threshold:
			direction = "louder"
		case score <= -d.Threshold:
			direction = "quieter"
		default:
			continue
		}
		anomalies = append(anomalies, d.make(key, todayCount, baselineMedian,
			score, direction, len(population), families))
	}

	// Rank by magnitude: a host gone silent (large negative) matters as much
	// as one gone loud (large positive).
	sort.SliceStable(anomalies, func(i, j int) bool {
		return math.Abs(anomalies[i].Score()) > math.Abs(anomalies[j].Score())
	})
	return anomalies, nil
}

func (d *BaselineDetector) make(key PairKey, count int, baselineMedian, score float64,
	direction string, daysSeen int, families map[string]string) *BaselineAnomaly {
	family, ok := families[key.Host]
	if !ok {
		family = "unknown"
	}
	return &BaselineAnomaly{
		host:           key.Host,
		program:        key.Program,
		Count:          count,
		BaselineMedian: baselineMedian,
		score:          score,
		Direction:      direction,
		DaysSeen:       daysSeen,
		exampleLine:    d.agg.Examples[key],
		osFamily:       family,
	}
}
