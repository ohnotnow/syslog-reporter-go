package reporter

// Port of tests/test_baseline_agent.py from the Python original.

import (
	"strings"
	"testing"
)

// A fortnight of slightly-jittery history around ~500/day. Real series always
// jitter, which is what gives MAD something to work with (a perfectly flat
// history has MAD 0 and RobustZ reports "nothing to see").
var baselineHistory = []int{500, 510, 490, 505, 495, 515, 485, 520, 480, 502}

var baselineToday = day(2026, 6, 13)

func seedBaseline(t *testing.T, s *AggregateStore, host, program string, values []int) {
	t.Helper()
	for i, n := range values {
		mustWrite(t, s, day(2026, 6, 1+i), singleCount(host, program, "00:00", n))
	}
}

// todayAggregate builds the Aggregate for a single series today; n < 0 means
// no data at all for the host today (the "gone silent" case).
func todayAggregate(host, program string, n int) *Aggregate {
	counts := NewCounts()
	if n >= 0 {
		counts.Add(AggKey{host, program, "00:00"}, n)
	}
	return &Aggregate{
		Counts:       counts,
		Examples:     map[PairKey]string{{host, program}: "Jun 13 00:00:00 " + host + " " + program + "[1]: today"},
		HostPrograms: map[string]map[string]struct{}{host: {program: {}}},
	}
}

func TestBaselineFlagsAHostGoneLoud(t *testing.T) {
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", baselineHistory)
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", 6000), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anomalies))
	}
	a := anomalies[0].(*BaselineAnomaly)
	if a.Direction != "louder" || a.Count != 6000 {
		t.Errorf("got %+v", a)
	}
	if a.Score() <= 3.5 {
		t.Errorf("score = %v, want > 3.5", a.Score())
	}
	if a.DaysSeen != len(baselineHistory) {
		t.Errorf("days seen = %d, want %d", a.DaysSeen, len(baselineHistory))
	}
	if !strings.Contains(a.Headline(), "Louder") {
		t.Errorf("headline = %q", a.Headline())
	}
}

func TestBaselineFlagsAHostGoneSilent(t *testing.T) {
	// No data for boxA today at all: it has gone silent vs its own normal.
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", baselineHistory)
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", -1), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anomalies))
	}
	a := anomalies[0].(*BaselineAnomaly)
	if a.Direction != "silent" || a.Count != 0 {
		t.Errorf("got %+v", a)
	}
	if a.Headline() != "Gone silent" {
		t.Errorf("headline = %q", a.Headline())
	}
	if !strings.Contains(strings.ToLower(a.Summary()), "gone silent") {
		t.Errorf("summary = %q", a.Summary())
	}
}

func TestBaselineFlagsAHostGoneQuiet(t *testing.T) {
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", baselineHistory)
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", 40), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 || anomalies[0].(*BaselineAnomaly).Direction != "quieter" {
		t.Fatalf("got %+v", anomalies)
	}
	if anomalies[0].Score() >= -3.5 {
		t.Errorf("score = %v, want < -3.5", anomalies[0].Score())
	}
}

func TestBaselineStableHostIsNotFlagged(t *testing.T) {
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", baselineHistory)
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", 503), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 { // bang on its normal
		t.Errorf("got %+v, want none", anomalies)
	}
}

func TestBaselineInsufficientHistoryIsNotScored(t *testing.T) {
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", baselineHistory[:3]) // only 3 days
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", 6000), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 {
		t.Errorf("got %+v, want none", anomalies)
	}
}

func TestBaselineTinySeriesBelowMinBaselineIgnored(t *testing.T) {
	s := newTestStore(t)
	seedBaseline(t, s, "boxA", "puppet", []int{2, 3, 1, 2, 4, 2, 3, 1, 2, 3}) // trivial volume
	anomalies, err := NewBaselineDetector(todayAggregate("boxA", "puppet", 40), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 { // "spike" but still tiny
		t.Errorf("got %+v, want none", anomalies)
	}
}
