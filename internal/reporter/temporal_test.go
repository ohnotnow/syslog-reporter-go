package reporter

// Tests for the temporal burst detector: same-window comparison,
// seasonality, and the history thresholds.

import (
	"strings"
	"testing"
)

// ~30 events in the 10:00 window every day: think a lab's morning reboot
// churn. This is exactly the "expected seasonality" the spike got swamped by.
var temporalHistory = []int{28, 32, 30, 29, 31, 27, 33, 30, 28, 32}

const temporalWindow = "10:00"

func seedTemporal(t *testing.T, s *AggregateStore, values []int) {
	t.Helper()
	for i, n := range values {
		mustWrite(t, s, day(2026, 6, 1+i), singleCount("lab1", "kernel", temporalWindow, n))
	}
}

func temporalTodayAggregate(n int) *Aggregate {
	counts := map[AggKey]int{{"lab1", "kernel", temporalWindow}: n}
	return &Aggregate{
		Counts:       counts,
		Examples:     map[PairKey]string{{"lab1", "kernel"}: "Jun 13 10:00:00 lab1 kernel: boot"},
		HostPrograms: map[string]map[string]struct{}{"lab1": {"kernel": {}}},
	}
}

func TestTemporalFlagsAGenuineBurst(t *testing.T) {
	s := newTestStore(t)
	seedTemporal(t, s, temporalHistory)
	anomalies, err := NewTemporalDetector(temporalTodayAggregate(2000), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anomalies))
	}
	a := anomalies[0].(*TemporalAnomaly)
	if a.Window != temporalWindow || a.Count != 2000 {
		t.Errorf("got %+v", a)
	}
	if a.Score() <= 3.5 {
		t.Errorf("score = %v, want > 3.5", a.Score())
	}
	if !strings.Contains(a.Headline(), "10:00") {
		t.Errorf("headline = %q", a.Headline())
	}
}

func TestTemporalRoutineMorningVolumeIsNotFlagged(t *testing.T) {
	// 32 events at 10:00 is bang-on normal FOR 10:00; comparing like with
	// like is the whole point. This must NOT flag, even though 10:00 is a
	// busy time of day in absolute terms.
	s := newTestStore(t)
	seedTemporal(t, s, temporalHistory)
	anomalies, err := NewTemporalDetector(temporalTodayAggregate(32), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 {
		t.Errorf("got %+v, want none", anomalies)
	}
}

func TestTemporalQuietWindowBelowMinCountIgnored(t *testing.T) {
	s := newTestStore(t)
	seedTemporal(t, s, temporalHistory)
	anomalies, err := NewTemporalDetector(temporalTodayAggregate(10), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 { // below MinCount
		t.Errorf("got %+v, want none", anomalies)
	}
}

func TestTemporalInsufficientHistoryIsNotScored(t *testing.T) {
	s := newTestStore(t)
	seedTemporal(t, s, temporalHistory[:3])
	anomalies, err := NewTemporalDetector(temporalTodayAggregate(2000), s, baselineToday).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 {
		t.Errorf("got %+v, want none", anomalies)
	}
}
