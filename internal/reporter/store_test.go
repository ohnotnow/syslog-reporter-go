package reporter

// Port of tests/test_aggregate_store.py from the Python original.

import (
	"reflect"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *AggregateStore {
	t.Helper()
	s, err := OpenAggregateStore(":memory:")
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func countsOf(t *testing.T, entries map[AggKey]int, order ...AggKey) *Counts {
	t.Helper()
	c := NewCounts()
	for _, k := range order {
		c.Add(k, entries[k])
	}
	return c
}

func mustWrite(t *testing.T, s *AggregateStore, d time.Time, c *Counts) {
	t.Helper()
	if _, err := s.WriteAggregates(d, c); err != nil {
		t.Fatalf("write aggregates: %v", err)
	}
}

func singleCount(host, program, window string, n int) *Counts {
	c := NewCounts()
	c.Add(AggKey{host, program, window}, n)
	return c
}

func TestStoreWriteAndReadBackPairTotals(t *testing.T) {
	s := newTestStore(t)
	c := NewCounts()
	c.Add(AggKey{"hostA", "puppet", "00:00"}, 100)
	c.Add(AggKey{"hostA", "puppet", "00:10"}, 50) // same series, different window
	c.Add(AggKey{"hostB", "sshd", "09:00"}, 7)
	mustWrite(t, s, day(2026, 6, 1), c)

	// beforeDate excludes the day itself, so query a later day
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := totals.Get(PairKey{"hostA", "puppet"})
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 150}) { // windows summed
		t.Errorf("hostA/puppet = %#v", got)
	}
	got, _ = totals.Get(PairKey{"hostB", "sshd"})
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 7}) {
		t.Errorf("hostB/sshd = %#v", got)
	}
}

func TestStoreRewriteIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 1), singleCount("hostA", "puppet", "00:00", 100))
	mustWrite(t, s, day(2026, 6, 1), singleCount("hostA", "puppet", "00:00", 100)) // re-run same day
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := totals.Get(PairKey{"hostA", "puppet"})
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 100}) { // not doubled
		t.Errorf("got %#v", got)
	}
}

func TestStoreBeforeDateIsExcludedFromHistory(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 5), singleCount("h", "p", "00:00", 99))
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := totals.Get(PairKey{"h", "p"}); ok {
		t.Error("the queried day must not sit in its own history")
	}
}

func TestStoreLookbackWindowBounds(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 5, 1), singleCount("h", "p", "00:00", 1)) // too old
	mustWrite(t, s, day(2026, 6, 4), singleCount("h", "p", "00:00", 2)) // in window
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := totals.Get(PairKey{"h", "p"})
	if !reflect.DeepEqual(got, map[string]int{"2026-06-04": 2}) {
		t.Errorf("got %#v", got)
	}
}

func TestStoreWindowCountsKeepTheWindow(t *testing.T) {
	s := newTestStore(t)
	c := NewCounts()
	c.Add(AggKey{"h", "p", "10:00"}, 30)
	c.Add(AggKey{"h", "p", "11:00"}, 5)
	mustWrite(t, s, day(2026, 6, 1), c)

	wins, err := s.HistoryWindowCounts(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wins[AggKey{"h", "p", "10:00"}], map[string]int{"2026-06-01": 30}) {
		t.Errorf("10:00 = %#v", wins[AggKey{"h", "p", "10:00"}])
	}
	if !reflect.DeepEqual(wins[AggKey{"h", "p", "11:00"}], map[string]int{"2026-06-01": 5}) {
		t.Errorf("11:00 = %#v", wins[AggKey{"h", "p", "11:00"}])
	}
}

func TestStorePruneDropsOldRows(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2000, 1, 1), singleCount("h", "p", "00:00", 1))
	removed, err := s.Prune(30)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	totals, err := s.HistoryPairTotals(day(2000, 2, 1), 999)
	if err != nil {
		t.Fatal(err)
	}
	if len(totals.Keys()) != 0 {
		t.Errorf("expected empty history, got %v", totals.Keys())
	}
}
