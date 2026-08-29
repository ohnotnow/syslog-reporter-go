package reporter

// Tests for the daily aggregate store: write/read-back, per-day
// idempotency, window bounds, and pruning.

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

func mustWrite(t *testing.T, s *AggregateStore, d time.Time, c map[AggKey]int) {
	t.Helper()
	if _, err := s.WriteAggregates(d, c); err != nil {
		t.Fatalf("write aggregates: %v", err)
	}
}

func singleCount(host, program, window string, n int) map[AggKey]int {
	return map[AggKey]int{{host, program, window}: n}
}

func TestStoreWriteAndReadBackPairTotals(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 1), map[AggKey]int{
		{"hostA", "puppet", "00:00"}: 100,
		{"hostA", "puppet", "00:10"}: 50, // same series, different window
		{"hostB", "sshd", "09:00"}:   7,
	})

	// beforeDate excludes the day itself, so query a later day
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	got := totals[PairKey{"hostA", "puppet"}]
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 150}) { // windows summed
		t.Errorf("hostA/puppet = %#v", got)
	}
	got = totals[PairKey{"hostB", "sshd"}]
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
	got := totals[PairKey{"hostA", "puppet"}]
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 100}) { // not doubled
		t.Errorf("got %#v", got)
	}
}

func TestStoreRewriteWithFewerKeysDropsStaleRows(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 1), map[AggKey]int{
		{"hostA", "puppet", "00:00"}: 100,
		{"hostA", "cron", "01:00"}:   40,
	})
	// The re-run of the day no longer sees the cron series; its old row
	// must not survive to contaminate the baseline.
	mustWrite(t, s, day(2026, 6, 1), singleCount("hostA", "puppet", "00:00", 80))
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := totals[PairKey{"hostA", "cron"}]; ok {
		t.Error("stale cron row survived the day's rewrite")
	}
	got := totals[PairKey{"hostA", "puppet"}]
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 80}) {
		t.Errorf("puppet = %#v, want the re-run's value", got)
	}
}

func TestStoreBeforeDateIsExcludedFromHistory(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 5), singleCount("h", "p", "00:00", 99))
	totals, err := s.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := totals[PairKey{"h", "p"}]; ok {
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
	got := totals[PairKey{"h", "p"}]
	if !reflect.DeepEqual(got, map[string]int{"2026-06-04": 2}) {
		t.Errorf("got %#v", got)
	}
}

func TestStoreWindowCountsKeepTheWindow(t *testing.T) {
	s := newTestStore(t)
	mustWrite(t, s, day(2026, 6, 1), map[AggKey]int{
		{"h", "p", "10:00"}: 30,
		{"h", "p", "11:00"}: 5,
	})

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
	if len(totals) != 0 {
		t.Errorf("expected empty history, got %v", totals)
	}
}
