package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeBackfill struct {
	fetched, ran []string
	failFetch    map[string]bool
	failRun      map[string]bool
}

func (f *fakeBackfill) steps() backfillSteps {
	return backfillSteps{
		fetch: func(args []string) int {
			day, out := args[1], args[3]
			f.fetched = append(f.fetched, day)
			if f.failFetch[day] {
				return 2
			}
			os.WriteFile(out, []byte("dump"), 0o644)
			return 0
		},
		runDay: func(_ context.Context, dump, day string) error {
			f.ran = append(f.ran, day)
			if f.failRun[day] {
				return errors.New("exit status 1")
			}
			return nil
		},
	}
}

func daysAgo(n int) string { return time.Now().AddDate(0, 0, -n).Format("2006-01-02") }

func TestBackfillRunsOldestFirstEndingYesterday(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBackfill{}
	if code := runBackfill([]string{"--days", "3", "--dump-dir", dir}, f.steps()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := []string{daysAgo(3), daysAgo(2), daysAgo(1)}
	if len(f.ran) != 3 || f.ran[0] != want[0] || f.ran[2] != want[2] {
		t.Errorf("ran %v, want %v", f.ran, want)
	}
}

func TestBackfillFetchesOnlyMissingDumps(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "syslog-"+daysAgo(2)+".ndjson.gz"), []byte("have it"), 0o644)
	f := &fakeBackfill{}
	runBackfill([]string{"--days", "2", "--dump-dir", dir}, f.steps())
	if len(f.fetched) != 1 || f.fetched[0] != daysAgo(1) {
		t.Errorf("fetched %v, want only %s", f.fetched, daysAgo(1))
	}
}

func TestBackfillCarriesOnPastFailedDays(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBackfill{failFetch: map[string]bool{daysAgo(3): true}, failRun: map[string]bool{daysAgo(2): true}}
	if code := runBackfill([]string{"--days", "3", "--dump-dir", dir}, f.steps()); code != 1 {
		t.Errorf("exit %d, want 1 with failures", code)
	}
	// Day 3's fetch failed, so it never ran; days 2 and 1 both ran.
	if len(f.ran) != 2 || f.ran[0] != daysAgo(2) || f.ran[1] != daysAgo(1) {
		t.Errorf("ran %v", f.ran)
	}
}

func TestBackfillRefusesZeroDays(t *testing.T) {
	f := &fakeBackfill{}
	if code := runBackfill([]string{"--days", "0", "--dump-dir", t.TempDir()}, f.steps()); code != 2 || len(f.ran) != 0 {
		t.Errorf("exit %d, ran %v", code, f.ran)
	}
}
