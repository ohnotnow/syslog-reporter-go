package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// A day that could not be filed must come back as an error, so run fails
// after writing and sending its report and daily's hourly retry refiles
// it; before ait srg-6Vsgx.2 it was a warning and the day counted as done.
func TestCaptureDailyReportsAFailedFiling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog.db")
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	lib.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER refuse BEFORE INSERT ON runs BEGIN SELECT RAISE(ABORT, 'disk says no'); END`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	day := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	err = captureDaily(&logger{}, path, day, "", 10, 5, &reporter.IssueList{}, &reporter.ResolutionList{}, nil)
	if err == nil || !strings.Contains(err.Error(), "disk says no") {
		t.Errorf("err %v, want the capture failure", err)
	}
}

func TestCaptureDailyFilesTheDay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog.db")
	day := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	if err := captureDaily(&logger{}, path, day, "m", 10, 5, &reporter.IssueList{}, &reporter.ResolutionList{}, nil); err != nil {
		t.Fatal(err)
	}
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	if runs, err := lib.ListRuns("2026-09-28", "2026-09-28"); err != nil || len(runs) != 1 {
		t.Errorf("runs %v, %v; want the day filed once", runs, err)
	}
}
