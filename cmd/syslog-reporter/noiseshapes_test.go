package main

// The run's noise-shape step (ait srg-OymJL.2). Fictional hosts only.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

var noiseDay = time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)

// storedShapes reads the pool back, keyed by program.
func storedShapes(t *testing.T, path string) map[string]reporter.NoiseShape {
	t.Helper()
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	got, err := lib.SampleNoiseShapes(1000, time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]reporter.NoiseShape{}
	for _, sh := range got {
		out[sh.Program] = sh
	}
	return out
}

func TestStoreNoiseShapesFilesTheDaysShapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog.db")
	storeNoiseShapes(&logger{}, path, noiseDay, discoverDays["2026-09-15"])
	got := storedShapes(t, path)
	fw, kern := got["fwupd"], got["kernel"]
	if len(got) != 2 || fw.Lines != 2 || fw.Hosts != 2 || kern.Lines != 1 || kern.Hosts != 1 {
		t.Fatalf("pool = %+v", got)
	}
	if kern.ExampleHost != "db01.example.test" || kern.Example != "kernel: EXT4-fs error (device sda1): bad block 77" {
		t.Errorf("kernel example = %q on %q", kern.Example, kern.ExampleHost)
	}
	if !fw.Day.Equal(noiseDay) {
		t.Errorf("day = %v", fw.Day)
	}

	// Same date again replaces the pool; an older date leaves it.
	storeNoiseShapes(&logger{}, path, noiseDay, discoverDays["2026-09-17"])
	if got := storedShapes(t, path); len(got) != 2 || got["motd-news"].Lines != 1 || got["kernel"].Program != "" {
		t.Errorf("same-day rerun should replace: %+v", got)
	}
	storeNoiseShapes(&logger{}, path, noiseDay.AddDate(0, 0, -1), discoverDays["2026-09-16"])
	if got := storedShapes(t, path); got["kernel"].Program != "" {
		t.Errorf("an older day replaced the pool: %+v", got)
	}
}

// A failed write only warns: the function has no error to return, and the
// pool is simply left empty.
func TestStoreNoiseShapesFailureOnlyWarns(t *testing.T) {
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
	if _, err := db.Exec(`CREATE TRIGGER refuse BEFORE INSERT ON noise_shapes BEGIN SELECT RAISE(ABORT, 'disk says no'); END`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	storeNoiseShapes(&logger{}, path, noiseDay, discoverDays["2026-09-15"])
	if got := storedShapes(t, path); len(got) != 0 {
		t.Errorf("pool = %+v, want empty after the refused write", got)
	}
}

// The run writes shapes only when it stores: not with --no-store, and not
// with --dump-filtered, which returns before the step.
func TestRunWritesNoiseShapesOnlyWhenStoring(t *testing.T) {
	for _, tc := range []struct {
		name              string
		storeOn, dumpOnly bool
		want              int
	}{
		{"store", true, false, 2},
		{"no-store", false, false, 0},
		{"dump-filtered", true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "syslog.db")
			if tc.dumpOnly {
				devnull, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				stdout := os.Stdout
				os.Stdout = devnull
				t.Cleanup(func() { os.Stdout = stdout; devnull.Close() })
			}
			run(runConfig{lines: discoverDays["2026-09-15"], dbPath: path, storeOn: tc.storeOn,
				dumpOnly: tc.dumpOnly, outDir: dir, logDate: noiseDay, keepDays: reporter.DefaultKeepDays})
			if got := storedShapes(t, path); len(got) != tc.want {
				t.Errorf("%d shapes stored, want %d", len(got), tc.want)
			}
		})
	}
}
