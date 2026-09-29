package main

// The backfill command (ait srg-Sm1Is.3): run the last N days through the
// pipeline with --no-llm, so it costs nothing, to give a fresh install the
// history two of the three anomaly detectors compare against.
//
// Unlike daily, each day's run is a child process of this same binary:
// run fails through fatal() -> os.Exit(1), and a backfill must carry on
// past a bad day. The fetch stays in-process; it returns its errors.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// backfillSteps are the pieces backfill drives; tests swap them for fakes.
type backfillSteps struct {
	fetch  func(args []string) int // runFetch's exit code
	runDay func(ctx context.Context, dump, day string) error
}

var backfillDefaultSteps = backfillSteps{
	fetch:  func(args []string) int { return runFetch(args, os.Stderr) },
	runDay: runDayInChild,
}

func cmdBackfill(args []string) int {
	return runBackfill(args, backfillDefaultSteps)
}

func runBackfill(args []string, steps backfillSteps) int {
	fs := flag.NewFlagSet("backfill", flag.ExitOnError)
	setUsage(fs, backfillHelpIntro, "")
	days := fs.Int("days", 14, "How many days to backfill, ending yesterday")
	dumpDir := fs.String("dump-dir", defaultDumpDir(), "Where the per-day dumps live (missing ones are fetched)")
	fs.Parse(args)
	if fs.NArg() > 0 || *days < 1 {
		fmt.Fprintln(os.Stderr, "usage: syslog-reporter backfill [--days N] [--dump-dir DIR] (N at least 1)")
		return 2
	}
	if err := os.MkdirAll(*dumpDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-reporter backfill: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Oldest first, so each day's detectors see the history built before it.
	failures := 0
	for i := *days; i >= 1; i-- {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "backfill interrupted")
			return 1
		}
		day := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		dump := filepath.Join(*dumpDir, "syslog-"+day+".ndjson.gz")
		if info, err := os.Stat(dump); err != nil || info.Size() == 0 {
			fmt.Printf("== %s: fetching from ELK\n", day)
			if steps.fetch([]string{"--day", day, "--out", dump}) != 0 {
				fmt.Fprintf(os.Stderr, "WARN: %s: dump failed, skipping\n", day)
				failures++
				continue
			}
		}
		fmt.Printf("== %s: running (no LLM)\n", day)
		if err := steps.runDay(ctx, dump, day); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: %s: run failed: %v\n", day, err)
			failures++
		}
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "backfill finished with %d failed day(s)\n", failures)
		return 1
	}
	fmt.Printf("backfill complete: %d day(s) of history stored\n", *days)
	return 0
}

// runDayInChild runs one day's free pipeline as a child of this binary,
// sharing stdout and stderr; Ctrl-C or SIGTERM stops the child too.
func runDayInChild(ctx context.Context, dump, day string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, self, "run", dump, "--date", day, "--no-llm")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	return cmd.Run()
}
