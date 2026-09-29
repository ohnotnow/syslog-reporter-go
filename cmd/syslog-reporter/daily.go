package main

// The daily command (ait srg-Sm1Is.2), shaped for an hourly cron: fetch
// yesterday's dump, run the pipeline, then email the day's report, say
// nothing, or email the weekly digest instead. It replaced
// scripts/daily-run.sh.
//
// The first attempt that gets all the way through leaves a
// syslog-<day>.sent marker in the dump directory (and, with --digest, a
// syslog-<day>.digest.sent once the digest went out); every later attempt
// that day exits 0 without a word. Each marker is written after its own
// step succeeds. run and digest are called in-process and fail through
// fatal() -> os.Exit(1), so a failed step ends the process before its
// marker and the next hourly attempt retries. A run that spends the day's
// LLM budget finishes degraded rather than failing, so its marker is
// written and the retries stop.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// dailySteps are the pieces daily drives; tests swap them for fakes.
type dailySteps struct {
	fetch  func(args []string) int // runFetch's exit code
	run    func(args []string)     // exits the process on failure
	digest func(args []string)     // exits the process on failure
}

var dailyDefaultSteps = dailySteps{
	fetch:  func(args []string) int { return runFetch(args, os.Stderr) },
	run:    runBatch,
	digest: runDigest,
}

func cmdDaily(args []string) int {
	return runDaily(args, dailyDefaultSteps)
}

func runDaily(args []string, steps dailySteps) int {
	fs := flag.NewFlagSet("daily", flag.ExitOnError)
	setUsage(fs, dailyHelpIntro, "")
	noEmail := fs.Bool("no-email", false, "Run and file the day without emailing anyone")
	digest := fs.Bool("digest", false, "Run and file the day, then email the weekly digest instead of the day's report")
	dumpDir := fs.String("dump-dir", defaultDumpDir(), "Where the per-day dumps and .sent markers live")
	outDir := fs.String("out-dir", ".", "Where the report and digest files are written")
	digestDays := fs.Int("digest-days", 7, "Days the --digest covers, ending yesterday")
	fs.Parse(args)
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "syslog-reporter daily: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 1 {
		return fail("usage: syslog-reporter daily [--no-email] [--digest] [YYYY-MM-DD]")
	}
	explicit := fs.NArg() == 1
	if *digest && explicit {
		return fail("--digest takes no date (the window always ends yesterday); re-run the day alone, then: syslog-reporter digest --days N --send-email")
	}
	if *digestDays < 1 {
		return fail("--digest-days must be at least 1")
	}
	day := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	if explicit {
		day = fs.Arg(0)
		if _, err := time.Parse("2006-01-02", day); err != nil {
			return fail("the date must be YYYY-MM-DD, got %q", day)
		}
	}

	unlock, held, err := lockDaily("daily-run.lock")
	if err != nil {
		return fail("%v", err)
	}
	if held {
		abs, _ := filepath.Abs("daily-run.lock")
		fmt.Printf("another daily run is still going (lock: %s; find the holder with: fuser -v %s); leaving it to finish\n", abs, abs)
		return 0
	}
	defer unlock()

	dump := filepath.Join(*dumpDir, "syslog-"+day+".ndjson.gz")
	sent := filepath.Join(*dumpDir, "syslog-"+day+".sent")
	digestSent := filepath.Join(*dumpDir, "syslog-"+day+".digest.sent")
	digestArgs := []string{"--days", fmt.Sprint(*digestDays), "--send-email", "--out-dir", *outDir}

	// Already done today: the hourly retries have nothing to do, except a
	// digest that failed, which is retried on its own without re-running
	// (and re-paying for) the day.
	if !explicit && exists(sent) {
		if !*digest || exists(digestSent) {
			return 0
		}
		steps.digest(digestArgs)
		return touch(digestSent)
	}

	if err := os.MkdirAll(*dumpDir, 0o755); err != nil {
		return fail("%v", err)
	}
	if info, err := os.Stat(dump); err != nil || info.Size() == 0 {
		if code := steps.fetch([]string{"--day", day, "--out", dump}); code != 0 {
			return code
		}
	}

	runArgs := []string{dump, "--date", day, "--out-dir", *outDir}
	if !*noEmail && !*digest {
		runArgs = append(runArgs, "--send-email")
	}
	steps.run(runArgs)
	if code := touch(sent); code != 0 {
		return code
	}
	if *digest {
		steps.digest(digestArgs)
		return touch(digestSent)
	}
	return 0
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// touch creates an empty marker file, returning a non-zero exit code if it
// cannot: a missing marker means the next hourly attempt repeats the step.
func touch(path string) int {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-reporter daily: writing marker: %v\n", err)
		return 1
	}
	f.Close()
	return 0
}
