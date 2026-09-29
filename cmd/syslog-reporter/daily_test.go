package main

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// fakeDaily records every step daily drives; fetch writes a dump.
type fakeDaily struct {
	calls []string
}

func (f *fakeDaily) steps() dailySteps {
	return dailySteps{
		fetch: func(args []string) int {
			f.calls = append(f.calls, "fetch "+strings.Join(args, " "))
			os.WriteFile(args[len(args)-1], []byte("dump"), 0o644)
			return 0
		},
		run:    func(args []string) { f.calls = append(f.calls, "run "+strings.Join(args, " ")) },
		digest: func(args []string) { f.calls = append(f.calls, "digest "+strings.Join(args, " ")) },
	}
}

func (f *fakeDaily) names() string {
	var n []string
	for _, c := range f.calls {
		n = append(n, strings.Fields(c)[0])
	}
	return strings.Join(n, ",")
}

// dailyDir runs the test in a fresh working directory (the lock lives
// there) and returns the dump directory and yesterday's date.
func dailyDir(t *testing.T) (string, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	return "dumps", time.Now().AddDate(0, 0, -1).Format("2006-01-02")
}

func marker(dir, day, suffix string) string {
	return filepath.Join(dir, "syslog-"+day+suffix)
}

func TestDailyFirstAttemptFetchesRunsAndMarks(t *testing.T) {
	dir, day := dailyDir(t)
	f := &fakeDaily{}
	if code := runDaily([]string{"--dump-dir", dir}, f.steps()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if f.names() != "fetch,run" {
		t.Fatalf("calls %v", f.calls)
	}
	dump := marker(dir, day, ".ndjson.gz")
	if f.calls[0] != "fetch --day "+day+" --out "+dump {
		t.Errorf("fetch %q", f.calls[0])
	}
	if f.calls[1] != "run "+dump+" --date "+day+" --out-dir . --send-email" {
		t.Errorf("run %q", f.calls[1])
	}
	if !exists(marker(dir, day, ".sent")) {
		t.Error("no .sent marker")
	}
}

func TestDailyEmailModes(t *testing.T) {
	for _, c := range []struct {
		flag      string
		wantEmail bool
		wantCalls string
	}{
		{"--no-email", false, "fetch,run"},
		{"--digest", false, "fetch,run,digest"},
	} {
		t.Run(c.flag, func(t *testing.T) {
			dir, day := dailyDir(t)
			f := &fakeDaily{}
			if code := runDaily([]string{c.flag, "--dump-dir", dir}, f.steps()); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if f.names() != c.wantCalls {
				t.Fatalf("calls %v", f.calls)
			}
			if strings.Contains(f.calls[1], "--send-email") != c.wantEmail {
				t.Errorf("run %q", f.calls[1])
			}
			if c.flag == "--digest" {
				if f.calls[2] != "digest --days 7 --send-email --out-dir ." {
					t.Errorf("digest %q", f.calls[2])
				}
				if !exists(marker(dir, day, ".digest.sent")) {
					t.Error("no .digest.sent marker")
				}
			}
		})
	}
}

func TestDailyAlreadySentDoesNothing(t *testing.T) {
	dir, day := dailyDir(t)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(marker(dir, day, ".sent"), nil, 0o644)
	f := &fakeDaily{}
	if code := runDaily([]string{"--dump-dir", dir}, f.steps()); code != 0 || len(f.calls) != 0 {
		t.Errorf("exit %d, calls %v; want 0 and nothing run", code, f.calls)
	}
}

// A digest that failed after the day was filed is retried alone, without
// re-running (and re-paying for) the day.
func TestDailyRetriesOnlyAFailedDigest(t *testing.T) {
	dir, day := dailyDir(t)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(marker(dir, day, ".sent"), nil, 0o644)
	f := &fakeDaily{}
	if code := runDaily([]string{"--digest", "--dump-dir", dir}, f.steps()); code != 0 || f.names() != "digest" {
		t.Fatalf("exit %d, calls %v; want only the digest", code, f.calls)
	}
	if !exists(marker(dir, day, ".digest.sent")) {
		t.Error("no .digest.sent marker")
	}
}

func TestDailyExplicitDateIgnoresMarker(t *testing.T) {
	dir, _ := dailyDir(t)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(marker(dir, "2026-09-01", ".sent"), nil, 0o644)
	f := &fakeDaily{}
	if code := runDaily([]string{"--dump-dir", dir, "2026-09-01"}, f.steps()); code != 0 || f.names() != "fetch,run" {
		t.Errorf("exit %d, calls %v; want a full re-run", code, f.calls)
	}
}

func TestDailyRefusesDigestWithADate(t *testing.T) {
	dir, _ := dailyDir(t)
	f := &fakeDaily{}
	if code := runDaily([]string{"--digest", "--dump-dir", dir, "2026-09-01"}, f.steps()); code != 2 || len(f.calls) != 0 {
		t.Errorf("exit %d, calls %v; want 2 and nothing run", code, f.calls)
	}
}

// An existing non-empty dump is the escape hatch for sites without ELK;
// an empty one (a dead earlier fetch) is fetched again.
func TestDailyUsesAnExistingDump(t *testing.T) {
	dir, day := dailyDir(t)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(marker(dir, day, ".ndjson.gz"), []byte("already here"), 0o644)
	f := &fakeDaily{}
	runDaily([]string{"--no-email", "--dump-dir", dir}, f.steps())
	if f.names() != "run" {
		t.Errorf("calls %v; want no fetch", f.calls)
	}

	os.WriteFile(marker(dir, day, ".ndjson.gz"), nil, 0o644)
	os.Remove(marker(dir, day, ".sent"))
	f = &fakeDaily{}
	runDaily([]string{"--no-email", "--dump-dir", dir}, f.steps())
	if f.names() != "fetch,run" {
		t.Errorf("empty dump: calls %v; want a fetch", f.calls)
	}
}

func TestDailyFailedFetchStopsWithoutMarker(t *testing.T) {
	dir, day := dailyDir(t)
	f := &fakeDaily{}
	steps := f.steps()
	steps.fetch = func([]string) int { return 2 }
	if code := runDaily([]string{"--dump-dir", dir}, steps); code != 2 || len(f.calls) != 0 {
		t.Errorf("exit %d, calls %v; want the fetch's code and no run", code, f.calls)
	}
	if exists(marker(dir, day, ".sent")) {
		t.Error(".sent written after a failed fetch")
	}
}

func TestDailySecondConcurrentAttemptLeavesIt(t *testing.T) {
	dir, _ := dailyDir(t)
	unlock, held, err := lockDaily("daily-run.lock")
	if err != nil || held {
		t.Fatalf("taking the lock: held %v, %v", held, err)
	}
	defer unlock()
	f := &fakeDaily{}
	if code := runDaily([]string{"--dump-dir", dir}, f.steps()); code != 0 || len(f.calls) != 0 {
		t.Errorf("exit %d, calls %v; want 0 and nothing run while locked", code, f.calls)
	}
}

// The load-bearing one: a run that spends the day's LLM budget finishes
// degraded, returns normally, and so gets its .sent marker - otherwise
// the hourly retries would keep going (each refused, but each re-filing
// the day). Uses the real run against a stub model.
func TestDailyBudgetDegradedRunStillWritesMarker(t *testing.T) {
	fakeSpendingLLM(t) // 400 prompt tokens a request
	dir, day := dailyDir(t)
	t.Setenv("SYSLOG_MAX_PROMPT_TOKENS", "1")
	t.Setenv("SYSLOG_DEFAULT_MODEL", "openai/test-model")
	t.Setenv("SYSLOG_LOGSCAN_MODEL", "")
	t.Setenv("SYSLOG_ISSUE_MODEL", "")
	t.Setenv("SYSLOG_DB_PATH", "syslog.db")
	os.MkdirAll(dir, 0o755)
	writeGzipNDJSON(t, marker(dir, day, ".ndjson.gz"), day)
	// An earlier attempt today already spent the budget, so this one's
	// first request is refused.
	lib, err := reporter.OpenLibraryStore("syslog.db")
	if err != nil {
		t.Fatal(err)
	}
	lib.AddPromptTokens(time.Now(), 5)
	lib.Close()

	steps := dailyDefaultSteps
	steps.fetch = func([]string) int { t.Error("fetch called with a dump present"); return 2 }
	if code := runDaily([]string{"--no-email", "--dump-dir", dir}, steps); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !llm.BudgetReached() {
		t.Fatal("the run never hit the budget; the test proves nothing")
	}
	if !exists(marker(dir, day, ".sent")) {
		t.Error("no .sent marker after a budget-degraded run")
	}
}

func writeGzipNDJSON(t *testing.T, path, day string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	for i := 0; i < 3; i++ {
		gz.Write([]byte(`{"@timestamp":"` + day + `T10:00:0` + string(rune('0'+i)) + `Z","host.name":"web01","process.name":"app","message":"error: disk full ` + string(rune('a'+i)) + `"}` + "\n"))
	}
	gz.Close()
}
