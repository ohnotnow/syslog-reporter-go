package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// SYSLOG_DIGEST_MODEL > SYSLOG_ISSUE_MODEL > --model (srg-xiBoC.7), so the
// .env can hold cheap daily models and one smart weekly one.
func TestDigestModelPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, digest, issue, fallback, want string
	}{
		{"fallback only", "", "", "openai/flag", "openai/flag"},
		{"issue model wins over fallback", "", "openai/issue", "openai/flag", "openai/issue"},
		{"digest model wins over both", "openai/smart", "openai/issue", "openai/flag", "openai/smart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYSLOG_DIGEST_MODEL", tc.digest)
			t.Setenv("SYSLOG_ISSUE_MODEL", tc.issue)
			if got := digestModel(tc.fallback); got != tc.want {
				t.Errorf("digestModel = %q, want %q", got, tc.want)
			}
		})
	}
}

// seedDailyRuns files a recurring issue on the last three days (ending
// yesterday, the digest's anchor) into a fresh library at path.
func seedDailyRuns(t *testing.T, path string) {
	t.Helper()
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	for back := 3; back >= 1; back-- {
		day := time.Now().AddDate(0, 0, -back)
		issue := &reporter.Issue{
			Issue: "SSH brute force", Severity: "high",
			Description:     "Repeated failed logins.",
			ExampleLogEntry: "web01.example.test sshd[1]: Failed password for root",
			AffectedHost:    []string{"web01.example.test"}, AffectedService: "sshd",
			RecommendedAction: "Disable password auth.",
		}
		anomaly := &reporter.ExplainedAnomaly{Host: "db01.example.test", Program: "postgres",
			Kind: "baseline", Headline: "Louder than usual", Detail: "900 lines vs baseline 40"}
		if err := reporter.CaptureRun(lib, day, reporter.RunKindDaily, "cheap/model", 100, 10,
			&reporter.IssueList{Issues: []*reporter.Issue{issue}}, nil,
			[]*reporter.ExplainedAnomaly{anomaly}); err != nil {
			t.Fatal(err)
		}
	}
}

func runDigestCommand(t *testing.T, args ...string) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := dispatch(append([]string{"digest"}, args...), io.Discard, io.Discard)
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

// A --no-llm digest over a seeded library files a digest run under the
// window's end day, prints the digest findings' ids (not the daily ones),
// and drops both files in --out-dir.
func TestDigestFilesARunAndWritesFiles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "library.db")
	seedDailyRuns(t, dbPath)
	outDir := t.TempDir()

	body, code := runDigestCommand(t, "--no-llm", "--db", dbPath, "--out-dir", outDir)
	if code != 0 {
		t.Fatalf("digest exit %d", code)
	}
	for _, name := range []string{"digest_body.md", "digest_attachment.md"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	for _, want := range []string{
		"# Syslog weekly digest - ",
		"Covers 3 daily runs. No run was recorded for ",
		"## 1. SSH brute force\n",
		"**Seen on 3 of 3 run days: ",
		"### db01.example.test / postgres",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}

	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	digests, err := lib.SearchFindings(reporter.FindingFilter{RunKind: reporter.RunKindDigest, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(digests) != 2 {
		t.Fatalf("digest findings = %d, want the issue group and the anomaly group", len(digests))
	}
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	for _, f := range digests {
		if f.LogDate != yesterday {
			t.Errorf("digest finding dated %s, want the window end %s", f.LogDate, yesterday)
		}
		// Issues print a Finding tag, anomalies an id in their heading;
		// both print the paste-ready mute line.
		if !strings.Contains(body, "syslog-mute "+itoa(f.ID)+" ") {
			t.Errorf("body does not print a mute line for digest finding #%d:\n%s", f.ID, body)
		}
	}
	dailies, err := lib.SearchFindings(reporter.FindingFilter{RunKind: reporter.RunKindDaily, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(dailies) != 6 {
		t.Errorf("daily findings = %d, want the 6 seeded ones untouched", len(dailies))
	}

	// Re-running replaces the digest, never the dailies.
	if _, code := runDigestCommand(t, "--no-llm", "--db", dbPath, "--out-dir", outDir); code != 0 {
		t.Fatalf("second digest exit %d", code)
	}
	runs, err := lib.ListRuns("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 4 {
		t.Errorf("runs after re-run = %d, want 3 daily + 1 digest", len(runs))
	}
}

// --no-store renders without ids or mute lines and files nothing.
func TestDigestNoStoreHasNoIDs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "library.db")
	seedDailyRuns(t, dbPath)
	body, code := runDigestCommand(t, "--no-llm", "--no-store", "--db", dbPath, "--out-dir", t.TempDir())
	if code != 0 {
		t.Fatalf("digest exit %d", code)
	}
	if strings.Contains(body, "**Finding:**") || strings.Contains(body, "syslog-mute") {
		t.Errorf("--no-store body carries ids:\n%s", body)
	}
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	runs, err := lib.ListRuns("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Errorf("runs = %d, want only the 3 seeded dailies", len(runs))
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
