package cli

// Tests for the findings CLI (ait srg-2KY5X.8). Fictional hostnames only.

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// seedLibrary builds a temp db with two runs: run1 (2026-06-01) holds an
// issue finding (hostA, hostB) with a resolution; run2 (2026-06-02) holds a
// peer anomaly (hostC). Returns the db path and the two finding ids.
func seedLibrary(t *testing.T) (dbPath string, issueID, anomID int64) {
	t.Helper()
	dbPath = filepath.Join(t.TempDir(), "cli.db")
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	run1, err := lib.BeginRun(day(2026, 6, 1), "openai/gpt-test")
	if err != nil {
		t.Fatal(err)
	}
	run2, err := lib.BeginRun(day(2026, 6, 2), "")
	if err != nil {
		t.Fatal(err)
	}
	issue := reporter.IssuePayload{
		Issue: reporter.Issue{
			Issue: "Disk filling on /var", Severity: "high",
			Description:     "Log partition at 92% and climbing.",
			ExampleLogEntry: "hostA kernel: VFS: file-max limit reached",
			AffectedHost:    []string{"hostA", "hostB"}, AffectedService: "kernel",
			TimestampFrequency: "hourly since 03:00",
			PotentialImpact:    "Service outage when the partition fills.",
			RecommendedAction:  "Rotate and compress old logs.",
		},
		Resolution: &reporter.Resolution{
			Issue: "Disk filling on /var", RootCause: "logrotate unit disabled",
			Investigate: "df -h /var",
			FixCommands: []string{"systemctl enable --now logrotate.timer"},
		},
	}
	issueID, err = lib.AddFinding(run1, "issue", "high", issue.Issue.Issue,
		issue.AffectedService, issue.AffectedHost, issue)
	if err != nil {
		t.Fatal(err)
	}
	anom := &reporter.ExplainedAnomaly{
		Host: "hostC", Program: "sshd", Kind: "peer",
		Headline: "Chattier than its peers", Detail: "480 lines vs peer median 12",
		OSFamily: "debian", LikelyCauses: "Credential scanning.",
		SuggestedCommands: []string{"lastb | head"},
	}
	anomID, err = lib.AddFinding(run2, anom.Kind, "", anom.Headline,
		anom.Program, []string{anom.Host}, anom)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.CreateUser("opsuser", "opsuser@example.test", "hash"); err != nil {
		t.Fatal(err)
	}
	return dbPath, issueID, anomID
}

func run(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := RunFindings(dbPath, args, &out)
	return out.String(), err
}

func mustRun(t *testing.T, dbPath string, args ...string) string {
	t.Helper()
	out, err := run(t, dbPath, args...)
	if err != nil {
		t.Fatalf("findings %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// listedTitles pulls the TITLE-adjacent check down to which findings appear.
func assertLists(t *testing.T, out string, want, dontWant []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("list output missing %q:\n%s", w, out)
		}
	}
	for _, d := range dontWant {
		if strings.Contains(out, d) {
			t.Errorf("list output should not contain %q:\n%s", d, out)
		}
	}
}

func TestListFiltersMatchStoreSemantics(t *testing.T) {
	dbPath, _, _ := seedLibrary(t)
	issue, anomaly := "Disk filling on /var", "Chattier than its peers"

	assertLists(t, mustRun(t, dbPath, "list"), []string{issue, anomaly, "worked 0 / didnt 0"}, nil)
	// Host and service are substring matches, like the web.
	assertLists(t, mustRun(t, dbPath, "list", "--host", "stC"), []string{anomaly}, []string{issue})
	assertLists(t, mustRun(t, dbPath, "list", "--service", "kern"), []string{issue}, []string{anomaly})
	assertLists(t, mustRun(t, dbPath, "list", "--search", "disk"), []string{issue}, []string{anomaly})
	assertLists(t, mustRun(t, dbPath, "list", "--kind", "peer"), []string{anomaly}, []string{issue})
	assertLists(t, mustRun(t, dbPath, "list", "--severity", "high"), []string{issue}, []string{anomaly})
	assertLists(t, mustRun(t, dbPath, "list", "--since", "2026-06-02"), []string{anomaly}, []string{issue})
	assertLists(t, mustRun(t, dbPath, "list", "--until", "2026-06-01"), []string{issue}, []string{anomaly})
	assertLists(t, mustRun(t, dbPath, "list", "--host", "no-such"), []string{"no findings match"}, nil)
}

func TestListJSON(t *testing.T) {
	dbPath, issueID, anomID := seedLibrary(t)
	out := mustRun(t, dbPath, "list", "--json")
	var rows []reporter.FindingSummary
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("unmarshal list json: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != anomID || rows[1].ID != issueID {
		t.Errorf("json rows = %+v, want anomaly (newer run) then issue", rows)
	}
	if rows[1].Hosts != "hostA, hostB" || rows[1].Severity != "high" {
		t.Errorf("issue row = %+v", rows[1])
	}
}

func TestShowRendersBothKindsAsPlainText(t *testing.T) {
	dbPath, issueID, anomID := seedLibrary(t)

	out := mustRun(t, dbPath, "show", intArg(issueID))
	for _, want := range []string{
		"Disk filling on /var", "Severity: high", "hourly since 03:00",
		"Affected: hostA, hostB", "Impact: Service outage",
		"Recommended action: Rotate and compress old logs.",
		"VFS: file-max limit reached", "Root cause: logrotate unit disabled",
		"df -h /var", "systemctl enable --now logrotate.timer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("issue show missing %q", want)
		}
	}

	out = mustRun(t, dbPath, "show", intArg(anomID))
	for _, want := range []string{
		"Chattier than its peers", "Host: hostC", "Program: sshd", "OS: debian",
		"480 lines vs peer median 12", "Likely causes: Credential scanning.",
		"(none given)", "lastb | head",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("anomaly show missing %q", want)
		}
	}

	if _, err := run(t, dbPath, "show", "9999"); err == nil {
		t.Error("show of a missing id should error")
	}
}

func TestShowJSONRoundTrips(t *testing.T) {
	dbPath, issueID, _ := seedLibrary(t)
	out := mustRun(t, dbPath, "show", intArg(issueID), "--json")
	var d reporter.FindingDetail
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("unmarshal show json: %v", err)
	}
	if d.ID != issueID || d.Anomaly != nil || d.Issue == nil {
		t.Fatalf("detail = %+v", d)
	}
	if d.Issue.Description != "Log partition at 92% and climbing." ||
		d.Issue.Resolution == nil ||
		d.Issue.Resolution.FixCommands[0] != "systemctl enable --now logrotate.timer" {
		t.Errorf("payload did not round-trip: %+v", d.Issue)
	}
}

func TestFeedbackAttribution(t *testing.T) {
	dbPath, issueID, _ := seedLibrary(t)
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })

	// Explicit --user lands on that user, and didnt-work maps to the
	// stored verdict spelling.
	out := mustRun(t, dbPath, "feedback", intArg(issueID), "didnt-work",
		"--user", "opsuser", "--comment", "made it worse")
	if !strings.Contains(out, "as opsuser") || !strings.Contains(out, "didnt work") {
		t.Errorf("feedback output = %q", out)
	}
	// Default path: the invoking OS user is not in the fictional users
	// table, so the vote is the anonymous singleton.
	out = mustRun(t, dbPath, "feedback", intArg(issueID), "worked")
	if !strings.Contains(out, "(anonymous)") {
		t.Errorf("feedback output = %q", out)
	}

	rows, err := lib.FeedbackFor(issueID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("feedback rows = %d, want 2", len(rows))
	}
	byUser := map[string]string{}
	for _, r := range rows {
		byUser[r.Username] = r.Verdict
	}
	if byUser["opsuser"] != "didnt_work" || byUser[""] != "worked" {
		t.Errorf("verdicts = %v", byUser)
	}

	// Unknown --user is an error, never a silent anonymous fallback.
	if _, err := run(t, dbPath, "feedback", intArg(issueID), "worked", "--user", "nobody"); err == nil {
		t.Error("unknown --user should error")
	}
	if _, err := run(t, dbPath, "feedback", intArg(issueID), "thumbs-up"); err == nil {
		t.Error("invalid verdict should error")
	}
	if _, err := run(t, dbPath, "feedback", "9999", "worked"); err == nil {
		t.Error("feedback on a missing finding should error")
	}
}

func intArg(id int64) string {
	return strconv.FormatInt(id, 10)
}
