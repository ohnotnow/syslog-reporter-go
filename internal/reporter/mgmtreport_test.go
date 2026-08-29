package reporter

// Tests for the management report (ait srg-YHETx): stats gathering against
// a shared temp db, email-safe rendering, and the multipart/alternative
// email shape. Fictional hostnames only.
//
// No banned-dash assertion here: the owner's edit hook rejects any file
// containing one (in any encoding), so the template is vetted at edit time
// and a runtime check could not even name the character it looks for.

import (
	"path/filepath"
	"strings"
	"testing"
)

// seedMgmtFixture builds four days ending 2026-06-04:
//   - 06-01: aggregates only (pre-library history) -> approximate volume 150
//   - 06-02: run with stats (1000/40), two issues + one anomaly, two votes
//   - 06-03: run WITHOUT stats (pre-stats-column row) but aggregates 500
//   - 06-04: nothing at all
func seedMgmtFixture(t *testing.T) (*LibraryStore, *AggregateStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mgmt.db")
	agg, err := OpenAggregateStore(path)
	if err != nil {
		t.Fatalf("open aggregate store: %v", err)
	}
	t.Cleanup(func() { agg.Close() })
	lib := openTestLibrary(t, path)

	mustWrite(t, agg, day(2026, 6, 1), singleCount("hostA", "puppet", "00:00", 150))
	mustWrite(t, agg, day(2026, 6, 3), singleCount("hostB", "cron", "01:00", 500))

	runID, err := lib.BeginRun(day(2026, 6, 2), "openai/gpt-test")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	if err := lib.SetRunStats(runID, 1000, 40); err != nil {
		t.Fatalf("set stats: %v", err)
	}
	sample := sampleIssuePayload()
	critical := sample.Issue
	critical.Severity = "critical"
	fid1, err := lib.AddFinding(runID, "issue", "high", "Disk filling on /var", "kernel",
		[]string{"hostA"}, sample)
	if err != nil {
		t.Fatal(err)
	}
	fid2, err := lib.AddFinding(runID, "issue", "critical", "Auth loop on hostB", "sssd",
		[]string{"hostB"}, IssuePayload{Issue: critical})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.AddFinding(runID, "peer", "", "Chattier than its peers", "sshd",
		[]string{"hostC"}, sampleAnomaly()); err != nil {
		t.Fatal(err)
	}
	user1, err := lib.CreateUser("alice", "alice@example.ac.uk", "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.RecordFeedback(fid1, &user1, "worked", ""); err != nil {
		t.Fatal(err)
	}
	if err := lib.RecordFeedback(fid2, &user1, "didnt_work", "red herring"); err != nil {
		t.Fatal(err)
	}

	// A pre-stats-column run row: BeginRun then null the columns, the shape
	// an old binary left behind.
	oldRun, err := lib.BeginRun(day(2026, 6, 3), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lib.db.Exec(
		"UPDATE runs SET raw_lines = NULL, filtered_lines = NULL WHERE id = ?", oldRun); err != nil {
		t.Fatal(err)
	}
	return lib, agg
}

func TestGatherMgmtStats(t *testing.T) {
	lib, agg := seedMgmtFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 4))
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	if len(stats.Days) != 4 {
		t.Fatalf("days = %d, want 4", len(stats.Days))
	}
	if stats.DaysWithData != 3 || stats.ApproxDays != 2 {
		t.Errorf("days with data/approx = %d/%d, want 3/2", stats.DaysWithData, stats.ApproxDays)
	}
	if stats.TotalRaw != 1650 {
		t.Errorf("total raw = %d, want 1650", stats.TotalRaw)
	}
	if !stats.HaveFiltered || stats.TotalFiltered != 40 {
		t.Errorf("filtered = %v/%d, want true/40", stats.HaveFiltered, stats.TotalFiltered)
	}
	if stats.TotalFindings != 3 || stats.AnomalyCount != 1 {
		t.Errorf("findings/anomalies = %d/%d, want 3/1", stats.TotalFindings, stats.AnomalyCount)
	}
	if stats.SeverityCounts["high"] != 1 || stats.SeverityCounts["critical"] != 1 {
		t.Errorf("severities = %#v", stats.SeverityCounts)
	}
	if stats.FeedbackWorked != 1 || stats.FeedbackDidnt != 1 {
		t.Errorf("feedback = %d/%d, want 1/1", stats.FeedbackWorked, stats.FeedbackDidnt)
	}
	if len(stats.TopServices) == 0 || stats.TopServices[0].Count != 1 {
		t.Errorf("top services = %#v", stats.TopServices)
	}

	days := stats.Days
	if days[0].RawLines != 150 || !days[0].Approx {
		t.Errorf("day 1 = %+v, want approx 150", days[0])
	}
	if days[1].RawLines != 1000 || days[1].Approx || days[1].Findings != 3 {
		t.Errorf("day 2 = %+v, want exact 1000 with 3 findings", days[1])
	}
	if days[2].RawLines != 500 || !days[2].Approx {
		t.Errorf("day 3 = %+v, want approx 500 (stats-less run row)", days[2])
	}
	if days[3].RawLines != -1 {
		t.Errorf("day 4 = %+v, want no data", days[3])
	}
}

func TestRenderMgmtHTML(t *testing.T) {
	lib, agg := seedMgmtFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 4))
	if err != nil {
		t.Fatal(err)
	}
	html, err := RenderMgmtHTML(stats, "test-version")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, want := range []string{
		"1,650",                            // total volume, grouped
		"01 Jun to 04 Jun 2026",            // period label
		"3 of 4 days with data",            // coverage
		"1 of 2 reviewed findings",         // feedback line
		"approximate volume reconstructed", // footnote (2 approx days)
		"no data",                          // the empty day
		"test-version",
		"sssd", // flagged service
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(html, "<script") || strings.Contains(html, "<svg") {
		t.Error("html must stay email-safe: no script or svg")
	}
}

func TestRenderMgmtTextHeadlines(t *testing.T) {
	lib, agg := seedMgmtFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 4))
	if err != nil {
		t.Fatal(err)
	}
	text := RenderMgmtText(stats)
	// "including": anomalies are part of the findings total, not on top of
	// it, and the wording must never drift back to "plus" (srg-so8ja.3).
	for _, want := range []string{"1,650", "Findings surfaced: 3 (including", "1 of 2 reviewed findings"} {
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q in:\n%s", want, text)
		}
	}
}

func TestMgmtEmailIsMultipartAlternative(t *testing.T) {
	agent := &EmailAgent{
		BodyText:   "plain summary",
		HTMLBody:   "<html><body>hello</body></html>",
		Recipients: "boss@example.ac.uk",
		Subject:    "Syslog management summary - 01 Jun to 04 Jun 2026",
		Sender:     "syslog@example.ac.uk",
	}
	msg, err := agent.BuildMessage()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := string(msg)
	for _, want := range []string{
		"Content-Type: multipart/alternative",
		"text/plain; charset=\"utf-8\"",
		"text/html; charset=\"utf-8\"",
		"plain summary",
		"hello",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("message missing %q", want)
		}
	}
	if strings.Contains(got, "Content-Disposition: attachment") {
		t.Error("management email must not carry an attachment")
	}
}
