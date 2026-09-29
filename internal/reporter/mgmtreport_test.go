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
	"reflect"
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
	html, err := RenderMgmtHTML(stats, "test-version", "https://example.test/repo")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, want := range []string{
		"1,650",                 // total volume, grouped
		"01 Jun to 04 Jun 2026", // period label
		"3 of 4 days with data", // coverage
		"1 of 2 feedback votes said the fix worked", // feedback line
		"approximate volume reconstructed",          // footnote (2 approx days)
		"no data",                                   // the empty day
		"test-version",
		"sssd",                                // flagged service
		`<a href="https://example.test/repo"`, // footer links the project
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
	for _, want := range []string{"1,650", "Findings surfaced: 3 (including", "1 of 2 feedback votes said the fix worked"} {
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

// The management report reads daily runs only (srg-xiBoC.1): a digest run
// in the window must not double-count the week's findings or votes.
func TestGatherMgmtStatsIgnoresDigestRuns(t *testing.T) {
	lib, agg := seedMgmtFixture(t)
	before, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 4))
	if err != nil {
		t.Fatal(err)
	}
	issue := sampleIssuePayload().Issue
	issue.Severity = "critical"
	if err := CaptureRun(lib, day(2026, 6, 2), RunKindDigest, "smart/model", -1, -1,
		&IssueList{Issues: []*Issue{&issue}}, nil, []*ExplainedAnomaly{sampleAnomaly()}); err != nil {
		t.Fatal(err)
	}
	if err := lib.RecordFeedback(issue.ID, nil, "worked", ""); err != nil {
		t.Fatal(err)
	}
	after, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 4))
	if err != nil {
		t.Fatal(err)
	}
	if after.TotalFindings != before.TotalFindings || after.AnomalyCount != before.AnomalyCount ||
		after.SeverityCounts["critical"] != before.SeverityCounts["critical"] ||
		after.FeedbackWorked != before.FeedbackWorked || after.TotalRaw != before.TotalRaw ||
		!reflect.DeepEqual(after.TopHosts, before.TopHosts) {
		t.Errorf("digest run changed the numbers: before %+v after %+v", before, after)
	}
}

// seedHostFixture builds a fortnight, 2026-06-01 to 06-14, for the per-host
// tables. Volumes (lines a day, first week / second week):
//   - risinghost: 1,000 / 20,000, all rsyslogd        -> up 20x
//   - steadyhost: 5,000 / 5,000, 4,000 nginx + 1,000 cron -> not a mover
//   - gonehost:   3,000 / nothing                     -> stopped
//   - quiethost:  10 / 200, under the mover floor     -> not a mover
//
// Findings: flakyhost on two days (one finding each), busyhost on one day
// (three findings), so days must outrank the finding count. Three days
// have a run, so "of 3 days" is the flagged-hosts denominator.
func seedHostFixture(t *testing.T) (*LibraryStore, *AggregateStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.db")
	agg, err := OpenAggregateStore(path)
	if err != nil {
		t.Fatalf("open aggregate store: %v", err)
	}
	t.Cleanup(func() { agg.Close() })
	lib := openTestLibrary(t, path)

	for d := 1; d <= 14; d++ {
		counts := map[AggKey]int{
			{"steadyhost", "nginx", "00:00"}: 4000,
			{"steadyhost", "cron", "00:00"}:  1000,
		}
		if d <= 7 {
			counts[AggKey{"risinghost", "rsyslogd", "00:00"}] = 1000
			counts[AggKey{"gonehost", "sshd", "00:00"}] = 3000
			counts[AggKey{"quiethost", "cron", "00:00"}] = 10
		} else {
			counts[AggKey{"risinghost", "rsyslogd", "00:00"}] = 20000
			counts[AggKey{"quiethost", "cron", "00:00"}] = 200
		}
		mustWrite(t, agg, day(2026, 6, d), counts)
	}

	payload := sampleIssuePayload()
	addFindings := func(d int, host string, n int) {
		t.Helper()
		runID, err := lib.BeginRun(day(2026, 6, d), "openai/gpt-test")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if _, err := lib.AddFinding(runID, "issue", "high", "Something odd", "kernel",
				[]string{host}, payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	addFindings(2, "flakyhost", 1)
	addFindings(9, "flakyhost", 1)
	addFindings(5, "busyhost", 3)
	return lib, agg
}

func TestGatherMgmtStatsHostTables(t *testing.T) {
	lib, agg := seedHostFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 14))
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	t.Run("flagged hosts rank by days before findings", func(t *testing.T) {
		want := []HostFlagged{{"flakyhost", 2, 2}, {"busyhost", 1, 3}}
		if !reflect.DeepEqual(stats.TopHosts, want) {
			t.Errorf("top hosts = %+v, want %+v", stats.TopHosts, want)
		}
	})

	t.Run("noisiest hosts against the median", func(t *testing.T) {
		// Per day over 14 days: rising 10,500, steady 5,000, gone 1,500,
		// quiet 105. Median of four is (1,500 + 5,000) / 2.
		if stats.VolumeHosts != 4 || stats.MedianPerDay != 3250 {
			t.Errorf("hosts/median = %d/%v, want 4/3250", stats.VolumeHosts, stats.MedianPerDay)
		}
		var hosts []string
		for _, h := range stats.NoisiestHosts {
			hosts = append(hosts, h.Host)
		}
		if want := []string{"risinghost", "steadyhost", "gonehost", "quiethost"}; !reflect.DeepEqual(hosts, want) {
			t.Errorf("noisiest order = %v, want %v", hosts, want)
		}
		steady := stats.NoisiestHosts[1]
		if steady.PerDay != 5000 || steady.TopProgram != "nginx" || steady.TopShare != 0.8 {
			t.Errorf("steadyhost = %+v, want 5000/day, nginx 80%%", steady)
		}
	})

	t.Run("hosts sending logs, per day and over the last week", func(t *testing.T) {
		if stats.Days[0].Hosts != 4 || stats.Days[13].Hosts != 3 {
			t.Errorf("hosts on first/last day = %d/%d, want 4/3",
				stats.Days[0].Hosts, stats.Days[13].Hosts)
		}
		// gonehost stopped after the first week; nothing a period earlier.
		if stats.RecentDays != 7 || stats.RecentHosts != 3 || stats.PrevHosts != 0 {
			t.Errorf("recent = %d hosts in %d days, prev %d; want 3 in 7, prev 0",
				stats.RecentHosts, stats.RecentDays, stats.PrevHosts)
		}
	})

	t.Run("movers rank stopped first, skip steady and tiny hosts", func(t *testing.T) {
		want := []HostMover{{"gonehost", 3000, 0}, {"risinghost", 1000, 20000}}
		if stats.MoverWindow != 7 || !reflect.DeepEqual(stats.Movers, want) {
			t.Errorf("movers = %+v (window %d), want %+v (window 7)",
				stats.Movers, stats.MoverWindow, want)
		}
	})
}

func TestGatherMgmtStatsMoversNeedTwoDays(t *testing.T) {
	lib, agg := seedHostFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 14), day(2026, 6, 14))
	if err != nil {
		t.Fatal(err)
	}
	if stats.MoverWindow != 0 || len(stats.Movers) != 0 {
		t.Errorf("one-day period gave movers %+v (window %d)", stats.Movers, stats.MoverWindow)
	}
	if len(stats.NoisiestHosts) == 0 {
		t.Error("one-day period should still rank the noisiest hosts")
	}
}

func TestRenderMgmtHostTables(t *testing.T) {
	lib, agg := seedHostFixture(t)
	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 14))
	if err != nil {
		t.Fatal(err)
	}
	html, err := RenderMgmtHTML(stats, "test-version", "https://example.test/repo")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text := RenderMgmtText(stats)
	for _, want := range []string{
		"2 of 3 days",     // flagged hosts, out of the days with a run
		"3.2x",            // risinghost vs the median
		"rsyslogd (100%)", // main source
		"3,250 lines a day (the median across 4 hosts)",
		"up 20x",
		"stopped",
		"first and last 7 days",
		"Hosts sending logs",
		"in the 7 days to Sun 14 Jun; 4 different hosts over the period",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
		if !strings.Contains(text, want) {
			t.Errorf("text missing %q in:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "Hosts sending logs: 3 in the 7 days") {
		t.Errorf("text missing the recent host count in:\n%s", text)
	}
	if strings.Contains(html, "compared to") {
		t.Error("no data a period earlier, so there must be no comparison")
	}
}

// The comparison window sits one period back: a fortnight ending 14 Jun
// compares its last week with the week to 31 May. A host missing a day in
// that week still counts, which is the point of a week-long window.
func TestMgmtHostsComparedToPreviousPeriod(t *testing.T) {
	lib, agg := seedHostFixture(t)
	mustWrite(t, agg, day(2026, 5, 25), singleCount("oldhost1", "cron", "00:00", 50))
	mustWrite(t, agg, day(2026, 5, 31), map[AggKey]int{
		{"oldhost2", "cron", "00:00"}: 50,
		{"oldhost3", "cron", "00:00"}: 50,
	})
	mustWrite(t, agg, day(2026, 5, 28), singleCount("oldhost4", "cron", "00:00", 50))
	mustWrite(t, agg, day(2026, 5, 24), singleCount("tooearly", "cron", "00:00", 50))

	stats, err := GatherMgmtStats(lib, agg, day(2026, 6, 1), day(2026, 6, 14))
	if err != nil {
		t.Fatal(err)
	}
	if stats.PrevHosts != 4 || stats.PrevTo != "2026-05-31" {
		t.Errorf("prev = %d to %q, want 4 to 2026-05-31", stats.PrevHosts, stats.PrevTo)
	}
	const want = "compared to 4 in the 7 days to Sun 31 May"
	html, err := RenderMgmtHTML(stats, "v", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, want) {
		t.Errorf("html missing %q", want)
	}
	if text := RenderMgmtText(stats); !strings.Contains(text, "Hosts sending logs: 3 in the 7 days to Sun 14 Jun ("+want+"); 4 different") {
		t.Errorf("text missing the comparison in:\n%s", text)
	}
}

func TestMoverChange(t *testing.T) {
	for _, tc := range []struct {
		m    HostMover
		want string
	}{
		{HostMover{Before: 2700, After: 188000}, "up 70x"},
		{HostMover{Before: 1537, After: 402}, "down 3.8x"},
		{HostMover{Before: 0, After: 5000}, "new"},
		{HostMover{Before: 5000, After: 0}, "stopped"},
	} {
		if got := moverChange(tc.m); got != tc.want {
			t.Errorf("moverChange(%+v) = %q, want %q", tc.m, got, tc.want)
		}
	}
}

// The comparison wording: equal counts say "same as" rather than
// "compared to" the same number, and a one-day window names the day.
func TestMgmtHostsCompareWording(t *testing.T) {
	for _, tc := range []struct {
		name         string
		days, recent int
		prev         int
		want         string
	}{
		{"equal", 7, 35, 35, "same as the 7 days to Sat 29 Aug"},
		{"changed", 7, 35, 33, "compared to 33 in the 7 days to Sat 29 Aug"},
		{"no earlier data", 7, 35, 0, ""},
		{"one day", 1, 35, 33, "compared to 33 on Sat 29 Aug"},
		{"one day equal", 1, 35, 35, "same as Sat 29 Aug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := &MgmtStats{From: "2026-09-01", To: "2026-09-28", VolumeHosts: 36,
				RecentDays: tc.days, RecentHosts: tc.recent, PrevHosts: tc.prev, PrevTo: "2026-08-29"}
			if got := buildMgmtView(stats, "").HostsCompare; got != tc.want {
				t.Errorf("HostsCompare = %q, want %q", got, tc.want)
			}
		})
	}
}
