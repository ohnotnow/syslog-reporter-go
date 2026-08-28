package reporter

// Tests for the findings library store (ait srg-2KY5X.1). All against a temp
// db file, since sharing one file with the aggregate store is the point.
// Fictional hostnames only.

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func newTestLibrary(t *testing.T) *LibraryStore {
	t.Helper()
	return openTestLibrary(t, filepath.Join(t.TempDir(), "library.db"))
}

func openTestLibrary(t *testing.T, path string) *LibraryStore {
	t.Helper()
	s, err := OpenLibraryStore(path)
	if err != nil {
		t.Fatalf("open library store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func countRows(t *testing.T, s *LibraryStore, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func sampleIssuePayload() IssuePayload {
	return IssuePayload{
		Issue: Issue{
			Issue:              "Disk filling on /var",
			Severity:           "high",
			Description:        "Log partition at 92% and climbing.",
			ExampleLogEntry:    "hostA kernel: VFS: file-max limit reached",
			AffectedHost:       []string{"hostA", "hostB"},
			AffectedService:    "kernel",
			TimestampFrequency: "hourly since 03:00",
			PotentialImpact:    "Service outage when the partition fills.",
			RecommendedAction:  "Rotate and compress old logs.",
		},
		Resolution: &Resolution{
			Issue:       "Disk filling on /var",
			RootCause:   "logrotate unit disabled",
			Investigate: "df -h /var",
			FixCommands: []string{"systemctl enable --now logrotate.timer"},
			Notes:       "Check retention policy first.",
		},
	}
}

func sampleAnomaly() *ExplainedAnomaly {
	return &ExplainedAnomaly{
		Host:               "hostC",
		Program:            "sshd",
		Kind:               "peer",
		Headline:           "Chattier than its peers",
		Detail:             "480 lines vs peer median 12",
		OSFamily:           "debian",
		ExampleLine:        "hostC sshd[1234]: Failed password for invalid user",
		LikelyCauses:       "Credential scanning from a single source.",
		InvestigationSteps: []string{"Check auth log source addresses"},
		SuggestedCommands:  []string{"lastb | head"},
	}
}

func TestLibraryOpenOnExistingAggregatesDBLeavesAggregatesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	agg, err := OpenAggregateStore(path)
	if err != nil {
		t.Fatalf("open aggregate store: %v", err)
	}
	t.Cleanup(func() { agg.Close() })
	mustWrite(t, agg, day(2026, 6, 1), singleCount("hostA", "puppet", "00:00", 100))

	lib := openTestLibrary(t, path)
	if _, err := lib.BeginRun(day(2026, 6, 1), "openai/gpt-test"); err != nil {
		t.Fatalf("begin run: %v", err)
	}

	totals, err := agg.HistoryPairTotals(day(2026, 6, 5), 14)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := totals.Get(PairKey{"hostA", "puppet"})
	if !reflect.DeepEqual(got, map[string]int{"2026-06-01": 100}) {
		t.Errorf("aggregates disturbed by library open: %#v", got)
	}
}

func TestLibraryFindingPayloadsRoundTrip(t *testing.T) {
	lib := newTestLibrary(t)
	runID, err := lib.BeginRun(day(2026, 6, 1), "openai/gpt-test")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}

	issue := sampleIssuePayload()
	issueID, err := lib.AddFinding(runID, "issue", issue.Severity, issue.Issue.Issue,
		issue.AffectedService, issue.AffectedHost, issue)
	if err != nil {
		t.Fatalf("add issue finding: %v", err)
	}
	anom := sampleAnomaly()
	anomID, err := lib.AddFinding(runID, anom.Kind, "", anom.Headline,
		anom.Program, []string{anom.Host}, anom)
	if err != nil {
		t.Fatalf("add anomaly finding: %v", err)
	}

	var blob string
	if err := lib.db.QueryRow("SELECT payload FROM findings WHERE id = ?", issueID).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	var gotIssue IssuePayload
	if err := json.Unmarshal([]byte(blob), &gotIssue); err != nil {
		t.Fatalf("unmarshal issue payload: %v", err)
	}
	if !reflect.DeepEqual(gotIssue, issue) {
		t.Errorf("issue payload round-trip:\n got %#v\nwant %#v", gotIssue, issue)
	}

	if err := lib.db.QueryRow("SELECT payload FROM findings WHERE id = ?", anomID).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	var gotAnom ExplainedAnomaly
	if err := json.Unmarshal([]byte(blob), &gotAnom); err != nil {
		t.Fatalf("unmarshal anomaly payload: %v", err)
	}
	if !reflect.DeepEqual(&gotAnom, anom) {
		t.Errorf("anomaly payload round-trip:\n got %#v\nwant %#v", &gotAnom, anom)
	}
}

func TestLibraryMultiHostFindingWritesHostRows(t *testing.T) {
	lib := newTestLibrary(t)
	runID, err := lib.BeginRun(day(2026, 6, 1), "")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	issue := sampleIssuePayload()
	findingID, err := lib.AddFinding(runID, "issue", issue.Severity, issue.Issue.Issue,
		issue.AffectedService, issue.AffectedHost, issue)
	if err != nil {
		t.Fatalf("add finding: %v", err)
	}

	rows, err := lib.db.Query(
		"SELECT host FROM finding_hosts WHERE finding_id = ? ORDER BY host", findingID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"hostA", "hostB"}) {
		t.Errorf("finding_hosts = %v", hosts)
	}
}

func TestLibraryBeginRunReplacesSameDay(t *testing.T) {
	lib := newTestLibrary(t)
	runID, err := lib.BeginRun(day(2026, 6, 1), "openai/gpt-test")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	issue := sampleIssuePayload()
	findingID, err := lib.AddFinding(runID, "issue", issue.Severity, issue.Issue.Issue,
		issue.AffectedService, issue.AffectedHost, issue)
	if err != nil {
		t.Fatalf("add finding: %v", err)
	}
	// Feedback methods arrive with the UI issues; plant a vote directly so
	// the replacement's cascade is proven against all three child tables.
	if _, err := lib.db.Exec(
		"INSERT INTO feedback (finding_id, user_id, verdict, created_at) VALUES (?, NULL, 'worked', ?)",
		findingID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert feedback: %v", err)
	}
	// A different day must survive the replacement.
	otherRun, err := lib.BeginRun(day(2026, 6, 2), "")
	if err != nil {
		t.Fatalf("begin other run: %v", err)
	}
	anom := sampleAnomaly()
	if _, err := lib.AddFinding(otherRun, anom.Kind, "", anom.Headline,
		anom.Program, []string{anom.Host}, anom); err != nil {
		t.Fatalf("add other finding: %v", err)
	}

	if _, err := lib.BeginRun(day(2026, 6, 1), "anthropic/claude-test"); err != nil {
		t.Fatalf("re-run day: %v", err)
	}

	if n := countRows(t, lib, "runs"); n != 2 {
		t.Errorf("runs = %d, want 2 (one per day)", n)
	}
	var stale int
	if err := lib.db.QueryRow(
		"SELECT COUNT(*) FROM findings WHERE run_id = ?", runID).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Errorf("old run's findings survived: %d", stale)
	}
	if n := countRows(t, lib, "feedback"); n != 0 {
		t.Errorf("feedback = %d, want 0", n)
	}
	// Only the other day's single-host finding should remain.
	if n := countRows(t, lib, "findings"); n != 1 {
		t.Errorf("findings = %d, want 1", n)
	}
	if n := countRows(t, lib, "finding_hosts"); n != 1 {
		t.Errorf("finding_hosts = %d, want 1", n)
	}
}

func TestLibraryEmptyModelStoredAsNull(t *testing.T) {
	lib := newTestLibrary(t)
	runID, err := lib.BeginRun(day(2026, 6, 1), "")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	var isNull bool
	if err := lib.db.QueryRow(
		"SELECT model IS NULL FROM runs WHERE id = ?", runID).Scan(&isNull); err != nil {
		t.Fatal(err)
	}
	if !isNull {
		t.Error("empty model should be stored as SQL NULL")
	}
}

// seedSearchLibrary builds two runs of findings for the search tests.
// Insertion order (and so id order): run1 f1 issue "Disk filling on /var"
// (hostA, hostB) + f2 peer (hostC); run2 f3 issue "Disk 100% usage"
// (hostD) + f4 temporal (hostA) + f5 issue "Weird_title with % and \"
// (hostE). f1 carries 2 worked + 1 didnt_work feedback votes.
func seedSearchLibrary(t *testing.T) (*LibraryStore, []int64) {
	t.Helper()
	lib := newTestLibrary(t)
	run1, err := lib.BeginRun(day(2026, 6, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	run2, err := lib.BeginRun(day(2026, 6, 2), "")
	if err != nil {
		t.Fatal(err)
	}
	anom := sampleAnomaly()
	var ids []int64
	addf := func(runID int64, kind, severity, title, service string, hosts []string) {
		t.Helper()
		id, err := lib.AddFinding(runID, kind, severity, title, service, hosts, anom)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	addf(run1, "issue", "high", "Disk filling on /var", "kernel", []string{"hostA", "hostB"})
	addf(run1, "peer", "", "Chattier than its peers", "sshd", []string{"hostC"})
	addf(run2, "issue", "critical", "Disk 100% usage", "storaged", []string{"hostD"})
	addf(run2, "temporal", "", "Burst at 10:00", "cron", []string{"hostA"})
	addf(run2, "issue", "low", `Weird_title with % and \`, "misc", []string{"hostE"})
	now := time.Now().UTC().Format(time.RFC3339)
	for _, row := range []struct {
		userID  any
		verdict string
	}{{1, "worked"}, {2, "worked"}, {nil, "didnt_work"}} {
		if _, err := lib.db.Exec(
			"INSERT INTO feedback (finding_id, user_id, verdict, created_at) VALUES (?, ?, ?, ?)",
			ids[0], row.userID, row.verdict, now); err != nil {
			t.Fatal(err)
		}
	}
	return lib, ids
}

func searchIDs(t *testing.T, lib *LibraryStore, f FindingFilter) []int64 {
	t.Helper()
	if f.Limit == 0 {
		f.Limit = 50
	}
	results, err := lib.SearchFindings(f)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	var got []int64
	for _, r := range results {
		got = append(got, r.ID)
	}
	return got
}

func TestSearchFindingsFilters(t *testing.T) {
	lib, ids := seedSearchLibrary(t)
	f1, f2, f3, f4, f5 := ids[0], ids[1], ids[2], ids[3], ids[4]

	for name, tc := range map[string]struct {
		filter FindingFilter
		want   []int64
	}{
		// Newest run first, insertion order within a run.
		"no filter":         {FindingFilter{}, []int64{f3, f4, f5, f1, f2}},
		"host":              {FindingFilter{Host: "hostA"}, []int64{f4, f1}},
		"service":           {FindingFilter{Service: "sshd"}, []int64{f2}},
		"severity":          {FindingFilter{Severity: "critical"}, []int64{f3}},
		"kind":              {FindingFilter{Kind: "issue"}, []int64{f3, f5, f1}},
		"query lowercase":   {FindingFilter{Query: "disk"}, []int64{f3, f1}},
		"from":              {FindingFilter{From: "2026-06-02"}, []int64{f3, f4, f5}},
		"to":                {FindingFilter{To: "2026-06-01"}, []int64{f1, f2}},
		"combined":          {FindingFilter{Kind: "issue", Host: "hostA"}, []int64{f1}},
		"combined no match": {FindingFilter{Kind: "peer", Severity: "high"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if got := searchIDs(t, lib, tc.filter); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ids = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSearchFindingsEscapesLikeWildcards(t *testing.T) {
	lib, ids := seedSearchLibrary(t)
	weird := ids[4]
	// An unescaped % or _ would match every title; escaped, each matches
	// only titles containing the literal character ("Disk 100% usage"
	// legitimately contains a %).
	for q, want := range map[string][]int64{
		"%": {ids[2], weird},
		"_": {weird},
		`\`: {weird},
	} {
		if got := searchIDs(t, lib, FindingFilter{Query: q}); !reflect.DeepEqual(got, want) {
			t.Errorf("query %q matched %v, want %v", q, got, want)
		}
	}
}

func TestSearchFindingsPagination(t *testing.T) {
	lib, ids := seedSearchLibrary(t)
	f1, f2, f3, f4, f5 := ids[0], ids[1], ids[2], ids[3], ids[4]
	pages := [][]int64{{f3, f4}, {f5, f1}, {f2}}
	for i, want := range pages {
		got := searchIDs(t, lib, FindingFilter{Limit: 2, Offset: i * 2})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("page %d = %v, want %v", i+1, got, want)
		}
	}
}

func TestSearchFindingsRowShape(t *testing.T) {
	lib, ids := seedSearchLibrary(t)
	results, err := lib.SearchFindings(FindingFilter{Host: "hostB", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0]
	if r.ID != ids[0] || r.LogDate != "2026-06-01" || r.Kind != "issue" ||
		r.Severity != "high" || r.Title != "Disk filling on /var" ||
		r.Service != "kernel" || r.Hosts != "hostA, hostB" {
		t.Errorf("row = %+v", r)
	}
	if r.Worked != 2 || r.DidntWork != 1 {
		t.Errorf("feedback counts = %d worked / %d didnt, want 2 / 1", r.Worked, r.DidntWork)
	}
}

func TestLibraryUserRoundTrip(t *testing.T) {
	lib := newTestLibrary(t)
	id, err := lib.CreateUser("opsuser", "opsuser@example.test", "fake-bcrypt-hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	byName, err := lib.UserByUsername("opsuser")
	if err != nil {
		t.Fatal(err)
	}
	byID, err := lib.UserByID(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []*User{byName, byID} {
		if u == nil {
			t.Fatal("user not found")
		}
		if u.ID != id || u.Username != "opsuser" || u.Email != "opsuser@example.test" {
			t.Errorf("user = %+v", u)
		}
		if !u.PasswordHash.Valid || u.PasswordHash.String != "fake-bcrypt-hash" {
			t.Errorf("password hash = %+v", u.PasswordHash)
		}
		if u.Forenames.Valid || u.Surname.Valid {
			t.Errorf("names should be NULL, got %v / %v", u.Forenames, u.Surname)
		}
	}
}

func TestLibraryUserEmptyHashStoredAsNull(t *testing.T) {
	lib := newTestLibrary(t)
	if _, err := lib.CreateUser("ssouser", "ssouser@example.test", ""); err != nil {
		t.Fatal(err)
	}
	u, err := lib.UserByUsername("ssouser")
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || u.PasswordHash.Valid {
		t.Errorf("empty hash should be stored as NULL, got %+v", u)
	}
}

func TestLibraryUserNotFoundIsNilNil(t *testing.T) {
	lib := newTestLibrary(t)
	u, err := lib.UserByUsername("nobody")
	if err != nil || u != nil {
		t.Errorf("missing user = %v, %v; want nil, nil", u, err)
	}
	u, err = lib.UserByID(99)
	if err != nil || u != nil {
		t.Errorf("missing id = %v, %v; want nil, nil", u, err)
	}
}

func TestLibraryAggregatePruneLeavesLibraryRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	agg, err := OpenAggregateStore(path)
	if err != nil {
		t.Fatalf("open aggregate store: %v", err)
	}
	t.Cleanup(func() { agg.Close() })
	oldDay := day(2000, 1, 1)
	mustWrite(t, agg, oldDay, singleCount("hostA", "puppet", "00:00", 1))

	lib := openTestLibrary(t, path)
	runID, err := lib.BeginRun(oldDay, "")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	anom := sampleAnomaly()
	if _, err := lib.AddFinding(runID, anom.Kind, "", anom.Headline,
		anom.Program, []string{anom.Host}, anom); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	removed, err := agg.Prune(30)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("pruned %d aggregates rows, want 1", removed)
	}
	if n := countRows(t, lib, "runs"); n != 1 {
		t.Errorf("runs = %d, want 1 (Prune must not touch the library)", n)
	}
	if n := countRows(t, lib, "findings"); n != 1 {
		t.Errorf("findings = %d, want 1 (Prune must not touch the library)", n)
	}
}
