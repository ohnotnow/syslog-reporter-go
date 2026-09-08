package reporter

// Tests for CaptureRun (ait srg-2KY5X.2). Reuses the librarystore_test.go
// helpers and sample records; fictional hostnames only.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// findingRow is the queryable shape of a findings row for assertions.
type findingRow struct {
	kind, severity, title, service, payload string
}

func readFindings(t *testing.T, lib *LibraryStore) []findingRow {
	t.Helper()
	rows, err := lib.db.Query(
		"SELECT kind, severity, title, service, payload FROM findings ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var r findingRow
		if err := rows.Scan(&r.kind, &r.severity, &r.title, &r.service, &r.payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCaptureRunLLMShape(t *testing.T) {
	lib := newTestLibrary(t)
	sample := sampleIssuePayload()
	issue := sample.Issue
	issues := &IssueList{Issues: []*Issue{&issue}}
	resolutions := &ResolutionList{Resolutions: []*Resolution{sample.Resolution}}
	anom := sampleAnomaly()

	if err := CaptureRun(lib, day(2026, 6, 1), "openai/gpt-test", 41230, 812,
		issues, resolutions, []*ExplainedAnomaly{anom}); err != nil {
		t.Fatalf("capture: %v", err)
	}

	if n := countRows(t, lib, "runs"); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
	var model string
	var rawLines, filteredLines int
	if err := lib.db.QueryRow(
		"SELECT model, raw_lines, filtered_lines FROM runs").
		Scan(&model, &rawLines, &filteredLines); err != nil {
		t.Fatal(err)
	}
	if model != "openai/gpt-test" {
		t.Errorf("model = %q", model)
	}
	if rawLines != 41230 || filteredLines != 812 {
		t.Errorf("run stats = %d/%d, want 41230/812", rawLines, filteredLines)
	}

	found := readFindings(t, lib)
	if len(found) != 2 {
		t.Fatalf("findings = %d, want 2", len(found))
	}
	got := found[0]
	if got.kind != "issue" || got.severity != issue.Severity ||
		got.title != issue.Issue || got.service != issue.AffectedService {
		t.Errorf("issue row = %+v", got)
	}
	var payload IssuePayload
	if err := json.Unmarshal([]byte(got.payload), &payload); err != nil {
		t.Fatalf("unmarshal issue payload: %v", err)
	}
	if payload.Resolution == nil || payload.Resolution.RootCause != sample.Resolution.RootCause {
		t.Errorf("resolution not nested in payload: %+v", payload.Resolution)
	}
	got = found[1]
	if got.kind != anom.Kind || got.severity != "" ||
		got.title != anom.Headline || got.service != anom.Program {
		t.Errorf("anomaly row = %+v", got)
	}
}

func TestCaptureRunNoLLMShape(t *testing.T) {
	lib := newTestLibrary(t)
	if err := CaptureRun(lib, day(2026, 6, 1), "", 500, 20,
		nil, nil, []*ExplainedAnomaly{sampleAnomaly()}); err != nil {
		t.Fatalf("capture: %v", err)
	}

	var isNull bool
	if err := lib.db.QueryRow("SELECT model IS NULL FROM runs").Scan(&isNull); err != nil {
		t.Fatal(err)
	}
	if !isNull {
		t.Error("--no-llm run should store model as NULL")
	}
	found := readFindings(t, lib)
	if len(found) != 1 || found[0].kind != "peer" {
		t.Errorf("findings = %+v, want one peer anomaly", found)
	}
}

func TestCaptureRunUnmatchedResolutionIsNull(t *testing.T) {
	lib := newTestLibrary(t)
	sample := sampleIssuePayload()
	issue := sample.Issue
	issues := &IssueList{Issues: []*Issue{&issue}}
	orphan := &Resolution{Issue: "A different title entirely", RootCause: "n/a"}
	resolutions := &ResolutionList{Resolutions: []*Resolution{orphan}}

	if err := CaptureRun(lib, day(2026, 6, 1), "openai/gpt-test", 100, 5,
		issues, resolutions, nil); err != nil {
		t.Fatalf("capture: %v", err)
	}

	found := readFindings(t, lib)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	var payload IssuePayload
	if err := json.Unmarshal([]byte(found[0].payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Resolution != nil {
		t.Errorf("unmatched issue should persist with null resolution, got %+v", payload.Resolution)
	}
}

func TestCaptureRunSameDayTwiceLeavesOneRun(t *testing.T) {
	lib := newTestLibrary(t)
	anoms := []*ExplainedAnomaly{sampleAnomaly()}
	for i := 0; i < 2; i++ {
		if err := CaptureRun(lib, day(2026, 6, 1), "", 1000+i, 40+i, nil, nil, anoms); err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
	}
	if n := countRows(t, lib, "runs"); n != 1 {
		t.Errorf("runs = %d, want 1", n)
	}
	var rawLines, filteredLines int
	if err := lib.db.QueryRow(
		"SELECT raw_lines, filtered_lines FROM runs").Scan(&rawLines, &filteredLines); err != nil {
		t.Fatal(err)
	}
	if rawLines != 1001 || filteredLines != 41 {
		t.Errorf("re-run kept stale stats: %d/%d, want 1001/41", rawLines, filteredLines)
	}
	if n := countRows(t, lib, "findings"); n != 1 {
		t.Errorf("findings = %d, want 1", n)
	}
	if n := countRows(t, lib, "finding_hosts"); n != 1 {
		t.Errorf("finding_hosts = %d, want 1", n)
	}
}

// A capture that fails part-way must leave the previous day's run intact:
// the whole capture is one transaction (srg-so8ja.2). The failure is forced
// with a test-only trigger that aborts the insert of one poisoned title,
// exactly the mid-loop shape a disk-full or constraint error would take.
func TestCaptureRunFailurePreservesPreviousRun(t *testing.T) {
	lib := newTestLibrary(t)
	sample := sampleIssuePayload()
	issue := sample.Issue
	anom := sampleAnomaly()

	if err := CaptureRun(lib, day(2026, 6, 1), "openai/gpt-test", 1000, 50,
		&IssueList{Issues: []*Issue{&issue}}, nil,
		[]*ExplainedAnomaly{anom}); err != nil {
		t.Fatalf("first capture: %v", err)
	}
	if err := lib.RecordFeedback(readFindingIDs(t, lib)[0], nil, "worked", "kept me right"); err != nil {
		t.Fatalf("feedback: %v", err)
	}

	if _, err := lib.db.Exec(
		`CREATE TRIGGER fail_capture BEFORE INSERT ON findings
		 WHEN NEW.title = 'poisoned' BEGIN
		   SELECT RAISE(ABORT, 'test-induced failure');
		 END`); err != nil {
		t.Fatal(err)
	}

	poisoned := issue
	poisoned.Issue = "poisoned"
	survivor := sampleAnomaly()
	err := CaptureRun(lib, day(2026, 6, 1), "openai/gpt-test", 2000, 75,
		&IssueList{Issues: []*Issue{&issue, &poisoned}}, nil,
		[]*ExplainedAnomaly{survivor})
	if err == nil {
		t.Fatal("capture with poisoned finding did not fail")
	}
	// The good issue was inserted (and stamped) before the poisoned one
	// aborted the transaction; nothing may keep an id, and neither report
	// layout may advertise one (SECURITY_REVIEW.md SR-07).
	for name, id := range map[string]int64{"issue": issue.ID, "poisoned": poisoned.ID, "anomaly": survivor.ID} {
		if id != 0 {
			t.Errorf("%s still carries id %d after a rolled-back capture", name, id)
		}
	}
	rep := &ReportAgent{
		Issues:      &IssueList{Issues: []*Issue{&issue, &poisoned}},
		Resolutions: &ResolutionList{},
		Anomalies:   []*ExplainedAnomaly{survivor},
		RepoURL:     "https://example.test/repo",
	}
	for name, body := range map[string]string{"email": rep.EmailBody(), "full": rep.Run()} {
		if strings.Contains(body, "syslog-mute") || strings.Contains(body, "**Finding:** #") {
			t.Errorf("%s layout advertises ids after a rolled-back capture", name)
		}
	}

	// The failed replacement rolled back wholesale: original run, both
	// findings and the feedback vote all survive.
	if n := countRows(t, lib, "runs"); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
	var rawLines int
	if err := lib.db.QueryRow("SELECT raw_lines FROM runs").Scan(&rawLines); err != nil {
		t.Fatal(err)
	}
	if rawLines != 1000 {
		t.Fatalf("raw_lines = %d, want the original 1000", rawLines)
	}
	if n := countRows(t, lib, "findings"); n != 2 {
		t.Fatalf("findings = %d, want the original 2", n)
	}
	if n := countRows(t, lib, "feedback"); n != 1 {
		t.Fatalf("feedback = %d, want the original 1", n)
	}
}

func readFindingIDs(t *testing.T, lib *LibraryStore) []int64 {
	t.Helper()
	rows, err := lib.db.Query("SELECT id FROM findings ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCaptureRunHandsBackFindingIdsAndKeepsThemOutOfPayloads(t *testing.T) {
	lib := newTestLibrary(t)
	sample := sampleIssuePayload()
	issue := sample.Issue
	anom := sampleAnomaly()
	if issue.ID != 0 || anom.ID != 0 {
		t.Fatal("fixtures should start without ids")
	}
	if err := CaptureRun(lib, day(2026, 6, 1), "openai/gpt-test", 1, 1,
		&IssueList{Issues: []*Issue{&issue}}, nil, []*ExplainedAnomaly{anom}); err != nil {
		t.Fatal(err)
	}
	if issue.ID == 0 || anom.ID == 0 || issue.ID == anom.ID {
		t.Errorf("ids = %d / %d, want two distinct non-zero ids", issue.ID, anom.ID)
	}
	for _, id := range []int64{issue.ID, anom.ID} {
		d, err := lib.GetFinding(id)
		if err != nil {
			t.Fatalf("finding %d not readable: %v", id, err)
		}
		var payload string
		if err := lib.db.QueryRow("SELECT payload FROM findings WHERE id = ?", id).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, `"ID"`) || strings.Contains(payload, `"id"`) {
			t.Errorf("finding %d payload carries an id field: %s", d.ID, payload)
		}
	}
}

// A rerun of the same day must never reissue an id: a mute line copied
// from the earlier email would otherwise silently target whatever finding
// inherited the number (SECURITY_REVIEW.md SR-02, migration 3).
func TestCaptureRunRerunNeverReusesFindingIDs(t *testing.T) {
	lib := newTestLibrary(t)
	first := sampleAnomaly()
	if err := CaptureRun(lib, day(2026, 6, 1), "", 1000, 40, nil, nil,
		[]*ExplainedAnomaly{first}); err != nil {
		t.Fatalf("first capture: %v", err)
	}
	oldIDs := readFindingIDs(t, lib)

	second := sampleAnomaly()
	second.Host = "db07.example.test"
	if err := CaptureRun(lib, day(2026, 6, 1), "", 1001, 41, nil, nil,
		[]*ExplainedAnomaly{second}); err != nil {
		t.Fatalf("second capture: %v", err)
	}
	for _, old := range oldIDs {
		if second.ID <= old {
			t.Errorf("rerun handed out id %d, not above the retired %d", second.ID, old)
		}
		if _, err := lib.GetFinding(old); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("retired id %d: err = %v, want sql.ErrNoRows", old, err)
		}
	}
}
