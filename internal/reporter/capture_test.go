package reporter

// Tests for CaptureRun (ait srg-2KY5X.2). Reuses the librarystore_test.go
// helpers and sample records; fictional hostnames only.

import (
	"encoding/json"
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
