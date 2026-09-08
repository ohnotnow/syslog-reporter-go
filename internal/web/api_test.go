package web

// Tests for the read endpoints (ait srg-Kj5Q8.5). Fictional hosts only.

import (
	"net/http"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func TestAPIFindingsListAndFilters(t *testing.T) {
	f := newAPIServer(t, "none")
	ts, lib, raw := f.ts, f.lib, f.raw
	seedFindings(t, lib)

	var body struct {
		Findings []reporter.FindingSummary `json:"findings"`
		Limit    int                       `json:"limit"`
		Offset   int                       `json:"offset"`
	}
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/findings", raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	decodeJSON(t, resp, &body)
	if len(body.Findings) != 2 || body.Limit != apiDefaultLimit || body.Offset != 0 {
		t.Fatalf("body = %+v", body)
	}
	if body.Findings[0].Hosts != "hostA, hostB" {
		t.Errorf("hosts = %q", body.Findings[0].Hosts)
	}

	resp = apiRequest(t, http.MethodGet, ts.URL+"/api/findings?kind=peer&host=hostA", raw, "")
	decodeJSON(t, resp, &body)
	if len(body.Findings) != 1 || body.Findings[0].Kind != "peer" {
		t.Errorf("filtered = %+v", body.Findings)
	}

	resp = apiRequest(t, http.MethodGet, ts.URL+"/api/findings?since=2026-07-01", raw, "")
	decodeJSON(t, resp, &body)
	if len(body.Findings) != 0 {
		t.Errorf("since filter = %+v", body.Findings)
	}

	resp = apiRequest(t, http.MethodGet, ts.URL+"/api/findings?limit=9999", raw, "")
	decodeJSON(t, resp, &body)
	if body.Limit != apiMaxLimit {
		t.Errorf("limit = %d, want capped at %d", body.Limit, apiMaxLimit)
	}

	resp = apiRequest(t, http.MethodGet, ts.URL+"/api/findings?since=yesterday", raw, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad date = %d, want 400", resp.StatusCode)
	}
}

func TestAPIFindingShowAndNotFound(t *testing.T) {
	f := newAPIServer(t, "none")
	ts, lib, raw := f.ts, f.lib, f.raw
	seedFindings(t, lib)
	if err := lib.RecordFeedback(1, nil, "worked", "rebooted it"); err != nil {
		t.Fatal(err)
	}
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/findings/1", raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Finding  reporter.FindingDetail `json:"finding"`
		Feedback []apiFeedback          `json:"feedback"`
	}
	decodeJSON(t, resp, &body)
	if body.Finding.ID != 1 || body.Finding.Title != "Disk filling on /var" || len(body.Finding.Hosts) != 2 {
		t.Errorf("finding = %+v", body.Finding)
	}
	if len(body.Feedback) != 1 || body.Feedback[0].Verdict != "worked" || body.Feedback[0].User != "" {
		t.Errorf("feedback = %+v", body.Feedback)
	}
	for _, path := range []string{"/api/findings/999", "/api/findings/abc"} {
		resp := apiRequest(t, http.MethodGet, ts.URL+path, raw, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, resp.StatusCode)
		}
		var e map[string]string
		decodeJSON(t, resp, &e)
		if e["error"] == "" {
			t.Errorf("%s: no JSON error body", path)
		}
	}
}

func TestAPIRunsDefaultsToTheLastThirtyDays(t *testing.T) {
	f := newAPIServer(t, "none")
	ts, lib, raw := f.ts, f.lib, f.raw
	seedFindings(t, lib) // one run dated 2026-06-01
	var body struct {
		Runs  []reporter.RunSummary `json:"runs"`
		Since string                `json:"since"`
		Until string                `json:"until"`
	}
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/runs?since=2026-06-01&until=2026-06-30", raw, "")
	decodeJSON(t, resp, &body)
	if len(body.Runs) != 1 || body.Runs[0].Findings != 2 || body.Runs[0].LogDate != "2026-06-01" {
		t.Errorf("runs = %+v", body.Runs)
	}
	resp = apiRequest(t, http.MethodGet, ts.URL+"/api/runs", raw, "")
	decodeJSON(t, resp, &body)
	if body.Since == "" || body.Until == "" || len(body.Runs) != 0 {
		t.Errorf("default window = %s..%s with %d runs, want a filled window and no 2026-06 run",
			body.Since, body.Until, len(body.Runs))
	}
}

func TestAPIAggregatesRequireABoundedRange(t *testing.T) {
	f := newAPIServer(t, "none")
	ts, raw := f.ts, f.raw
	// Same file, second handle: how the daily run writes what serve reads.
	agg, err := reporter.OpenAggregateStore(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agg.Close() })
	if _, err := agg.WriteAggregates(day(2026, 9, 1), map[reporter.AggKey]int{
		{Host: "web01.example.test", Program: "sshd", Window: "09:00"}: 4,
		{Host: "web01.example.test", Program: "sshd", Window: "09:10"}: 6,
	}); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Rows []reporter.DailyTotal `json:"rows"`
	}
	resp := apiRequest(t, http.MethodGet, ts.URL+"/api/aggregates?since=2026-09-01&until=2026-09-07", raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	decodeJSON(t, resp, &body)
	if len(body.Rows) != 1 || body.Rows[0].Count != 10 || body.Rows[0].Host != "web01.example.test" {
		t.Errorf("rows = %+v", body.Rows)
	}
	for _, qs := range []string{
		"",
		"since=2026-09-01",
		"since=2026-09-07&until=2026-09-01",
		"since=2025-01-01&until=2026-09-01",
		"since=2026-09-01&until=soon",
	} {
		resp := apiRequest(t, http.MethodGet, ts.URL+"/api/aggregates?"+qs, raw, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", qs, resp.StatusCode)
		}
	}
}
