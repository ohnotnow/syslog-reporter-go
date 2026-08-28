package web

// Tests for the findings list page (ait srg-2KY5X.6). Fictional hostnames
// only.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// seedFindings puts two findings from one run into the server's store.
func seedFindings(t *testing.T, lib *reporter.LibraryStore) {
	t.Helper()
	runID, err := lib.BeginRun(day(2026, 6, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	anom := &reporter.ExplainedAnomaly{Host: "hostA", Program: "sshd", Kind: "peer",
		Headline: "Chattier than its peers"}
	if _, err := lib.AddFinding(runID, "issue", "high", "Disk filling on /var",
		"kernel", []string{"hostA", "hostB"}, anom); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.AddFinding(runID, "peer", "", "Chattier than its peers",
		"sshd", []string{"hostA"}, anom); err != nil {
		t.Fatal(err)
	}
}

// day mirrors the reporter test helper; web tests need their own copy.
func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func TestFindingsListFullPage(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	seedFindings(t, s.lib)
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<html",                // the full page, not a partial
		"Search titles",        // the filter form
		"Disk filling on /var", // findings rows
		"Chattier than its peers",
		"hostA, hostB",
		`href="/findings/1"`, // title links to the detail page
		"none yet",           // no feedback yet
		"2 findings.",        // status line
		`aria-live="polite"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("full page missing %q", want)
		}
	}
}

func TestFindingsListPartialForHtmx(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	seedFindings(t, s.lib)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?kind=issue", nil)
	req.Header.Set("HX-Request", "true")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("htmx GET = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<html") || strings.Contains(body, "Search titles") {
		t.Error("partial should not contain the full page or the filter form")
	}
	for _, want := range []string{
		`id="results"`,
		"Disk filling on /var",
		`hx-swap-oob="innerHTML"`, // the out-of-band status update
		"1 finding.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("partial missing %q", want)
		}
	}
	if strings.Contains(body, "Chattier than its peers") {
		t.Error("kind=issue filter leaked the peer finding into the partial")
	}
}

func TestFindingsListEmptyStates(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	if body := get(t, s, "/").Body.String(); !strings.Contains(body, "No findings have been captured yet") {
		t.Error("unfiltered empty library should show the teaching empty state")
	}
	seedFindings(t, s.lib)
	if body := get(t, s, "/?host=no-such-host").Body.String(); !strings.Contains(body, "No findings match") {
		t.Error("filtered no-match should show the filter empty state")
	}
}

func TestFindingsOutcomeBadgesRender(t *testing.T) {
	// Feedback write methods arrive with the detail-page issue, so the
	// badge rendering is exercised straight through the template.
	rec := httptest.NewRecorder()
	render(rec, "findings.html", pageData{Version: "test", Path: "/", Data: findingsView{
		Results: []*reporter.FindingSummary{{
			ID: 1, LogDate: "2026-06-01", Kind: "issue", Severity: "high",
			Title: "Disk filling on /var", Service: "kernel",
			Hosts: "hostA", Worked: 2, DidntWork: 1,
		}},
		StatusLine: "1 finding.",
	}})
	body := rec.Body.String()
	for _, want := range []string{"2 worked", "1 didn't", "badge-worked", "badge-didnt"} {
		if !strings.Contains(body, want) {
			t.Errorf("badges missing %q", want)
		}
	}
}

func TestFindingsPaginationLinks(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	runID, err := s.lib.BeginRun(day(2026, 6, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	anom := &reporter.ExplainedAnomaly{Host: "hostA", Program: "p", Kind: "peer", Headline: "h"}
	for i := 0; i < findingsPageSize+1; i++ {
		if _, err := s.lib.AddFinding(runID, "peer", "", "Finding", "p",
			[]string{"hostA"}, anom); err != nil {
			t.Fatal(err)
		}
	}
	body := get(t, s, "/").Body.String()
	if !strings.Contains(body, "Next page") || strings.Contains(body, "Previous page") {
		t.Error("page 1 of 2 should offer only a next-page link")
	}
	if !strings.Contains(body, "more available") {
		t.Error("status line should say more findings are available")
	}
	body = get(t, s, "/?page=2").Body.String()
	if strings.Contains(body, "Next page") || !strings.Contains(body, "Previous page") {
		t.Error("page 2 of 2 should offer only a previous-page link")
	}
}
