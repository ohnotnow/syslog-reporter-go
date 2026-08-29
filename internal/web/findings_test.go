package web

// Tests for the findings list page (ait srg-2KY5X.6). Fictional hostnames
// only.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func seedDetailFindings(t *testing.T, lib *reporter.LibraryStore) (issueID, anomID int64) {
	t.Helper()
	runID, err := lib.BeginRun(day(2026, 6, 1), "openai/gpt-test")
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
			Notes:       "Check retention policy first.",
		},
	}
	issueID, err = lib.AddFinding(runID, "issue", "high", issue.Issue.Issue,
		issue.AffectedService, issue.AffectedHost, issue)
	if err != nil {
		t.Fatal(err)
	}
	anom := &reporter.ExplainedAnomaly{
		Host: "hostC", Program: "sshd", Kind: "peer",
		Headline: "Chattier than its peers", Detail: "480 lines vs peer median 12",
		OSFamily: "debian", ExampleLine: "hostC sshd[1234]: Failed password",
		LikelyCauses:       "Credential scanning.",
		InvestigationSteps: []string{"Check auth log source addresses"},
		SuggestedCommands:  []string{"lastb | head"},
	}
	anomID, err = lib.AddFinding(runID, anom.Kind, "", anom.Headline,
		anom.Program, []string{anom.Host}, anom)
	if err != nil {
		t.Fatal(err)
	}
	return issueID, anomID
}

func TestFindingDetailRendersBothKinds(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	issueID, anomID := seedDetailFindings(t, s.lib)

	body := get(t, s, fmt.Sprintf("/findings/%d", issueID)).Body.String()
	for _, want := range []string{
		"Disk filling on /var", "hourly since 03:00",
		"Log partition at 92%", "hostA, hostB",
		"Service outage when the partition fills.", "Rotate and compress old logs.",
		"VFS: file-max limit reached",
		"logrotate unit disabled", "df -h /var",
		"systemctl enable --now logrotate.timer", "Check retention policy first.",
		"Review before pasting", // the paste caution (srg-so8ja.5)
		"Did this fix it?", "Fixed it", "Did not fix it",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("issue detail missing %q", want)
		}
	}

	body = get(t, s, fmt.Sprintf("/findings/%d", anomID)).Body.String()
	for _, want := range []string{
		"Chattier than its peers", "480 lines vs peer median 12",
		"debian", "Failed password", "Credential scanning.",
		"Check auth log source addresses", "lastb | head",
		"Review before pasting", // the paste caution (srg-so8ja.5)
	} {
		if !strings.Contains(body, want) {
			t.Errorf("anomaly detail missing %q", want)
		}
	}
}

func TestFindingDetailUnknownIs404(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	for _, path := range []string{"/findings/9999", "/findings/banana"} {
		rec := get(t, s, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Not found") {
			t.Errorf("GET %s should render the not-found page", path)
		}
	}
}

func postFeedback(t *testing.T, s *Server, id int64, form url.Values, htmx bool) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/findings/%d/feedback", id),
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestFeedbackAnonymousFlow(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	_, anomID := seedDetailFindings(t, s.lib)

	// htmx vote: fragment comes back with the honest single-vote copy and
	// the out-of-band live status update; no aggregate counts in mode none.
	rec := postFeedback(t, s, anomID, url.Values{
		"verdict": {"worked"}, "comment": {"rebooted the collector"}}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("htmx feedback = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Recorded: fixed it.", `hx-swap-oob="innerHTML"`,
		"rebooted the collector", "anonymous",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("feedback fragment missing %q", want)
		}
	}
	if strings.Contains(body, "<html") || strings.Contains(body, "You recorded") ||
		strings.Contains(body, "0 fixed it") {
		t.Error("anonymous fragment should be partial, without multi-user copy or counts")
	}

	// Re-vote with the (always-empty) comment box untouched: still one row,
	// verdict replaced, the earlier note kept (owner decision 2026-08-28).
	postFeedback(t, s, anomID, url.Values{"verdict": {"didnt_work"}}, true)
	rows, err := s.lib.FeedbackFor(anomID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "didnt_work" || rows[0].Comment != "rebooted the collector" {
		t.Errorf("after re-vote rows = %+v, want one didnt_work row keeping the note", rows)
	}

	// Non-htmx fallback: 303 back to the detail page.
	rec = postFeedback(t, s, anomID, url.Values{"verdict": {"worked"}}, false)
	if rec.Code != http.StatusSeeOther ||
		rec.Header().Get("Location") != fmt.Sprintf("/findings/%d", anomID) {
		t.Errorf("non-htmx POST = %d -> %q, want 303 to the detail page",
			rec.Code, rec.Header().Get("Location"))
	}

	// Invalid verdict is rejected before the CHECK constraint sees it.
	if rec := postFeedback(t, s, anomID, url.Values{"verdict": {"thumbs_up"}}, true); rec.Code != http.StatusBadRequest {
		t.Errorf("bad verdict = %d, want 400", rec.Code)
	}
}

func TestFeedbackSignedInShowsCounts(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	issueID, _ := seedDetailFindings(t, lib)
	ts := newLocalServer(t, lib)
	client := sessionClient(t)
	if _, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}

	resp, err := client.PostForm(fmt.Sprintf("%s/findings/%d/feedback", ts.URL, issueID),
		url.Values{"verdict": {"worked"}, "comment": {"ran the fix, held overnight"}})
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp) // non-htmx: redirected back to the detail page
	for _, want := range []string{
		"You recorded: fixed it.", "1 fixed it · 0 did not fix it",
		"opsuser", "ran the fix, held overnight",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-in detail missing %q", want)
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
