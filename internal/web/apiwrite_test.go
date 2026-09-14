package web

// Tests for the mute and feedback endpoints (ait srg-Kj5Q8.6). Fictional
// hosts only.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// seedMutable stores an anomaly finding (id 1) and a two-host issue finding
// (id 2) whose example line parses to dhcpd, plus one (id 3) whose program
// cannot be derived and one (id 4) whose program derives cleanly but whose
// only host is a glob.
func seedMutable(t *testing.T, lib *reporter.LibraryStore) {
	t.Helper()
	runID, err := lib.BeginRun(day(2026, 9, 7), "test/model")
	if err != nil {
		t.Fatal(err)
	}
	anom := &reporter.ExplainedAnomaly{Host: "web01.example.test", Program: "sshd", Kind: "peer",
		Headline: "Chattier than its peers"}
	if _, err := lib.AddFinding(runID, "peer", "", anom.Headline, "sshd",
		[]string{"web01.example.test"}, anom); err != nil {
		t.Fatal(err)
	}
	dhcp := reporter.IssuePayload{Issue: reporter.Issue{Issue: "No free leases", Severity: "medium",
		ExampleLogEntry: "Sep  7 10:00:01 dhcp01.example.test dhcpd[712]: DHCPDISCOVER from 00:11:22:33:44:55: no free leases",
		AffectedHost:    []string{"dhcp01.example.test", "dhcp02.example.test"}, AffectedService: "DHCP"}}
	if _, err := lib.AddFinding(runID, "issue", "medium", dhcp.Issue.Issue, "DHCP",
		dhcp.AffectedHost, dhcp); err != nil {
		t.Fatal(err)
	}
	prose := reporter.IssuePayload{Issue: reporter.Issue{Issue: "Something vague",
		ExampleLogEntry: "no parseable line here", AffectedHost: []string{"web02.example.test"},
		AffectedService: "the web tier"}}
	if _, err := lib.AddFinding(runID, "issue", "low", prose.Issue.Issue, "the web tier",
		prose.AffectedHost, prose); err != nil {
		t.Fatal(err)
	}
	glob := reporter.IssuePayload{Issue: reporter.Issue{Issue: "Everything is on fire",
		ExampleLogEntry: "Sep  7 10:00:01 web03.example.test nginx[1]: boom",
		AffectedHost:    []string{"*"}, AffectedService: "nginx"}}
	if _, err := lib.AddFinding(runID, "issue", "low", glob.Issue.Issue, "nginx",
		glob.AffectedHost, glob); err != nil {
		t.Fatal(err)
	}
}

// muteServer is an API fixture seeded with mutable findings.
func muteServer(t *testing.T, muteLimit int) apiFixture {
	t.Helper()
	if muteLimit > 0 {
		t.Setenv("SYSLOG_API_MUTE_LIMIT", strconv.Itoa(muteLimit))
	}
	f := newAPIServerFromEnv(t)
	seedMutable(t, f.lib)
	return f
}

func knownsCount(t *testing.T, f apiFixture) int {
	t.Helper()
	rows, err := f.lib.ListKnownEntries()
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func mute(t *testing.T, f apiFixture, id string, form url.Values) *http.Response {
	t.Helper()
	return apiRequest(t, http.MethodPost, f.ts.URL+"/api/findings/"+id+"/mute", f.raw, form.Encode())
}

func TestAPIMuteWritesOneEntryPerHostWithProvenance(t *testing.T) {
	f := muteServer(t, 0)
	resp := mute(t, f, "2", url.Values{"reason": {"no pool by design"}, "expires": {"2030-01-31"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Entries []muteEntry `json:"entries"`
	}
	decodeJSON(t, resp, &body)
	if len(body.Entries) != 2 || body.Entries[0].Host != "dhcp01.example.test" ||
		body.Entries[1].Host != "dhcp02.example.test" || body.Entries[0].Program != "dhcpd" {
		t.Fatalf("entries = %+v", body.Entries)
	}
	e := body.Entries[0]
	if e.ID == 0 || e.Reason != "no pool by design" || e.Expires == nil || *e.Expires != "2030-01-31" ||
		e.Source != "api" || e.CreatedBy != "opsuser" || len(e.TokenPrefix) != 8 ||
		e.FindingID == nil || *e.FindingID != 2 {
		t.Errorf("entry = %+v", e)
	}

	// The stored entries drop that program's lines on those hosts and no others.
	kk, err := f.lib.LoadKnownKnowns(day(2026, 9, 8))
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"Sep  8 10:00:01 dhcp01.example.test dhcpd[712]: no free leases",
		"Sep  8 10:00:02 dhcp02.example.test dhcpd[713]: no free leases",
		"Sep  8 10:00:03 dhcp03.example.test dhcpd[714]: no free leases",
	}
	if got := reporter.NewLogFilter(lines, kk).Run(); len(got) != 1 || !strings.Contains(got[0], "dhcp03") {
		t.Errorf("filter kept %#v, want only the dhcp03 line", got)
	}

	// Anomaly finding: one entry.
	resp = mute(t, f, "1", url.Values{"reason": {"scanner target"}})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("anomaly mute = %d", resp.StatusCode)
	}
	if n := knownsCount(t, f); n != 3 {
		t.Errorf("rows = %d, want 3", n)
	}
}

func TestAPIMuteRefusals(t *testing.T) {
	f := muteServer(t, 0)
	cases := []struct {
		name, id string
		form     url.Values
		want     int
	}{
		{"no reason", "1", url.Values{}, http.StatusBadRequest},
		{"long reason", "1", url.Values{"reason": {strings.Repeat("x", 201)}}, http.StatusBadRequest},
		{"newline in reason", "1", url.Values{"reason": {"one\ntwo"}}, http.StatusBadRequest},
		{"bad expiry", "1", url.Values{"reason": {"ok"}, "expires": {"soon"}}, http.StatusBadRequest},
		{"past expiry", "1", url.Values{"reason": {"ok"}, "expires": {"2020-01-01"}}, http.StatusBadRequest},
		{"unknown finding", "999", url.Values{"reason": {"ok"}}, http.StatusNotFound},
		{"underivable program", "3", url.Values{"reason": {"ok"}}, http.StatusUnprocessableEntity},
		{"glob host", "4", url.Values{"reason": {"ok"}}, http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := mute(t, f, tc.id, tc.form)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			var e map[string]string
			decodeJSON(t, resp, &e)
			if e["error"] == "" {
				t.Error("no JSON error body")
			}
		})
	}
	if n := knownsCount(t, f); n != 0 {
		t.Errorf("refused mutes wrote %d rows", n)
	}

	// A duplicate is a 409 and writes nothing.
	if resp := mute(t, f, "1", url.Values{"reason": {"first"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first mute = %d", resp.StatusCode)
	}
	if resp := mute(t, f, "1", url.Values{"reason": {"second"}}); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate mute = %d, want 409", resp.StatusCode)
	}
	if n := knownsCount(t, f); n != 1 {
		t.Errorf("duplicate mute changed the table: %d rows", n)
	}
}

func TestAPIMuteDailyCapIsPerToken(t *testing.T) {
	f := muteServer(t, 1)
	if resp := mute(t, f, "1", url.Values{"reason": {"one"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first mute = %d", resp.StatusCode)
	}
	resp := mute(t, f, "2", url.Values{"reason": {"two"}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second mute = %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("missing Retry-After")
	}
	// Another token for the same user has its own allowance.
	user, _ := f.lib.UserByUsername("opsuser")
	other, _, err := f.lib.CreateAPIToken(user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp = apiRequest(t, http.MethodPost, f.ts.URL+"/api/findings/2/mute", other,
		url.Values{"reason": {"two"}}.Encode())
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("other token = %d, want 201", resp.StatusCode)
	}
}

func TestAPIMuteAcceptsJSONBodies(t *testing.T) {
	f := muteServer(t, 0)
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/findings/1/mute",
		strings.NewReader(`{"reason":"json reason"}`))
	req.Header.Set("Authorization", "Bearer "+f.raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("json mute = %d", resp.StatusCode)
	}
}

func TestAPIFeedbackNamesTheTokensUser(t *testing.T) {
	f := muteServer(t, 0)
	resp := apiRequest(t, http.MethodPost, f.ts.URL+"/api/findings/1/feedback", f.raw,
		url.Values{"verdict": {"worked"}, "comment": {"rebooted"}}.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Feedback []apiFeedback `json:"feedback"`
	}
	decodeJSON(t, resp, &body)
	if len(body.Feedback) != 1 || body.Feedback[0].User != "opsuser" || body.Feedback[0].Comment != "rebooted" {
		t.Errorf("feedback = %+v", body.Feedback)
	}
	resp = apiRequest(t, http.MethodPost, f.ts.URL+"/api/findings/1/feedback", f.raw,
		url.Values{"verdict": {"maybe"}}.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad verdict = %d, want 400", resp.StatusCode)
	}
}

func TestMuteLimitEnvIsValidated(t *testing.T) {
	t.Setenv("SYSLOG_API_MUTE_LIMIT", "0")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "SYSLOG_API_MUTE_LIMIT") {
		t.Errorf("zero limit err = %v", err)
	}
	t.Setenv("SYSLOG_API_MUTE_LIMIT", "")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.MuteLimit != defaultMuteLimit {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
}

func TestAPIMuteHostSubsetAndMatch(t *testing.T) {
	f := muteServer(t, 0)
	// A host not on the finding refuses the whole request.
	resp := mute(t, f, "2", url.Values{"reason": {"x"}, "host": {"dhcp01.example.test", "dhcp09.example.test"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("host off finding = %d, want 400", resp.StatusCode)
	}
	var e map[string]string
	decodeJSON(t, resp, &e)
	if !strings.Contains(e["error"], "dhcp09.example.test") {
		t.Errorf("error should name the host: %q", e["error"])
	}
	// A regex that does not compile is a 400 carrying the compiler's words.
	resp = mute(t, f, "2", url.Values{"reason": {"x"}, "match": {"no free ("}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad regex = %d, want 400", resp.StatusCode)
	}
	decodeJSON(t, resp, &e)
	if !strings.Contains(e["error"], "regex") {
		t.Errorf("error = %q", e["error"])
	}
	if n := knownsCount(t, f); n != 0 {
		t.Fatalf("refusals wrote %d rows", n)
	}

	// One host of two, with a regex: one row carrying program AND match.
	resp = mute(t, f, "2", url.Values{"reason": {"pool-less"}, "host": {"dhcp02.example.test"}, "match": {"no free leases"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("subset mute = %d", resp.StatusCode)
	}
	var body struct {
		Entries []muteEntry `json:"entries"`
	}
	decodeJSON(t, resp, &body)
	if len(body.Entries) != 1 || body.Entries[0].Host != "dhcp02.example.test" ||
		body.Entries[0].Program != "dhcpd" || body.Entries[0].Match != "no free leases" {
		t.Fatalf("entries = %+v", body.Entries)
	}
	// The stored entry drops only matching dhcpd lines on that host.
	kk, err := f.lib.LoadKnownKnowns(day(2026, 9, 8))
	if err != nil {
		t.Fatal(err)
	}
	if !kk.LineIgnored("dhcp02.example.test", "dhcpd", "no free leases") ||
		kk.LineIgnored("dhcp02.example.test", "dhcpd", "lease database rewritten") ||
		kk.LineIgnored("dhcp01.example.test", "dhcpd", "no free leases") {
		t.Error("match entry should drop only the matching line on dhcp02")
	}
	if !kk.AnomalyMuted("dhcp02.example.test", "dhcpd") || kk.AnomalyMuted("dhcp01.example.test", "dhcpd") {
		t.Error("program+match entry should mute the anomaly on dhcp02 only")
	}

	// Same host and program with the same match: 409. A different match: a new row.
	if resp := mute(t, f, "2", url.Values{"reason": {"again"}, "host": {"dhcp02.example.test"}, "match": {"no free leases"}}); resp.StatusCode != http.StatusConflict {
		t.Errorf("identical mute = %d, want 409", resp.StatusCode)
	}
	if resp := mute(t, f, "2", url.Values{"reason": {"broader"}, "host": {"dhcp02.example.test"}}); resp.StatusCode != http.StatusCreated {
		t.Errorf("program-only after match = %d, want 201", resp.StatusCode)
	}
	if n := knownsCount(t, f); n != 2 {
		t.Errorf("rows = %d, want 2", n)
	}
}

func TestAPIMuteJSONHostArray(t *testing.T) {
	f := muteServer(t, 0)
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+"/api/findings/2/mute",
		strings.NewReader(`{"reason":"json","host":["dhcp01.example.test"]}`))
	req.Header.Set("Authorization", "Bearer "+f.raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Entries []muteEntry `json:"entries"`
	}
	decodeJSON(t, resp, &body)
	if resp.StatusCode != http.StatusCreated || len(body.Entries) != 1 || body.Entries[0].Host != "dhcp01.example.test" {
		t.Errorf("status %d entries %+v", resp.StatusCode, body.Entries)
	}
}

func TestAPIKnownsListAndUnmute(t *testing.T) {
	f := muteServer(t, 0)
	// Unauthenticated DELETE is refused like every other API call.
	if resp := apiRequest(t, http.MethodDelete, f.ts.URL+"/api/knowns/1", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous delete = %d, want 401", resp.StatusCode)
	}
	// A CLI free-form row, an expired CLI row, and an API mute of finding 2 (two hosts).
	exp := day(2020, 1, 1)
	if _, err := f.lib.AddKnownEntries([]reporter.KnownEntryInput{
		{Host: "dhcp01.example.test", Program: "cron", Reason: "hand-written", Added: day(2026, 9, 1), Source: reporter.KnownSourceCLI},
		{Host: "oldbox.example.test", Program: "cron", Reason: "lapsed", Added: day(2019, 1, 1), Expires: &exp, Source: reporter.KnownSourceCLI},
	}); err != nil {
		t.Fatal(err)
	}
	if resp := mute(t, f, "2", url.Values{"reason": {"pool-less"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("mute = %d", resp.StatusCode)
	}

	list := func(query string) []muteEntry {
		t.Helper()
		resp := apiRequest(t, http.MethodGet, f.ts.URL+"/api/knowns"+query, f.raw, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list%s = %d", query, resp.StatusCode)
		}
		var body struct {
			Entries []muteEntry `json:"entries"`
		}
		decodeJSON(t, resp, &body)
		return body.Entries
	}
	all := list("")
	if len(all) != 3 || all[0].Source != "api" && all[0].Source != "cli" {
		t.Fatalf("default list = %+v", all)
	}
	if got := list("?all=1"); len(got) != 4 || got[1].Host != "oldbox.example.test" {
		t.Errorf("all=1 list = %+v", got)
	}
	if got := list("?host=dhcp01.example.test"); len(got) != 2 {
		t.Errorf("host filter = %+v", got)
	}
	forFinding := list("?finding_id=2")
	if len(forFinding) != 2 || forFinding[0].CreatedBy != "opsuser" || forFinding[0].FindingID == nil {
		t.Fatalf("finding filter = %+v", forFinding)
	}
	if resp := apiRequest(t, http.MethodGet, f.ts.URL+"/api/knowns?finding_id=x", f.raw, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad finding_id = %d, want 400", resp.StatusCode)
	}

	// Delete one entry by id; a second delete is a 404.
	target := strconv.FormatInt(forFinding[0].ID, 10)
	resp := apiRequest(t, http.MethodDelete, f.ts.URL+"/api/knowns/"+target, f.raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	var del struct {
		Deleted int   `json:"deleted"`
		ID      int64 `json:"id"`
	}
	decodeJSON(t, resp, &del)
	if del.Deleted != 1 || del.ID != forFinding[0].ID {
		t.Errorf("delete body = %+v", del)
	}
	if resp := apiRequest(t, http.MethodDelete, f.ts.URL+"/api/knowns/"+target, f.raw, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", resp.StatusCode)
	}

	// Undo the finding: removes its remaining row, leaves the CLI rows alone.
	resp = apiRequest(t, http.MethodDelete, f.ts.URL+"/api/findings/2/mute", f.raw, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unmute finding = %d", resp.StatusCode)
	}
	var undo struct {
		Deleted int     `json:"deleted"`
		IDs     []int64 `json:"ids"`
	}
	decodeJSON(t, resp, &undo)
	if undo.Deleted != 1 || len(undo.IDs) != 1 || undo.IDs[0] != forFinding[1].ID {
		t.Errorf("undo body = %+v", undo)
	}
	if got := list("?all=1"); len(got) != 2 || got[0].Source != "cli" || got[1].Source != "cli" {
		t.Errorf("after undo = %+v", got)
	}
	// Idempotent: nothing left to undo is still 200, deleted 0.
	resp = apiRequest(t, http.MethodDelete, f.ts.URL+"/api/findings/2/mute", f.raw, "")
	decodeJSON(t, resp, &undo)
	if resp.StatusCode != http.StatusOK || undo.Deleted != 0 {
		t.Errorf("second undo = %d %+v", resp.StatusCode, undo)
	}
	if resp := apiRequest(t, http.MethodDelete, f.ts.URL+"/api/findings/999/mute", f.raw, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unmute missing finding = %d, want 404", resp.StatusCode)
	}
}
