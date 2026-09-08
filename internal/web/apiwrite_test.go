package web

// Tests for the mute and feedback endpoints (ait srg-Kj5Q8.6). Fictional
// hosts only.

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// seedMutable stores an anomaly finding (id 1) and a two-host issue finding
// (id 2) whose example line parses to dhcpd, plus one (id 3) whose program
// cannot be derived.
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
}

// muteServer is an API fixture whose known-knowns path is a temp file.
func muteServer(t *testing.T, muteLimit int) (apiFixture, string) {
	t.Helper()
	knowns := filepath.Join(t.TempDir(), "known_knowns.toml")
	t.Setenv("SYSLOG_KNOWN_KNOWNS", knowns)
	if muteLimit > 0 {
		t.Setenv("SYSLOG_API_MUTE_LIMIT", strconv.Itoa(muteLimit))
	}
	f := newAPIServerFromEnv(t)
	seedMutable(t, f.lib)
	return f, knowns
}

func mute(t *testing.T, f apiFixture, id string, form url.Values) *http.Response {
	t.Helper()
	return apiRequest(t, http.MethodPost, f.ts.URL+"/api/findings/"+id+"/mute", f.raw, form.Encode())
}

func TestAPIMuteWritesOneEntryPerHostAndTheFileWorks(t *testing.T) {
	f, knowns := muteServer(t, 0)
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
	if !strings.Contains(body.Entries[0].Reason, "(finding 2, muted by opsuser via API)") ||
		body.Entries[0].Expires == nil || *body.Entries[0].Expires != "2030-01-31" {
		t.Errorf("entry = %+v", body.Entries[0])
	}

	// The written file drops that program's lines on those hosts and no others.
	kk, err := reporter.LoadKnownKnowns(knowns, day(2026, 9, 8))
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
	raw, _ := os.ReadFile(knowns)
	if strings.Count(string(raw), "[[known]]") != 3 {
		t.Errorf("file:\n%s", raw)
	}
}

func TestAPIMuteRefusals(t *testing.T) {
	f, knowns := muteServer(t, 0)
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
	if _, err := os.Stat(knowns); !os.IsNotExist(err) {
		t.Error("a refused mute must not create the file")
	}

	// A duplicate is a 409 and leaves the file byte-identical.
	if resp := mute(t, f, "1", url.Values{"reason": {"first"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first mute = %d", resp.StatusCode)
	}
	before, _ := os.ReadFile(knowns)
	if resp := mute(t, f, "1", url.Values{"reason": {"second"}}); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate mute = %d, want 409", resp.StatusCode)
	}
	after, _ := os.ReadFile(knowns)
	if string(before) != string(after) {
		t.Error("duplicate mute changed the file")
	}
}

func TestAPIMuteDailyCapIsPerToken(t *testing.T) {
	f, _ := muteServer(t, 1)
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
	f, _ := muteServer(t, 0)
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
	f, _ := muteServer(t, 0)
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
	if err != nil || cfg.MuteLimit != defaultMuteLimit || cfg.KnownsPath != "known_knowns.toml" {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
}
