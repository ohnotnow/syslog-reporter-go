package web

// Tests for the noise review page (ait srg-OymJL.3). Fictional hosts and
// programs only.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// seedNoisePool stores n shapes named prog00, prog01... for yesterday.
func seedNoisePool(t *testing.T, lib *reporter.LibraryStore, n int) {
	t.Helper()
	var shapes []reporter.NoiseShape
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("prog%02d", i)
		shapes = append(shapes, reporter.NoiseShape{Program: p, Template: "did a thing <n> times",
			Example: p + "[7]: did a thing 3 times", ExampleHost: "web1.example.test", Lines: 5, Hosts: 2})
	}
	if _, err := lib.ReplaceNoiseShapes(time.Now().AddDate(0, 0, -1), shapes); err != nil {
		t.Fatal(err)
	}
}

var shownID = regexp.MustCompile(`name="shown" value="(\d+)"`)

func shownIDs(body string) []string {
	var ids []string
	for _, m := range shownID.FindAllStringSubmatch(body, -1) {
		ids = append(ids, m[1])
	}
	return ids
}

func programsShown(body string) []string {
	return regexp.MustCompile(`<strong>(prog\d\d)</strong>`).FindAllString(body, -1)
}

func TestNoisePageShowsTenAndHidesMutedAndJudged(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	seedNoisePool(t, s.lib, 14)
	uid, err := s.lib.CreateUser("opsuser", "ops@example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	// prog00 is muted by a current entry; prog01 was judged last week.
	if _, err := s.lib.AddKnownEntries([]reporter.KnownEntryInput{{Host: "*", Match: `prog00\[\d+\]: did`,
		Reason: "test", Added: time.Now(), Source: reporter.KnownSourceCLI}}); err != nil {
		t.Fatal(err)
	}
	pool, _ := s.lib.SampleNoiseShapes(100, time.Time{}, nil)
	for _, sh := range pool {
		if sh.Program == "prog01" {
			if err := s.lib.RecordNoiseVerdicts(uid, nil, []reporter.NoiseShape{sh}, time.Now().AddDate(0, 0, -7)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 5; i++ { // random draw: check the exclusions hold every time
		rec := get(t, s, "/noise")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /noise = %d", rec.Code)
		}
		body := rec.Body.String()
		if n := len(shownIDs(body)); n != noiseSampleSize {
			t.Fatalf("%d rows, want %d", n, noiseSampleSize)
		}
		if strings.Contains(body, "<strong>prog00</strong>") || strings.Contains(body, "<strong>prog01</strong>") {
			t.Errorf("a muted or recently judged shape was shown: %v", programsShown(body))
		}
		// auth mode none: rows, but no Save button.
		if strings.Contains(body, "Save and show more") || !strings.Contains(body, "Saving needs a login") {
			t.Error("anonymous page should show the login notice instead of Save")
		}
		if !strings.Contains(body, `aria-current="page">Noise review`) {
			t.Error("nav item not marked current")
		}
	}
}

func TestNoiseSaveRefusedWithoutALogin(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	seedNoisePool(t, s.lib, 3)
	ids := shownIDs(get(t, s, "/noise").Body.String())
	form := url.Values{"shown": ids, "noise": ids[:1]}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/noise", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous save = %d, want 403", rec.Code)
	}
	if entries, _ := s.lib.ListKnownEntries(); len(entries) != 0 {
		t.Errorf("anonymous save wrote %d mutes", len(entries))
	}
	if left, _ := s.lib.SampleNoiseShapes(100, time.Now().AddDate(0, 0, -30), nil); len(left) != 3 {
		t.Errorf("anonymous save recorded verdicts: %d shapes left", len(left))
	}
}

func TestNoiseSaveMutesTickedAndKeepsTheRest(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	seedNoisePool(t, lib, 4)
	ts := newLocalServer(t, lib)
	client := sessionClient(t)
	if _, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/noise"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(ts.URL + "/noise")
	if err != nil {
		t.Fatal(err)
	}
	page := bodyOf(t, resp)
	if !strings.Contains(page, "Save and show more") {
		t.Fatal("logged-in page lacks the Save button")
	}
	ids := shownIDs(page)
	if len(ids) != 4 {
		t.Fatalf("%d rows, want 4", len(ids))
	}
	// Tick the first; an unknown id in either list is ignored.
	form := url.Values{"shown": append(ids, "99999"), "noise": {ids[0], "99999"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/noise", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	frag := bodyOf(t, resp)
	for _, want := range []string{"Muted 1, kept 3.", `hx-swap-oob="innerHTML"`, "Nothing left to review"} {
		if !strings.Contains(frag, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	if strings.Contains(frag, "<html") {
		t.Error("htmx save should return the panel, not a page")
	}

	entries, err := lib.ListKnownEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("mutes = %+v, %v", entries, err)
	}
	e := entries[0]
	if e.Host != "*" || e.Source != reporter.KnownSourceWeb || e.CreatedBy != "opsuser" ||
		!strings.HasPrefix(e.Reason, "web review: 5 lines on 2 hosts on ") {
		t.Errorf("mute = %+v", e)
	}
	knowns, _ := lib.LoadKnownKnowns(time.Now())
	muted := 0
	// A cut-off in the future counts no verdict, so this is the whole pool.
	pool, _ := lib.SampleNoiseShapes(100, time.Now().AddDate(1, 0, 0), nil)
	if len(pool) != 4 {
		t.Fatalf("whole pool = %d shapes, want 4", len(pool))
	}
	for _, sh := range pool {
		if knowns.LineIgnored(sh.ExampleHost, sh.Program, sh.Example) {
			muted++
		}
	}
	if muted != 1 {
		t.Errorf("the mute drops %d of the pool's examples, want exactly the ticked one", muted)
	}
	// Every shown shape now has a verdict, so nothing is left to draw.
	if left, _ := lib.SampleNoiseShapes(100, time.Now().AddDate(0, 0, -30), nil); len(left) != 0 {
		t.Errorf("%d shapes still in the draw after the save", len(left))
	}
}

func TestNoisePageEmptyPoolAndEscaping(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	if body := get(t, s, "/noise").Body.String(); !strings.Contains(body, "No shapes yet. The daily run fills this page.") {
		t.Error("empty pool message missing")
	}
	if _, err := s.lib.ReplaceNoiseShapes(time.Now(), []reporter.NoiseShape{{Program: "evil",
		Template: "<script>alert(1)</script>", Example: "evil: <script>alert(1)</script>",
		ExampleHost: "web1.example.test", Lines: 1, Hosts: 1}}); err != nil {
		t.Fatal(err)
	}
	body := get(t, s, "/noise").Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("log text was not escaped")
	}
}

// A shape whose regex does not match its own example is reported, gets no
// mute and no verdict, so it is not hidden for a month while unmuted.
func TestNoiseSaveReportsAnUnmutableShape(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	if _, err := lib.ReplaceNoiseShapes(time.Now(), []reporter.NoiseShape{{Program: "odd",
		Template: "did a thing <n> times", Example: "odd[7]: something else entirely",
		ExampleHost: "web1.example.test", Lines: 1, Hosts: 1}}); err != nil {
		t.Fatal(err)
	}
	ts := newLocalServer(t, lib)
	client := sessionClient(t)
	if _, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/noise"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(ts.URL + "/noise")
	if err != nil {
		t.Fatal(err)
	}
	ids := shownIDs(bodyOf(t, resp))
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/noise",
		strings.NewReader(url.Values{"shown": ids, "noise": ids}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	frag := bodyOf(t, resp)
	if !strings.Contains(frag, "Could not mute odd") || !strings.Contains(frag, "Muted 0, kept 0.") {
		t.Errorf("fragment = %s", frag)
	}
	if entries, _ := lib.ListKnownEntries(); len(entries) != 0 {
		t.Errorf("%d mutes written for an unmutable shape", len(entries))
	}
	if left, _ := lib.SampleNoiseShapes(10, time.Now().AddDate(0, 0, -30), nil); len(left) != 1 {
		t.Error("the unmutable shape got a verdict and left the draw")
	}
}
