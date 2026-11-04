package web

// Tests for the People page (ait srg-xDjoC.4). Fictional users only.

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

var inviteLink = regexp.MustCompile(`id="invite-link" value="([^"]+)"`)

// signedInAdmin returns a client logged in as a fresh admin "boss".
func signedInAdmin(t *testing.T, ts string, lib *reporter.LibraryStore) *http.Client {
	t.Helper()
	createTestUser(t, lib, "boss", "correct horse")
	if err := lib.SetUserAdmin("boss", true); err != nil {
		t.Fatal(err)
	}
	return signedIn(t, ts, lib, "boss")
}

func postPeople(t *testing.T, client *http.Client, target string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, bodyOf(t, resp)
}

func TestPeopleAddIssuesAWorkingLink(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	boss := signedInAdmin(t, ts.URL, lib)

	code, page := postPeople(t, boss, ts.URL+"/people", url.Values{
		"username": {"jsmith"}, "email": {"jsmith@example.test"}, "admin": {"1"}})
	if code != http.StatusOK {
		t.Fatalf("add: %d\n%s", code, page)
	}
	m := inviteLink.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no link shown:\n%s", page)
	}
	host := strings.TrimPrefix(ts.URL, "http://")
	if !strings.HasPrefix(m[1], "https://"+host+"/set-password/") {
		t.Errorf("link %q should use https and the request host", m[1])
	}
	u, _ := lib.UserByUsername("jsmith")
	if u == nil || !u.IsAdmin || u.PasswordHash.Valid {
		t.Fatalf("jsmith: %+v (want an admin with no password yet)", u)
	}

	token := m[1][strings.LastIndex(m[1], "/")+1:]
	if code, body := setPassword(t, ts.URL, token, goodPassword, goodPassword); code != http.StatusOK {
		t.Fatalf("using the link: %d\n%s", code, body)
	}

	resp, err := boss.Get(ts.URL + "/people")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodyOf(t, resp), token) {
		t.Error("a later GET shows the link again")
	}
}

func TestPeopleReissueRetiresTheOldLink(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	boss := signedInAdmin(t, ts.URL, lib)
	_, first := postPeople(t, boss, ts.URL+"/people", url.Values{
		"username": {"jsmith"}, "email": {"jsmith@example.test"}})
	u, _ := lib.UserByUsername("jsmith")
	_, second := postPeople(t, boss, ts.URL+"/people/"+itoa(u.ID)+"/invite", nil)
	old, cur := inviteLink.FindStringSubmatch(first), inviteLink.FindStringSubmatch(second)
	if old == nil || cur == nil || old[1] == cur[1] {
		t.Fatalf("want two different links, got %v and %v", old, cur)
	}
	tok := func(link string) string { return link[strings.LastIndex(link, "/")+1:] }
	if code, _ := setPassword(t, ts.URL, tok(old[1]), goodPassword, goodPassword); code != http.StatusNotFound {
		t.Errorf("old link still works: %d", code)
	}
	if code, _ := setPassword(t, ts.URL, tok(cur[1]), goodPassword, goodPassword); code != http.StatusOK {
		t.Errorf("new link: %d", code)
	}
}

func TestPeopleAddRefusesADuplicate(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	boss := signedInAdmin(t, ts.URL, lib)
	code, page := postPeople(t, boss, ts.URL+"/people", url.Values{
		"username": {"boss"}, "email": {"other@example.test"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(page, `Username &#34;boss&#34; already exists`) {
		t.Errorf("duplicate: %d\n%s", code, page)
	}
	if inviteLink.MatchString(page) {
		t.Error("a link was issued for a refused add")
	}
}

func TestPeopleIsForAdminsOnly(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)
	ops := signedIn(t, ts.URL, lib, "opsuser")
	resp, err := ops.Get(ts.URL + "/people")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "for admins") {
		t.Errorf("GET as non-admin: %d", resp.StatusCode)
	} else if strings.Contains(body, `href="/people"`) {
		t.Error("the nav shows People to a non-admin")
	}
	u, _ := lib.UserByUsername("opsuser")
	for _, target := range []string{"/people", "/people/" + itoa(u.ID) + "/invite"} {
		code, page := postPeople(t, ops, ts.URL+target, url.Values{
			"username": {"sneaky"}, "email": {"sneaky@example.test"}})
		if code != http.StatusForbidden || inviteLink.MatchString(page) {
			t.Errorf("POST %s as non-admin: %d", target, code)
		}
	}
	if s, _ := lib.UserByUsername("sneaky"); s != nil {
		t.Error("a non-admin added a user")
	}
}

func TestPeopleInModeNoneNeedsALogin(t *testing.T) {
	s := newTestServer(t, Config{})
	rec := get(t, s, "/people")
	if !strings.Contains(rec.Body.String(), "needs a login") {
		t.Errorf("mode none: %d\n%s", rec.Code, rec.Body.String())
	}
}
