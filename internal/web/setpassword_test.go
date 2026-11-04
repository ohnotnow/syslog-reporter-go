package web

// Tests for the set-password page (ait srg-xDjoC.3). Fictional users only.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const goodPassword = "violet-kettle-harbour-42"

// newInvitedUser makes an admin and a password-less user with a fresh link.
func newInvitedUser(t *testing.T, lib *reporter.LibraryStore) string {
	t.Helper()
	admin, err := lib.CreateUser("boss", "boss@example.test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	user, err := lib.CreateUser("newbie", "newbie@example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := lib.CreateInvite(user, admin, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func setPassword(t *testing.T, ts string, token, password, again string) (int, string) {
	t.Helper()
	resp, err := http.PostForm(ts+"/set-password/"+token,
		url.Values{"password": {password}, "again": {again}})
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, bodyOf(t, resp)
}

func TestSetPasswordThenSignIn(t *testing.T) {
	lib := newAuthTestStore(t)
	raw := newInvitedUser(t, lib)
	ts := newLocalServer(t, lib)

	resp, err := http.Get(ts.URL + "/set-password/" + raw)
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, `value="newbie"`) {
		t.Fatalf("form: %d\n%s", resp.StatusCode, body)
	}
	if code, body := setPassword(t, ts.URL, raw, goodPassword, goodPassword); code != http.StatusOK || !strings.Contains(body, "Password set") {
		t.Fatalf("set: %d\n%s", code, body)
	}

	client := sessionClient(t)
	resp, err = client.PostForm(ts.URL+"/login", url.Values{
		"username": {"newbie"}, "password": {goodPassword}, "next": {"/"}})
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); strings.Contains(body, "not recognised") {
		t.Error("cannot sign in with the password just set")
	}

	if code, body := setPassword(t, ts.URL, raw, goodPassword+"x", goodPassword+"x"); code != http.StatusNotFound || !strings.Contains(body, "expired or been used") {
		t.Errorf("second use: %d\n%s", code, body)
	}
}

func TestSetPasswordRefusalsKeepTheLinkUsable(t *testing.T) {
	lib := newAuthTestStore(t)
	raw := newInvitedUser(t, lib)
	ts := newLocalServer(t, lib)
	for _, c := range []struct{ name, password, again, want string }{
		{"mismatch", goodPassword, goodPassword + "x", "do not match"},
		{"policy", "Password1!", "Password1!", "at least 15 characters"},
	} {
		code, body := setPassword(t, ts.URL, raw, c.password, c.again)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d, want 422 with %q\n%s", c.name, code, c.want, body)
		}
	}
	if code, _ := setPassword(t, ts.URL, raw, goodPassword, goodPassword); code != http.StatusOK {
		t.Errorf("link unusable after refusals: %d", code)
	}
}

func TestSetPasswordUnknownLink(t *testing.T) {
	ts := newLocalServer(t, newAuthTestStore(t))
	resp, err := http.Get(ts.URL + "/set-password/nonsense")
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Ask an admin for a new one") {
		t.Errorf("unknown link: %d\n%s", resp.StatusCode, body)
	}
}

func TestSetPasswordIsOnlyInLocalMode(t *testing.T) {
	s := newTestServer(t, Config{})
	if rec := get(t, s, "/set-password/anything"); rec.Code != http.StatusNotFound {
		t.Errorf("mode none: GET /set-password = %d, want 404", rec.Code)
	}
}
