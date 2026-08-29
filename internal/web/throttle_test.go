package web

// Resource-control tests (srg-so8ja.8): request body bounds, comment
// length cap, and the failed-login throttle. Fictional users only.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginThrottleWindowAndReset(t *testing.T) {
	now := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	th := newLoginThrottle()
	th.now = func() time.Time { return now }

	for i := 0; i < maxLoginFailures; i++ {
		if th.blocked("192.0.2.10") {
			t.Fatalf("blocked after %d failures, limit is %d", i, maxLoginFailures)
		}
		th.fail("192.0.2.10")
	}
	if !th.blocked("192.0.2.10") {
		t.Fatal("not blocked after reaching the failure limit")
	}
	if th.blocked("192.0.2.99") {
		t.Fatal("a different IP must not share the lockout")
	}
	now = now.Add(loginLockout + time.Second)
	if th.blocked("192.0.2.10") {
		t.Fatal("still blocked after the lockout window passed")
	}

	// A success wipes the slate mid-count.
	th.fail("192.0.2.20")
	th.success("192.0.2.20")
	for i := 0; i < maxLoginFailures-1; i++ {
		th.fail("192.0.2.20")
	}
	if th.blocked("192.0.2.20") {
		t.Fatal("success did not reset the failure count")
	}
}

func TestLoginThrottledOverHTTP(t *testing.T) {
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	ts := newLocalServer(t, lib)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	form := url.Values{"username": {"opsuser"}, "password": {"wrong"}}
	for i := 0; i < maxLoginFailures; i++ {
		resp, err := client.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("failed login %d = %d, want 200 (login page re-render)", i+1, resp.StatusCode)
		}
	}
	// Attempt six is refused before any credential check - even with the
	// RIGHT password, so the lockout cannot be raced.
	resp, err := client.PostForm(ts.URL+"/login",
		url.Values{"username": {"opsuser"}, "password": {"correct horse"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("post-lockout login = %d, want 429", resp.StatusCode)
	}
}

func TestOversizedLoginBodyRejected(t *testing.T) {
	lib := newAuthTestStore(t)
	ts := newLocalServer(t, lib)

	big := url.Values{"username": {"opsuser"},
		"password": {strings.Repeat("x", int(maxFormBytes)+1024)}}
	resp, err := http.Post(ts.URL+"/login", "application/x-www-form-urlencoded",
		strings.NewReader(big.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized login body = %d, want 400", resp.StatusCode)
	}
}

func TestFeedbackCommentLengthCap(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	_, anomID := seedDetailFindings(t, s.lib)

	over := strings.Repeat("a", maxCommentRunes+1)
	rec := postFeedback(t, s, anomID, url.Values{
		"verdict": {"worked"}, "comment": {over}}, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-cap comment = %d, want 400", rec.Code)
	}

	atCap := strings.Repeat("b", maxCommentRunes)
	rec = postFeedback(t, s, anomID, url.Values{
		"verdict": {"worked"}, "comment": {atCap}}, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("at-cap comment = %d, want 303", rec.Code)
	}
}

func TestOversizedFeedbackBodyRejected(t *testing.T) {
	s := newTestServer(t, Config{Version: "test"})
	_, anomID := seedDetailFindings(t, s.lib)

	rec := httptest.NewRecorder()
	body := url.Values{"verdict": {"worked"},
		"comment": {strings.Repeat("x", int(maxFormBytes)+1024)}}
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/findings/%d/feedback", anomID),
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized feedback body = %d, want 400", rec.Code)
	}
}
