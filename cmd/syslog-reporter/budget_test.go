package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// Each stub request reports 400 prompt tokens.
func fakeSpendingLLM(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": `{}`}}},
			"usage":   map[string]any{"prompt_tokens": 400, "completion_tokens": 1},
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")
	t.Cleanup(func() { llm.SetBudget(0, 0, nil) })
}

func complete(t *testing.T) error {
	t.Helper()
	return llm.Complete(context.Background(), "openai/test-model", "s", "u", "X", map[string]any{}, new(any))
}

// The hole srg-ZqQMU closes: an attempt spends real tokens then fails for
// some other reason (rate limits, SMTP), and the next hourly attempt is a
// new process. It must start from what today already cost, not from zero.
func TestBudgetIsSharedAcrossAttemptsOnOneDay(t *testing.T) {
	fakeSpendingLLM(t)
	path := filepath.Join(t.TempDir(), "syslog.db")
	log := &logger{}

	first, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := startBudget(log, first, 1000); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := complete(t); err != nil {
			t.Fatalf("attempt 1 request %d: %v", i+1, err)
		}
	}
	first.Close() // attempt 1 dies here, 800 spent

	second, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := startBudget(log, second, 1000); err != nil {
		t.Fatal(err)
	}
	if err := complete(t); err != nil {
		t.Fatalf("attempt 2 first request (800 carried in, under 1000): %v", err)
	}
	if err := complete(t); !errors.Is(err, llm.ErrBudget) {
		t.Fatalf("attempt 2 second request: err %v, want ErrBudget at 1200 of 1000", err)
	}
	if n, _ := second.PromptTokensSpent(time.Now()); n != 1200 {
		t.Errorf("recorded spend = %d, want 1200", n)
	}
}

func TestBudgetCommandShowsAndResetsToday(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog.db")
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	yesterday := time.Now().AddDate(0, 0, -1)
	lib.AddPromptTokens(time.Now(), 1500)
	lib.AddPromptTokens(yesterday, 700)
	lib.Close()
	t.Setenv("SYSLOG_MAX_PROMPT_TOKENS", "2000")
	today := time.Now().Format("2006-01-02")

	if out, code := runCommand(t, "budget", "--db", path); code != 0 || out != today+": 1500 of 2000 prompt tokens spent\n" {
		t.Errorf("show: %d %q", code, out)
	}
	if out, code := runCommand(t, "budget", "reset", "--db", path); code != 0 || out != today+": spend reset from 1500 to 0 prompt tokens\n" {
		t.Errorf("reset: %d %q", code, out)
	}

	lib, err = reporter.OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Close()
	if n, _ := lib.PromptTokensSpent(time.Now()); n != 0 {
		t.Errorf("today after reset = %d, want 0", n)
	}
	if n, _ := lib.PromptTokensSpent(yesterday); n != 700 {
		t.Errorf("yesterday after reset = %d, want 700 (untouched)", n)
	}
}
