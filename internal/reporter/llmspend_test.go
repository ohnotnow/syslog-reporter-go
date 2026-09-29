package reporter

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPromptTokensSpentSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "library.db")
	today := time.Date(2026, 9, 29, 10, 0, 0, 0, time.Local)

	first := openTestLibrary(t, path)
	if err := first.AddPromptTokens(today, 1200); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := first.AddPromptTokens(today.Add(time.Hour), 300); err != nil {
		t.Fatalf("add later the same day: %v", err)
	}
	first.Close()

	// The next hourly attempt is a new process: it must see 1500, not 0.
	second := openTestLibrary(t, path)
	if n, err := second.PromptTokensSpent(today); err != nil || n != 1500 {
		t.Errorf("spent after reopen = %d, %v; want 1500", n, err)
	}
}

func TestPromptTokensSpentIsPerDay(t *testing.T) {
	lib := newTestLibrary(t)
	monday := time.Date(2026, 9, 28, 16, 0, 0, 0, time.Local)
	tuesday := time.Date(2026, 9, 29, 8, 0, 0, 0, time.Local)
	if err := lib.AddPromptTokens(monday, 900); err != nil {
		t.Fatalf("add: %v", err)
	}
	if n, err := lib.PromptTokensSpent(tuesday); err != nil || n != 0 {
		t.Errorf("a new day spent = %d, %v; want 0", n, err)
	}
}

func TestResetPromptTokensTouchesOnlyThatDay(t *testing.T) {
	lib := newTestLibrary(t)
	monday := time.Date(2026, 9, 28, 16, 0, 0, 0, time.Local)
	tuesday := time.Date(2026, 9, 29, 8, 0, 0, 0, time.Local)
	for _, d := range []time.Time{monday, tuesday} {
		if err := lib.AddPromptTokens(d, 500); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := lib.ResetPromptTokens(tuesday); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if n, _ := lib.PromptTokensSpent(tuesday); n != 0 {
		t.Errorf("reset day spent = %d, want 0", n)
	}
	if n, _ := lib.PromptTokensSpent(monday); n != 500 {
		t.Errorf("other day spent = %d, want 500 (untouched)", n)
	}
}
