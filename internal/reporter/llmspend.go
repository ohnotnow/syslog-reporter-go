package reporter

// The per-day prompt-token ledger behind SYSLOG_MAX_PROMPT_TOKENS
// (migration 7, ait srg-ZqQMU). llm keeps the running total in memory;
// this is where it survives the process, so the hourly cron retries of a
// failed run start from what today already cost rather than from zero.

import (
	"database/sql"
	"errors"
	"time"
)

func spendDay(day time.Time) string { return day.Format("2006-01-02") }

// PromptTokensSpent returns the prompt tokens recorded for day's local
// calendar date; a day with no row has spent nothing.
func (s *LibraryStore) PromptTokensSpent(day time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow("SELECT prompt_tokens FROM llm_spend WHERE day = ?", spendDay(day)).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// AddPromptTokens adds n to day's total in one statement, so concurrent
// callers cannot lose an update.
func (s *LibraryStore) AddPromptTokens(day time.Time, n int64) error {
	_, err := s.db.Exec(`INSERT INTO llm_spend (day, prompt_tokens) VALUES (?, ?)
ON CONFLICT (day) DO UPDATE SET prompt_tokens = prompt_tokens + excluded.prompt_tokens`,
		spendDay(day), n)
	return err
}

// ResetPromptTokens forgets day's spend, giving it a fresh budget. Other
// days are untouched.
func (s *LibraryStore) ResetPromptTokens(day time.Time) error {
	_, err := s.db.Exec("DELETE FROM llm_spend WHERE day = ?", spendDay(day))
	return err
}
