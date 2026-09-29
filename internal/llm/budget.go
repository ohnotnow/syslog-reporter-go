package llm

// The prompt-token budget: a safety net for the day something floods the
// pipeline in a way nothing else catches. On 28 Sep 2026 a crash loop sent
// 25M prompt tokens in one run and was noticed by chance (ait srg-kQYKT).
// Complete refuses once the budget is spent, with ErrBudget, so the caller
// can finish the run degraded. The budget is per calendar day (ait
// srg-ZqQMU): the caller passes in what earlier attempts already spent
// today and a record func that persists each request's spend, so hourly
// cron retries share one budget instead of starting afresh. ResetUsage
// never touches it; it only clears the per-stage log totals.

import (
	"errors"
	"fmt"
	"sync"
)

// DefaultMaxPromptTokens is the default SYSLOG_MAX_PROMPT_TOKENS. A normal
// daily run after collapsing spends roughly 150-300K prompt tokens (the
// 28 Sep flood day, collapsed, about 160K) and a digest well under 100K, so
// this is several times a busy day while capping a runaway at about $4 on
// a $2-per-million model.
const DefaultMaxPromptTokens = 2_000_000

// ErrBudget is returned (wrapped) by Complete once the budget is spent.
var ErrBudget = errors.New("LLM prompt-token budget reached")

var (
	budgetMu      sync.Mutex
	budgetLimit   int64 // 0 = no budget
	budgetSpent   int64 // prompt tokens today: carried in, plus this process
	budgetReached bool
	budgetRecord  func(prompt int64)
)

// SetBudget starts the budget: limit tokens a day (0 = none), of which
// spent are already gone. record, when non-nil, is called with each
// successful request's prompt tokens so the caller can persist them; it
// runs outside the budget lock and may be called concurrently. run and
// digest call SetBudget once at startup.
func SetBudget(limit, spent int64, record func(prompt int64)) {
	budgetMu.Lock()
	budgetLimit, budgetSpent, budgetReached, budgetRecord = limit, spent, false, record
	budgetMu.Unlock()
}

// BudgetReached reports whether any Complete call was refused.
func BudgetReached() bool {
	budgetMu.Lock()
	defer budgetMu.Unlock()
	return budgetReached
}

func spendBudget(prompt int64) {
	budgetMu.Lock()
	budgetSpent += prompt
	record := budgetRecord
	budgetMu.Unlock()
	if record != nil {
		record(prompt)
	}
}

// checkBudget runs before every request. The check is against what has
// already been spent, so a run overshoots by at most the one request that
// crossed the line.
func checkBudget() error {
	budgetMu.Lock()
	defer budgetMu.Unlock()
	if budgetLimit > 0 && budgetSpent >= budgetLimit {
		budgetReached = true
		return fmt.Errorf("%w: %d prompt tokens spent today, budget %d (SYSLOG_MAX_PROMPT_TOKENS / --max-prompt-tokens)",
			ErrBudget, budgetSpent, budgetLimit)
	}
	return nil
}
