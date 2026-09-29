package llm

// The prompt-token budget: a safety net for the day something floods the
// pipeline in a way nothing else catches. On 28 Sep 2026 a crash loop sent
// 25M prompt tokens in one run and was noticed by chance (ait srg-kQYKT).
// Complete refuses once a process has spent its budget, with ErrBudget, so
// the caller can finish the run degraded. It is per process and never
// reset by ResetUsage, which only clears the per-stage log totals.

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
	budgetSpent   int64 // prompt tokens this process, never reset
	budgetReached bool
)

// SetBudget starts a fresh budget of tokens (0 = none), clearing the
// spend and the reached flag. run and digest call it once at startup.
func SetBudget(tokens int64) {
	budgetMu.Lock()
	budgetLimit, budgetSpent, budgetReached = tokens, 0, false
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
	budgetMu.Unlock()
}

// checkBudget runs before every request. The check is against what has
// already been spent, so a run overshoots by at most the one request that
// crossed the line.
func checkBudget() error {
	budgetMu.Lock()
	defer budgetMu.Unlock()
	if budgetLimit > 0 && budgetSpent >= budgetLimit {
		budgetReached = true
		return fmt.Errorf("%w: %d prompt tokens spent, budget %d (SYSLOG_MAX_PROMPT_TOKENS / --max-prompt-tokens)",
			ErrBudget, budgetSpent, budgetLimit)
	}
	return nil
}
