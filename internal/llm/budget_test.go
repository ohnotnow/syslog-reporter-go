package llm

import (
	"context"
	"errors"
	"testing"
)

func resetBudget(t *testing.T) {
	t.Helper()
	budgetMu.Lock()
	budgetLimit, budgetSpent, budgetReached = 0, 0, false
	budgetMu.Unlock()
	t.Cleanup(func() {
		budgetMu.Lock()
		budgetLimit, budgetSpent, budgetReached = 0, 0, false
		budgetMu.Unlock()
	})
}

func TestBudgetRefusesOnceSpent(t *testing.T) {
	resetBudget(t)
	SetBudget(1000)
	addUsage("azure/test", 600, 10)
	if err := checkBudget(); err != nil || BudgetReached() {
		t.Fatalf("under budget: err %v, reached %v", err, BudgetReached())
	}
	addUsage("azure/test", 500, 10)
	// ResetUsage clears the per-stage log totals, never the budget.
	ResetUsage()
	err := Complete(context.Background(), "azure/test", "s", "u", "X", map[string]any{}, new(any))
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("over budget: err %v, want ErrBudget", err)
	}
	if !BudgetReached() {
		t.Error("BudgetReached is false after a refusal")
	}
}

func TestBudgetZeroIsOff(t *testing.T) {
	resetBudget(t)
	addUsage("azure/test", 50_000_000, 0)
	if err := checkBudget(); err != nil {
		t.Errorf("no budget set: %v", err)
	}
}
