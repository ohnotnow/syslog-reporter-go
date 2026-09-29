package llm

import (
	"context"
	"errors"
	"testing"
)

func resetBudget(t *testing.T) {
	t.Helper()
	budgetMu.Lock()
	budgetLimit, budgetSpent, budgetReached, budgetRecord = 0, 0, false, nil
	budgetMu.Unlock()
	t.Cleanup(func() {
		budgetMu.Lock()
		budgetLimit, budgetSpent, budgetReached, budgetRecord = 0, 0, false, nil
		budgetMu.Unlock()
	})
}

func TestBudgetRefusesOnceSpent(t *testing.T) {
	resetBudget(t)
	SetBudget(1000, 0, nil)
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

func TestBudgetCarriesInEarlierSpend(t *testing.T) {
	resetBudget(t)
	// An earlier attempt today spent 900 of 1000: this one gets 100.
	SetBudget(1000, 900, nil)
	addUsage("azure/test", 100, 0)
	if err := checkBudget(); !errors.Is(err, ErrBudget) {
		t.Fatalf("err %v, want ErrBudget once carried-in plus new spend reaches the limit", err)
	}
}

func TestBudgetRecordsEachSpend(t *testing.T) {
	resetBudget(t)
	var got []int64
	SetBudget(0, 0, func(prompt int64) { got = append(got, prompt) })
	addUsage("azure/test", 40, 5)
	addUsage("azure/other", 2, 1)
	if len(got) != 2 || got[0] != 40 || got[1] != 2 {
		t.Errorf("recorded %v, want [40 2] (prompt tokens only, recorded even with no limit)", got)
	}
}
