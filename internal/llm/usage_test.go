package llm

import (
	"slices"
	"testing"
)

// Usage is kept per model so a run split across two deployments can be
// costed against each one's price; the listing is sorted by name so the
// log order is stable.
func TestUsageIsKeptPerModel(t *testing.T) {
	ResetUsage()
	t.Cleanup(ResetUsage)
	addUsage("azure/gpt-6-astra", 100, 10)
	addUsage("azure/gpt-5.6-luna", 1000, 50)
	addUsage("azure/gpt-6-astra", 200, 20)

	want := []ModelUsage{
		{Model: "azure/gpt-5.6-luna", Usage: Usage{PromptTokens: 1000, CompletionTokens: 50}},
		{Model: "azure/gpt-6-astra", Usage: Usage{PromptTokens: 300, CompletionTokens: 30}},
	}
	if got := UsageByModel(); !slices.Equal(got, want) {
		t.Errorf("UsageByModel() = %+v, want %+v", got, want)
	}
	if got := TotalUsage(); got != (Usage{PromptTokens: 1300, CompletionTokens: 80}) {
		t.Errorf("TotalUsage() = %+v", got)
	}
}
