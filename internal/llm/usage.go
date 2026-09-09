package llm

// Token accounting: every Complete call adds the SDK-reported usage to a
// process-wide total, kept per model so a run split across two
// deployments can be costed against each one's price. A run logs one
// line per model after its LLM stages; eval snapshots the total between
// stages.

import (
	"sort"
	"sync"
)

// Usage is the accumulated token count reported by the provider SDKs.
type Usage struct {
	PromptTokens     int64
	CompletionTokens int64
}

// ModelUsage is one model's share of the run's tokens.
type ModelUsage struct {
	Model string // full litellm-style name, e.g. azure/gpt-6-astra
	Usage
}

var (
	usageMu      sync.Mutex
	usageByModel = map[string]Usage{}
)

func addUsage(model string, prompt, completion int64) {
	usageMu.Lock()
	u := usageByModel[model]
	u.PromptTokens += prompt
	u.CompletionTokens += completion
	usageByModel[model] = u
	usageMu.Unlock()
}

// TotalUsage returns the tokens accumulated across every model since
// process start or the last ResetUsage.
func TotalUsage() Usage {
	var total Usage
	for _, m := range UsageByModel() {
		total.PromptTokens += m.PromptTokens
		total.CompletionTokens += m.CompletionTokens
	}
	return total
}

// UsageByModel returns each model's accumulated tokens, sorted by model
// name so the log order never depends on map iteration.
func UsageByModel() []ModelUsage {
	usageMu.Lock()
	defer usageMu.Unlock()
	out := make([]ModelUsage, 0, len(usageByModel))
	for model, u := range usageByModel {
		out = append(out, ModelUsage{Model: model, Usage: u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Model < out[j].Model })
	return out
}

// ResetUsage zeroes the accumulated counts.
func ResetUsage() {
	usageMu.Lock()
	usageByModel = map[string]Usage{}
	usageMu.Unlock()
}
