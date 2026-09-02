package llm

// Token accounting: every Complete call adds the SDK-reported usage to a
// process-wide total. A run logs the total after its LLM stages; eval
// snapshots it between stages.

import "sync"

// Usage is the accumulated token count reported by the provider SDKs.
type Usage struct {
	PromptTokens     int64
	CompletionTokens int64
}

var (
	usageMu    sync.Mutex
	usageTotal Usage
)

func addUsage(prompt, completion int64) {
	usageMu.Lock()
	usageTotal.PromptTokens += prompt
	usageTotal.CompletionTokens += completion
	usageMu.Unlock()
}

// TotalUsage returns the tokens accumulated since process start or the last
// ResetUsage.
func TotalUsage() Usage {
	usageMu.Lock()
	defer usageMu.Unlock()
	return usageTotal
}

// ResetUsage zeroes the accumulated counts.
func ResetUsage() {
	usageMu.Lock()
	usageTotal = Usage{}
	usageMu.Unlock()
}
