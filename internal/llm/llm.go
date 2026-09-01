// Package llm is the one seam between the pipeline and LLM providers.
//
// Model strings use litellm-style prefixes
// ("openai/gpt-4o-mini", "anthropic/claude-sonnet-4-6"):
// the prefix picks the official SDK, the rest
// is passed through as the provider's model id. azure/ rides the OpenAI
// backend against an Azure OpenAI resource's v1 endpoint. Only
// structured-output completions exist in this pipeline, so Complete is the
// whole interface.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	anthropicoption "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"
)

// A batch run would rather wait than fail: Azure in particular throttles
// with Retry-After values far beyond the openai-go default cap (2 retries,
// server waits clamped to 8s), which turns a passing rate-limit squall
// into a dead run within seconds. A nightly cron job has nowhere better to
// be, so both providers get a patient budget: worst case is bounded by
// retries x delay cap, after which the run still fails loudly for cron.
// The Anthropic SDK honours Retry-After uncapped, so it only needs the
// retry count raised.
const (
	llmMaxRetries    = 8
	llmMaxRetryDelay = 2 * time.Minute
)

// Complete sends a system+user prompt to the provider named by the model
// prefix and decodes the JSON structured output (constrained by schema)
// into out. schemaName labels the schema for providers that want a name.
func Complete(ctx context.Context, model, system, user, schemaName string, schema map[string]any, out any) error {
	// Redaction sits here so every provider path is covered and no future
	// agent can forget it (SYSLOG_REDACT; ant ADR srg-Mzvjf).
	user = redactUser(user)
	provider, modelID, ok := strings.Cut(model, "/")
	if !ok {
		return fmt.Errorf("model %q has no provider prefix; use the litellm format, e.g. openai/%s", model, model)
	}
	switch provider {
	case "openai":
		return completeOpenAI(ctx, modelID, system, user, schemaName, schema, out)
	case "azure":
		return completeAzure(ctx, modelID, system, user, schemaName, schema, out)
	case "anthropic":
		return completeAnthropic(ctx, modelID, system, user, schema, out)
	default:
		return fmt.Errorf("unsupported provider prefix %q in model %q (supported: openai/, azure/, anthropic/)", provider, model)
	}
}

// CheckCredentials fails fast when the model's provider is missing its
// API key, so a misconfigured cron run dies at startup with the variable
// named rather than mid-pipeline with an HTTP error. A configured base
// URL waives the key requirement for openai/ and anthropic/ (a local
// keyless endpoint is a supported way to run).
func CheckCredentials(model string) error {
	provider, modelID, ok := strings.Cut(model, "/")
	if !ok {
		return fmt.Errorf("model %q has no provider prefix; use the litellm format, e.g. openai/%s", model, model)
	}
	switch provider {
	case "openai":
		if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("OPENAI_BASE_URL") == "" {
			return fmt.Errorf("openai/%s needs OPENAI_API_KEY set (or OPENAI_BASE_URL for a keyless endpoint)", modelID)
		}
	case "anthropic":
		if os.Getenv("ANTHROPIC_API_KEY") == "" && os.Getenv("ANTHROPIC_BASE_URL") == "" {
			return fmt.Errorf("anthropic/%s needs ANTHROPIC_API_KEY set (or ANTHROPIC_BASE_URL for a keyless endpoint)", modelID)
		}
	case "azure":
		if os.Getenv("AZURE_OPENAI_ENDPOINT") == "" || os.Getenv("AZURE_OPENAI_API_KEY") == "" {
			return fmt.Errorf("azure/%s needs AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY set", modelID)
		}
	default:
		return fmt.Errorf("unsupported provider prefix %q in model %q (supported: openai/, azure/, anthropic/)", provider, model)
	}
	return nil
}

// reasoningEffort reads SYSLOG_REASONING_EFFORT at call time. Unset means
// provider default.
func reasoningEffort() string {
	return os.Getenv("SYSLOG_REASONING_EFFORT")
}

func completeOpenAI(ctx context.Context, modelID, system, user, schemaName string, schema map[string]any, out any) error {
	client := openai.NewClient( // OPENAI_API_KEY / OPENAI_BASE_URL from env
		option.WithMaxRetries(llmMaxRetries),
		option.WithMaxRetryDelay(llmMaxRetryDelay),
	)
	return completeChat(ctx, client, "openai", modelID, system, user, schemaName, schema, out)
}

// completeAzure rides the OpenAI chat path against an Azure OpenAI
// resource's v1 endpoint (https://<resource>.openai.azure.com/openai/v1/).
// The v1 surface behaves like OpenAI proper - model id in the body, bearer
// auth - so none of the SDK's azure subpackage machinery (per-deployment
// URL rewriting, api-version, azcore) is needed. The trailing slash on the
// base URL is load-bearing: request paths resolve relative to it, and
// without the slash the endpoint's final path segment is silently dropped.
func completeAzure(ctx context.Context, modelID, system, user, schemaName string, schema map[string]any, out any) error {
	endpoint := os.Getenv("AZURE_OPENAI_ENDPOINT")
	apiKey := os.Getenv("AZURE_OPENAI_API_KEY")
	if endpoint == "" || apiKey == "" {
		return fmt.Errorf("azure/%s needs AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY set", modelID)
	}
	client := openai.NewClient(
		option.WithBaseURL(strings.TrimRight(endpoint, "/")+"/"),
		option.WithAPIKey(apiKey),
		option.WithMaxRetries(llmMaxRetries),
		option.WithMaxRetryDelay(llmMaxRetryDelay),
		option.WithMiddleware(azureRetryAfterFix),
	)
	return completeChat(ctx, client, "azure", modelID, system, user, schemaName, schema, out)
}

// azureRetryAfterFix works around Azure OpenAI 429s carrying BOTH
// "Retry-After: 30" and "Retry-After-Ms: 0" (observed live, 2026-09-01).
// The SDK prefers the milliseconds header, so the zero turns every backoff
// into an instant retry and the whole retry budget burns in about a
// second. Dropping the lying header lets the honest seconds value (or the
// SDK's own capped exponential backoff) drive the wait.
func azureRetryAfterFix(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	resp, err := next(req)
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		if ms, perr := strconv.ParseFloat(resp.Header.Get("Retry-After-Ms"), 64); perr == nil && ms <= 0 {
			resp.Header.Del("Retry-After-Ms")
		}
	}
	return resp, err
}

func completeChat(ctx context.Context, client openai.Client, provider, modelID, system, user, schemaName string, schema map[string]any, out any) error {
	params := openai.ChatCompletionNewParams{
		Model: modelID,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(system),
			openai.UserMessage(user),
		},
		ResponseFormat: openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &shared.ResponseFormatJSONSchemaParam{
				JSONSchema: shared.ResponseFormatJSONSchemaJSONSchemaParam{
					Name:   schemaName,
					Schema: schema,
					Strict: openai.Bool(true),
				},
			},
		},
	}
	// litellm passes reasoning_effort through verbatim; so do we ("none" is
	// valid for gpt-5-class models and right for batch runs).
	if effort := reasoningEffort(); effort != "" {
		params.ReasoningEffort = shared.ReasoningEffort(effort)
	}
	resp, err := client.Chat.Completions.New(ctx, params)
	if err != nil {
		return fmt.Errorf("%s/%s: %w", provider, modelID, err)
	}
	addUsage(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
	if len(resp.Choices) == 0 {
		return fmt.Errorf("%s/%s: response had no choices", provider, modelID)
	}
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), out); err != nil {
		return fmt.Errorf("%s/%s: decoding structured output: %w", provider, modelID, err)
	}
	return nil
}

// anthropicEffort maps the OpenAI-vocabulary SYSLOG_REASONING_EFFORT values
// onto Anthropic's output_config.effort. "none" and "minimal" have no
// Anthropic equivalent, so they clamp to the floor; everything else passes
// through and the API rejects anything it doesn't know.
func anthropicEffort(effort string) anthropic.OutputConfigEffort {
	switch effort {
	case "none", "minimal":
		return anthropic.OutputConfigEffortLow
	default:
		return anthropic.OutputConfigEffort(effort)
	}
}

func completeAnthropic(ctx context.Context, modelID, system, user string, schema map[string]any, out any) error {
	client := anthropic.NewClient( // ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL from env
		anthropicoption.WithMaxRetries(llmMaxRetries),
	)
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(modelID),
		MaxTokens: 16000,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: schema},
		},
	}
	if effort := reasoningEffort(); effort != "" {
		params.OutputConfig.Effort = anthropicEffort(effort)
	}
	resp, err := client.Messages.New(ctx, params)
	if err != nil {
		return fmt.Errorf("anthropic/%s: %w", modelID, err)
	}
	addUsage(resp.Usage.InputTokens, resp.Usage.OutputTokens)
	var text strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	if text.Len() == 0 {
		return fmt.Errorf("anthropic/%s: response had no text content (stop_reason=%s)", modelID, resp.StopReason)
	}
	if err := json.Unmarshal([]byte(text.String()), out); err != nil {
		return fmt.Errorf("anthropic/%s: decoding structured output: %w", modelID, err)
	}
	return nil
}
