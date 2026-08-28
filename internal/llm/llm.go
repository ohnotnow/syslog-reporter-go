// Package llm is the one seam between the pipeline and LLM providers.
//
// Model strings keep the litellm format the Python original used
// ("openai/gpt-4o-mini", "anthropic/claude-sonnet-4-6") so every existing
// .env carries over unchanged: the prefix picks the official SDK, the rest
// is passed through as the provider's model id. Only structured-output
// completions exist in this pipeline, so Complete is the whole interface.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/shared"
)

// Complete sends a system+user prompt to the provider named by the model
// prefix and decodes the JSON structured output (constrained by schema)
// into out. schemaName labels the schema for providers that want a name.
func Complete(ctx context.Context, model, system, user, schemaName string, schema map[string]any, out any) error {
	provider, modelID, ok := strings.Cut(model, "/")
	if !ok {
		return fmt.Errorf("model %q has no provider prefix; use the litellm format, e.g. openai/%s", model, model)
	}
	switch provider {
	case "openai":
		return completeOpenAI(ctx, modelID, system, user, schemaName, schema, out)
	case "anthropic":
		return completeAnthropic(ctx, modelID, system, user, schema, out)
	default:
		return fmt.Errorf("unsupported provider prefix %q in model %q (supported: openai/, anthropic/)", provider, model)
	}
}

// reasoningEffort reads SYSLOG_REASONING_EFFORT at call time, mirroring the
// Python agents/llm.py wrapper. Unset means provider default.
func reasoningEffort() string {
	return os.Getenv("SYSLOG_REASONING_EFFORT")
}

func completeOpenAI(ctx context.Context, modelID, system, user, schemaName string, schema map[string]any, out any) error {
	client := openai.NewClient() // OPENAI_API_KEY / OPENAI_BASE_URL from env
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
		return fmt.Errorf("openai/%s: %w", modelID, err)
	}
	if len(resp.Choices) == 0 {
		return fmt.Errorf("openai/%s: response had no choices", modelID)
	}
	content := resp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), out); err != nil {
		return fmt.Errorf("openai/%s: decoding structured output: %w", modelID, err)
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
	client := anthropic.NewClient() // ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL from env
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
