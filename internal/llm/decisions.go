package llm

// The OpenAI Decisions API (POST <endpoint>/decisions) on an Azure OpenAI
// resource: typed answers, no generated text (ait srg-uh92Y). It is the
// Azure-hosted alternative to Jev for 'knowns discover', so scored log
// shapes stay inside the Azure tenancy; for that reason only azure/ models
// are accepted. The deployment must run gpt-6-luna, the one model the
// endpoint supports; the model field carries the deployment name.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v3"
)

// ErrRefused is returned (wrapped) when the model refuses the question.
// A refusal is not a low probability; the caller decides what it means.
var ErrRefused = errors.New("decisions: question refused")

// CheckDecisionsModel fails fast on a model the Decisions path cannot
// use: anything but azure/<deployment>, or missing Azure credentials.
func CheckDecisionsModel(model string) error {
	provider, deployment, ok := strings.Cut(model, "/")
	if !ok || provider != "azure" || deployment == "" {
		return fmt.Errorf("decisions model %q must be azure/<deployment> (the Decisions API is used through Azure only)", model)
	}
	return CheckCredentials(model)
}

// Predicate asks one yes/no question about input and returns the
// probability that the answer is yes. Like Complete it checks the budget
// first, scrubs what it sends (SYSLOG_SCRUB*; the reply is a number, so
// there is nothing to reverse) and adds the reported tokens to the usage
// totals; it also returns that request's tokens.
func Predicate(ctx context.Context, model, input, instructions string) (float64, Usage, error) {
	if err := CheckDecisionsModel(model); err != nil {
		return 0, Usage{}, err
	}
	if err := checkBudget(); err != nil {
		return 0, Usage{}, err
	}
	_, deployment, _ := strings.Cut(model, "/")
	client, err := azureClient(deployment)
	if err != nil {
		return 0, Usage{}, err
	}
	scrubbed, _ := scrubAll(input, instructions)
	resp, err := client.Decisions.New(ctx, openai.DecisionNewParams{
		Model: deployment,
		Input: openai.DecisionNewParamsInputUnion{OfString: openai.String(scrubbed[0])},
		Questions: []openai.DecisionNewParamsQuestionUnion{{OfPredicate: &openai.DecisionNewParamsQuestionPredicate{
			Name:         openai.String("q"),
			Instructions: openai.DecisionNewParamsQuestionPredicateInstructionsUnion{OfString: openai.String(scrubbed[1])},
		}}},
	})
	if err != nil {
		return 0, Usage{}, fmt.Errorf("%s: %w", model, err)
	}
	usage := Usage{PromptTokens: resp.Usage.InputTokens, CompletionTokens: resp.Usage.OutputTokens}
	addUsage(model, usage.PromptTokens, usage.CompletionTokens)
	if len(resp.Answers) != 1 {
		return 0, usage, fmt.Errorf("%s: want 1 answer, got %d", model, len(resp.Answers))
	}
	switch a := resp.Answers[0]; a.Type {
	case "predicate":
		if !a.JSON.Probability.Valid() {
			return 0, usage, fmt.Errorf("%s: predicate answer has no probability", model)
		}
		return a.Probability, usage, nil
	case "refusal":
		return 0, usage, fmt.Errorf("%s: %w", model, ErrRefused)
	default:
		return 0, usage, fmt.Errorf("%s: unexpected answer type %q", model, a.Type)
	}
}
