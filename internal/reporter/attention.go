package reporter

// The attention question: "should this log message shape be brought to an
// admin's attention?", asked of Jev or of the Azure OpenAI Decisions API.
// 'knowns discover' (ant ADR srg-uHwCr, ait srg-uh92Y) and the web UI's
// noise review model view (ait srg-OymJL.4) both ask it through
// ScoreAttention, so a shape gets the same question wherever it is scored.

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ohnotnow/syslog-reporter-go/internal/jev"
	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

// The attention question's parts, shared by both scorers and by every
// caller ('knowns discover', the web UI's model view). Jev takes them
// in its object form (attentionQuestion); the Decisions API takes one
// instructions string (attentionInstructions). The not_for sits on the
// yes side: a message is not worth attention merely for containing the
// word error. The evaluation (srg-FGSKN) had it on the no side, which
// says the opposite, so the 0.1 threshold measured there predates the
// fix; re-measure with --preview.
const (
	attentionAsk       = "Should this system log message be brought to a system administrator's attention?"
	attentionFocus     = "Judge whether an admin would want to know or act, given how many lines, hosts and days produced it."
	attentionYesWhat   = "Indicates a failure, error, security event, resource problem, hardware fault or misconfiguration an administrator should act on or know about"
	attentionNoWhat    = "Routine operational chatter: successful or expected events, informational start/stop messages, scheduled jobs running normally, debug output"
	attentionYesNotFor = "A message that merely contains the word error or warning but describes normal behaviour"
)

var (
	attentionYesExamples = []string{
		"kernel: EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0",
		"sshd: Failed password for invalid user <user> from <ip> port <n> ssh2",
		"systemd: <fqdn>.service: Main process exited, code=exited, status=1/FAILURE",
	}
	attentionNoExamples = []string{
		"systemd: Started Daily apt download activities.",
		"sshd: Accepted publickey for <user> from <ip> port <n> ssh2",
		"CRON: (<user>) CMD (/usr/lib/<fqdn> --cron)",
	}
)

var attentionQuestion = map[string]jev.Question{"attention": {
	Type: "noul",
	Instructions: map[string]any{
		"question": attentionAsk,
		"inspect":  "`log.message`",
		"focus":    attentionFocus,
	},
	Criteria: map[string]any{
		"true":  map[string]any{"what": attentionYesWhat, "not_for": attentionYesNotFor, "examples": attentionYesExamples},
		"false": map[string]any{"what": attentionNoWhat, "examples": attentionNoExamples},
	},
}}

// attentionInstructions is the same question as prose.
var attentionInstructions = attentionAsk + " Inspect log.message in the input; the input also gives how many lines, hosts and days produced it. " +
	attentionFocus + "\n\nAnswer yes when it: " + attentionYesWhat + ". This does not cover: " + attentionYesNotFor + ". For example:\n- " + strings.Join(attentionYesExamples, "\n- ") +
	"\n\nAnswer no when it is: " + attentionNoWhat + ". For example:\n- " + strings.Join(attentionNoExamples, "\n- ")

// AttentionShape is what a scorer is shown about one shape: the counts
// ride along so the model judges "this shape, this often, this widely",
// as in the evaluation (srg-FGSKN).
type AttentionShape struct {
	Program, Template  string
	Lines, Hosts, Days int
}

func (s AttentionShape) state() map[string]any {
	return map[string]any{"log": map[string]any{
		"program": s.Program, "message": s.Template,
		"lines_seen": s.Lines, "hosts_seen": s.Hosts, "days_seen": s.Days,
	}}
}

// ScoreAttention returns the probability that the shape needs an admin's
// attention. decisionsModel (azure/<deployment>) picks the Decisions API,
// which sends the state as JSON text and the question as prose; "" picks
// Jev, which takes both as objects. A Decisions refusal comes back as
// llm.ErrRefused for the caller to decide on.
func ScoreAttention(ctx context.Context, decisionsModel string, s AttentionShape) (float64, llm.Usage, error) {
	if decisionsModel != "" {
		input, err := json.Marshal(s.state())
		if err != nil {
			return 0, llm.Usage{}, err
		}
		return llm.Predicate(ctx, decisionsModel, string(input), attentionInstructions)
	}
	resp, err := jev.Ask(ctx, s.state(), attentionQuestion)
	if err != nil {
		return 0, llm.Usage{}, err
	}
	score, err := jev.Noul(resp, "attention")
	if err != nil {
		return 0, llm.Usage{}, err
	}
	return score, llm.Usage{PromptTokens: int64(resp.Usage.InputTokens), CompletionTokens: int64(resp.Usage.OutputTokens)}, nil
}
