package main

// The weekly digest (ait srg-xiBoC.7, ant ADR srg-WtzbG): read the findings
// library over a window of days, group the daily findings across days,
// rank by recurrence, hand only the top groups to the smart model, file
// the result as a run of kind digest, write the files, email it. No dump,
// no log scan, no stored "last digest" state: a missed week is recovered
// by running it by hand with a bigger --days.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
	"github.com/ohnotnow/syslog-reporter-go/internal/selfupdate"
)

// Digest caps: how many recurring groups get the smart model's prose and
// the email's attention. Everything else still reaches the attachment.
const (
	defaultDigestIssues    = 10
	defaultDigestOneOffs   = 5
	defaultDigestAnomalies = 5
)

// digestModel resolves the digest's one model: SYSLOG_DIGEST_MODEL, then
// SYSLOG_ISSUE_MODEL, then the --model fallback. So the .env can hold the
// cheap daily models and one smart weekly one, with nothing per crontab
// line.
func digestModel(fallback string) string {
	return getenvDefault("SYSLOG_DIGEST_MODEL", getenvDefault("SYSLOG_ISSUE_MODEL", fallback))
}

func runDigest(args []string) {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	setUsage(fs, digestHelpIntro, digestHelpEnv)
	days := fs.Int("days", 7, "Number of days the digest covers, ending yesterday")
	model := fs.String("model", getenvDefault("SYSLOG_DEFAULT_MODEL", "openai/gpt-5.6-luna"),
		"Fallback model (litellm format); SYSLOG_DIGEST_MODEL, then SYSLOG_ISSUE_MODEL, override it")
	maxIssues := fs.Int("max-issues", defaultDigestIssues,
		"Recurring issue groups sent to the resolution writer and shown in the email")
	maxOneOffs := fs.Int("max-one-offs", defaultDigestOneOffs,
		"Single-day critical/high issue groups shown after them, with the daily run's own advice (no model call)")
	maxAnomalies := fs.Int("max-anomalies", defaultDigestAnomalies,
		"Recurring anomaly groups explained and shown in the email")
	sendEmail := fs.Bool("send-email", false, "Email the digest to the recipients")
	recipients := fs.String("recipients", "",
		"Comma-separated recipient addresses (default: SYSLOG_SMTP_RECIPIENTS)")
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"Path to the SQLite database")
	outDir := fs.String("out-dir", ".", "Directory the digest files are written to (must exist)")
	noLLM := fs.Bool("no-llm", false,
		"Skip the resolution writer and anomaly explainer so the digest costs nothing")
	noStore := fs.Bool("no-store", false,
		"Don't file the digest in the findings library (no finding ids or mute lines in the email)")
	debug := fs.Bool("debug", false, "Print extra debug information")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatal("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *days < 1 {
		fatal("--days must be at least 1")
	}
	if *maxIssues < 0 || *maxOneOffs < 0 || *maxAnomalies < 0 {
		fatal("--max-issues, --max-one-offs and --max-anomalies cannot be negative")
	}
	log := &logger{debugEnabled: *debug}

	if info, err := os.Stat(*outDir); err != nil || !info.IsDir() {
		fatal("--out-dir %s is not an existing directory", *outDir)
	}
	to := *recipients
	if to == "" {
		to = os.Getenv("SYSLOG_SMTP_RECIPIENTS")
	}
	if *sendEmail {
		if to == "" {
			fatal("--send-email needs --recipients or SYSLOG_SMTP_RECIPIENTS to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SERVER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SERVER to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SENDER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SENDER to be set")
		}
	} else if *recipients != "" {
		log.Warn("--recipients given but --send-email not set; no email will be sent")
	}
	digestModel := digestModel(*model)
	if !*noLLM {
		if err := llm.CheckCredentials(digestModel); err != nil {
			fatal("%v", err)
		}
		if err := llm.CheckReasoningEffort(); err != nil {
			fatal("%v", err)
		}
	}
	// The digest is a reader; a missing db is a typo'd path.
	if err := reporter.RequireDatabase(*dbPath); err != nil {
		fatal("%v", err)
	}

	// The window ends yesterday like mgmt-report: log dates cover completed
	// days, and a calendar anchor keeps a stalled cron visible as missing
	// days rather than a stale week.
	toDate := time.Now().AddDate(0, 0, -1)
	fromDate := toDate.AddDate(0, 0, -(*days - 1))
	from, until := fromDate.Format("2006-01-02"), toDate.Format("2006-01-02")

	lib, err := reporter.OpenLibraryStore(*dbPath)
	if err != nil {
		fatal("opening findings library %s: %v", *dbPath, err)
	}
	defer lib.Close()
	runs, err := lib.ListRuns(from, until)
	if err != nil {
		fatal("listing runs: %v", err)
	}
	findings, err := lib.DailyFindings(from, until)
	if err != nil {
		fatal("reading findings: %v", err)
	}
	digest := reporter.BuildDigest(from, until, runs, findings)
	log.Info("Digest %s to %s: %d daily runs, %d issue groups (%d recurring), %d anomaly groups",
		from, until, len(digest.RunDays), len(digest.Issues), len(digest.Recurring()), len(digest.Anomalies))
	if len(digest.MissingDays) > 0 {
		log.Warn("No daily run recorded for: %s", strings.Join(digest.MissingDays, ", "))
	}

	runDays := len(digest.RunDays)
	issues := &reporter.IssueList{Issues: digest.RecurringIssues(*maxIssues, runDays)}
	oneOffIssues, oneOffResolutions := digest.OneOffIssues(*maxOneOffs, runDays)
	oneOffs := &reporter.IssueList{Issues: oneOffIssues}
	var anomalies []reporter.Anomaly
	for _, g := range digest.Anomalies[:min(*maxAnomalies, len(digest.Anomalies))] {
		anomalies = append(anomalies, &reporter.DigestAnomaly{Group: g, RunDays: runDays})
	}

	ctx := context.Background()
	resolutions := &reporter.ResolutionList{}
	var explained []*reporter.ExplainedAnomaly
	if *noLLM {
		log.Info("--no-llm: rendering the digest without resolutions or explanations")
		explained = reporter.FactsOnlyN(anomalies, len(anomalies))
	} else {
		if len(issues.Issues) > 0 {
			log.Info("Resolving %d recurring issues with %s", len(issues.Issues), digestModel)
			// No context windows (the dumps are not re-read) and no host OS
			// map: each issue's own OS field travels in its markdown.
			resolutions, err = reporter.NewResolutionAgent(issues, nil, digestModel, nil).Run(ctx)
			if err != nil {
				fatal("resolving recurring issues: %v", err)
			}
		}
		if len(anomalies) > 0 {
			log.Info("Explaining %d recurring anomalies with %s", len(anomalies), digestModel)
			explainer := reporter.NewAnomalyExplainer(anomalies, digestModel)
			explainer.MaxExplain = len(anomalies)
			explained, err = explainer.Run(ctx)
			if err != nil {
				fatal("explaining recurring anomalies: %v", err)
			}
		}
		for _, m := range llm.UsageByModel() {
			log.Info("Token usage: model=%s prompt_tokens=%d completion_tokens=%d",
				m.Model, m.PromptTokens, m.CompletionTokens)
		}
	}
	// The one-offs keep the resolution the daily run already wrote; it
	// rides in the same list so capture and the layouts pair it by title.
	resolutions.Resolutions = append(resolutions.Resolutions, oneOffResolutions...)
	if len(oneOffs.Issues) > 0 {
		log.Info("Including %d single-day critical/high issues with their daily advice", len(oneOffs.Issues))
	}

	// File the digest BEFORE rendering so the email prints the digest
	// findings' own ids (the daily ids would resolve to the cheap model's
	// resolution, not the one the reader is looking at). A capture failure
	// costs the ids, not the email.
	if !*noStore {
		captureModel := digestModel
		if *noLLM {
			captureModel = ""
		}
		filed := &reporter.IssueList{Issues: append(append([]*reporter.Issue{}, issues.Issues...), oneOffs.Issues...)}
		if err := reporter.CaptureRun(lib, toDate, reporter.RunKindDigest, captureModel,
			-1, -1, filed, resolutions, explained); err != nil {
			log.Warn("capturing digest findings: %v", err)
		} else {
			log.Info("Captured %d digest findings under %s", len(filed.Issues)+len(explained), until)
		}
	}

	report := &reporter.DigestReport{
		Digest:      digest,
		Issues:      issues,
		OneOffs:     oneOffs,
		Resolutions: resolutions,
		Anomalies:   explained,
		Model:       digestModel,
		LLMSkipped:  *noLLM,
		RepoURL:     selfupdate.RepoURL,
	}
	body := report.EmailBody()
	attachment := report.FullReport()
	bodyPath := filepath.Join(*outDir, "digest_body.md")
	attachmentPath := filepath.Join(*outDir, reporter.DigestAttachmentName)
	if err := os.WriteFile(bodyPath, []byte(body), 0o600); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile(attachmentPath, []byte(attachment), 0o600); err != nil {
		fatal("%v", err)
	}
	log.Info("Wrote %s and %s", bodyPath, attachmentPath)
	fmt.Print(body)

	if !*sendEmail {
		log.Info("Skipping email")
		return
	}
	htmlBody, err := reporter.RenderDigestHTML(body, version)
	if err != nil {
		log.Warn("rendering HTML digest, falling back to plain text: %v", err)
		htmlBody = ""
	}
	agent := &reporter.EmailAgent{
		BodyText: body,
		HTMLBody: htmlBody,
		Attachments: []reporter.EmailAttachment{
			{Filename: "digest_body.md", Text: body},
			{Filename: reporter.DigestAttachmentName, Text: attachment},
		},
		Recipients: to,
		Subject:    "Syslog weekly digest - " + reporter.DigestPeriodLabel(from, until),
		SMTPServer: os.Getenv("SYSLOG_SMTP_SERVER"),
		Sender:     os.Getenv("SYSLOG_SMTP_SENDER"),
	}
	log.Info("Sending digest to %s", agent.Recipients)
	// The files are already on disk; a failed send must still fail the
	// process so cron notices and retries.
	if err := agent.Run(); err != nil {
		fatal("%v", err)
	}
}
