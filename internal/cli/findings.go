package cli

// The findings library over plain CLI (ait srg-2KY5X.8), for terminal-only
// sysadmins who ssh into the box: query the history and record outcomes
// without the web UI. Same binary, same SQLite file, direct LibraryStore
// access - a local shell on the box IS the auth (owner decision
// 2026-08-28). No query logic lives here: anything the CLI needs comes
// from LibraryStore, so web and CLI can never drift apart.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const defaultListLimit = 50

// ParseFlagsAnywhere parses argparse-style: flags may appear before or
// after positionals. Go's flag package stops at the first non-flag
// argument, so re-parse until every argument is consumed.
func ParseFlagsAnywhere(fs *flag.FlagSet, args []string) []string {
	var positionals []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			return positionals
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

const findingsUsage = "usage: syslog-reporter findings <list|show|feedback> [options]"

// RunFindings dispatches the findings subcommands. defaultDB is the
// resolved SYSLOG_DB_PATH default; each subcommand's --db can override it.
func RunFindings(defaultDB string, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", findingsUsage)
	}
	switch args[0] {
	case "list":
		return runList(defaultDB, args[1:], out)
	case "show":
		return runShow(defaultDB, args[1:], out)
	case "feedback":
		return runFeedback(defaultDB, args[1:], out)
	default:
		return fmt.Errorf("unknown findings command %q\n%s", args[0], findingsUsage)
	}
}

func openLibrary(path string) (*reporter.LibraryStore, error) {
	lib, err := reporter.OpenLibraryStore(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return lib, nil
}

func runList(defaultDB string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("findings list", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite store path")
	host := fs.String("host", "", "Filter by host (matches any part of the name)")
	service := fs.String("service", "", "Filter by service (matches any part of the name)")
	severity := fs.String("severity", "", "Filter by severity: critical, high, medium, low")
	kind := fs.String("kind", "", "Filter by kind: issue, peer, baseline, temporal")
	since := fs.String("since", "", "Only runs on or after this date (YYYY-MM-DD)")
	until := fs.String("until", "", "Only runs on or before this date (YYYY-MM-DD)")
	search := fs.String("search", "", "Title search (matches any part of the title)")
	limit := fs.Int("limit", defaultListLimit, "Maximum rows")
	asJSON := fs.Bool("json", false, "Emit JSON for scripting")
	if extra := ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		return fmt.Errorf("findings list takes no positional arguments (got %s)",
			strings.Join(extra, " "))
	}
	lib, err := openLibrary(*dbPath)
	if err != nil {
		return err
	}
	defer lib.Close()
	results, err := lib.SearchFindings(reporter.FindingFilter{
		Host:     *host,
		Service:  *service,
		Severity: *severity,
		Kind:     *kind,
		Query:    *search,
		From:     *since,
		To:       *until,
		Limit:    *limit,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(out, results)
	}
	if len(results) == 0 {
		fmt.Fprintln(out, "no findings match")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDATE\tKIND\tSEVERITY\tSERVICE\tHOSTS\tTITLE\tOUTCOMES")
	for _, r := range results {
		severity := r.Severity
		if severity == "" {
			severity = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\tworked %d / didnt %d\n",
			r.ID, r.LogDate, r.Kind, severity, r.Service, r.Hosts, r.Title,
			r.Worked, r.DidntWork)
	}
	return tw.Flush()
}

func runShow(defaultDB string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("findings show", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite store path")
	asJSON := fs.Bool("json", false, "Emit JSON for scripting")
	positionals := ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		return fmt.Errorf("usage: syslog-reporter findings show <id>")
	}
	id, err := strconv.ParseInt(positionals[0], 10, 64)
	if err != nil {
		return fmt.Errorf("finding id must be a number, got %q", positionals[0])
	}
	lib, err := openLibrary(*dbPath)
	if err != nil {
		return err
	}
	defer lib.Close()
	d, err := lib.GetFinding(id)
	if err != nil {
		return fmt.Errorf("no finding with id %d", id)
	}
	if *asJSON {
		return writeJSON(out, d)
	}
	writeDetail(out, d)
	feedback, err := lib.FeedbackFor(id)
	if err != nil {
		return err
	}
	writeFeedback(out, feedback)
	return nil
}

// writeDetail prints one finding as plain text, in the same field order as
// the web page and the emailed report (models.go ToMarkdown).
func writeDetail(out io.Writer, d *reporter.FindingDetail) {
	fmt.Fprintf(out, "#%d  %s  (%s, run of %s)\n\n", d.ID, d.Title, d.Kind, d.LogDate)
	if d.Issue != nil {
		i := d.Issue
		fmt.Fprintf(out, "Severity: %s   Service: %s   When: %s\n\n",
			i.Severity, i.AffectedService, i.TimestampFrequency)
		fmt.Fprintf(out, "%s\n\n", i.Description)
		fmt.Fprintf(out, "Affected: %s\n", strings.Join(d.Hosts, ", "))
		fmt.Fprintf(out, "Impact: %s\n", i.PotentialImpact)
		fmt.Fprintf(out, "Recommended action: %s\n\n", i.RecommendedAction)
		fmt.Fprintf(out, "Example log entry:\n  %s\n", i.ExampleLogEntry)
		if r := i.Resolution; r != nil {
			fmt.Fprintf(out, "\nRoot cause: %s\n\n", r.RootCause)
			fmt.Fprintf(out, "Investigate:\n  %s\n\n", r.Investigate)
			if len(r.FixCommands) > 0 {
				fmt.Fprintln(out, "Fix:")
				for _, c := range r.FixCommands {
					fmt.Fprintf(out, "  %s\n", c)
				}
			} else {
				fmt.Fprintln(out, "Fix: (no commands suggested)")
			}
			if r.Notes != "" {
				fmt.Fprintf(out, "\nNote: %s\n", r.Notes)
			}
		} else {
			fmt.Fprintln(out, "\nNo resolution was generated for this finding.")
		}
		return
	}
	a := d.Anomaly
	fmt.Fprintf(out, "Host: %s   Program: %s   OS: %s\n\n", a.Host, a.Program, a.OSFamily)
	fmt.Fprintf(out, "%s\n", a.Detail)
	if a.ExampleLine != "" {
		fmt.Fprintf(out, "\nExample:\n  %s\n", a.ExampleLine)
	}
	fmt.Fprintf(out, "\nLikely causes: %s\n", a.LikelyCauses)
	fmt.Fprintln(out, "\nInvestigate:")
	if len(a.InvestigationSteps) > 0 {
		for _, s := range a.InvestigationSteps {
			fmt.Fprintf(out, "  - %s\n", s)
		}
	} else {
		fmt.Fprintln(out, "  (none given)")
	}
	fmt.Fprintln(out, "\nSuggested commands:")
	if len(a.SuggestedCommands) > 0 {
		for _, c := range a.SuggestedCommands {
			fmt.Fprintf(out, "  %s\n", c)
		}
	} else {
		fmt.Fprintln(out, "  (none given)")
	}
}

func writeFeedback(out io.Writer, feedback []*reporter.FeedbackRow) {
	if len(feedback) == 0 {
		return
	}
	worked, didnt := 0, 0
	for _, f := range feedback {
		if f.Verdict == "worked" {
			worked++
		} else {
			didnt++
		}
	}
	fmt.Fprintf(out, "\nOutcomes: worked %d / didnt %d\n", worked, didnt)
	for _, f := range feedback {
		who := f.Username
		if who == "" {
			who = "anonymous"
		}
		line := fmt.Sprintf("  %s: %s", who, strings.ReplaceAll(f.Verdict, "_", " "))
		if f.Comment != "" {
			line += " - " + f.Comment
		}
		fmt.Fprintln(out, line)
	}
}

func runFeedback(defaultDB string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("findings feedback", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite store path")
	comment := fs.String("comment", "", "Optional note to store with the verdict")
	username := fs.String("user", "", "Record the vote as this username (default: your OS username, if it matches)")
	positionals := ParseFlagsAnywhere(fs, args)
	if len(positionals) != 2 {
		return fmt.Errorf("usage: syslog-reporter findings feedback <id> (worked|didnt-work)")
	}
	id, err := strconv.ParseInt(positionals[0], 10, 64)
	if err != nil {
		return fmt.Errorf("finding id must be a number, got %q", positionals[0])
	}
	var verdict string
	switch positionals[1] {
	case "worked":
		verdict = "worked"
	case "didnt-work":
		verdict = "didnt_work"
	default:
		return fmt.Errorf("verdict must be worked or didnt-work, got %q", positionals[1])
	}
	lib, err := openLibrary(*dbPath)
	if err != nil {
		return err
	}
	defer lib.Close()
	if _, err := lib.GetFinding(id); err != nil {
		return fmt.Errorf("no finding with id %d", id)
	}
	userID, recordedAs, err := resolveVoter(lib, *username)
	if err != nil {
		return err
	}
	if err := lib.RecordFeedback(id, userID, verdict, *comment); err != nil {
		return err
	}
	fmt.Fprintf(out, "recorded: %s on finding %d (%s)\n",
		strings.ReplaceAll(verdict, "_", " "), id, recordedAs)
	return nil
}

// resolveVoter maps the vote to a users-table row. An explicit --user must
// match (an unknown name is an error, never a silent anonymous fallback);
// the default OS-username lookup falls back to the anonymous singleton,
// exactly as the web's none mode.
func resolveVoter(lib *reporter.LibraryStore, explicit string) (*int64, string, error) {
	if explicit != "" {
		u, err := lib.UserByUsername(explicit)
		if err != nil {
			return nil, "", err
		}
		if u == nil {
			return nil, "", fmt.Errorf("no user named %q in the users table", explicit)
		}
		return &u.ID, "as " + u.Username, nil
	}
	if current, err := user.Current(); err == nil {
		u, err := lib.UserByUsername(current.Username)
		if err != nil {
			return nil, "", err
		}
		if u != nil {
			return &u.ID, "as " + u.Username, nil
		}
	}
	return nil, "anonymous", nil
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
