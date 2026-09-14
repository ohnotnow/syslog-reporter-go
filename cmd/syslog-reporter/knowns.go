package main

// The knowns command (ait srg-CvFSr.3, ant ADR srg-gzXn6): the on-box side
// of known-knowns. Free-form entries (host globs, regexes) that never
// appeared as a finding, listing what is muted, removing an entry, and the
// one-shot import of the old TOML file. Mutes from a finding go through
// the API instead.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
	"github.com/pelletier/go-toml/v2"
)

func runKnowns(args []string) {
	const usage = "usage: syslog-reporter knowns <list|add|remove|import> [args] (see 'knowns --help')"
	if len(args) == 0 {
		fatal(usage)
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Print(knownsHelp)
	case "list":
		runKnownsList(args[1:])
	case "add":
		runKnownsAdd(args[1:])
	case "remove":
		runKnownsRemove(args[1:])
	case "import":
		runKnownsImport(args[1:])
	default:
		fatal("unknown knowns command %q\n%s", args[0], usage)
	}
}

func knownsFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), knownsHelp) }
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"SQLite store path, resolved exactly as in batch mode")
	return fs, dbPath
}

func runKnownsList(args []string) {
	fs, dbPath := knownsFlagSet("knowns list")
	all := fs.Bool("all", false, "Include entries that have expired")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("knowns list takes no arguments (got %s)", strings.Join(extra, " "))
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	if err := knownsList(lib, *all, os.Stdout); err != nil {
		fatal("%v", err)
	}
}

func knownsList(lib *reporter.LibraryStore, all bool, out io.Writer) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	kk, err := lib.LoadKnownKnowns(today)
	if err != nil {
		return err
	}
	entries := kk.Active
	if all {
		entries = append(entries, kk.Expired...)
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no known-knowns (add one with 'knowns add', or mute a finding through the API)")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tHOST\tPROGRAM\tMATCH\tADDED\tEXPIRES\tSOURCE\tBY\tFINDING\tREASON")
	for _, e := range entries {
		finding := "-"
		if e.FindingID != nil {
			finding = strconv.FormatInt(*e.FindingID, 10)
		}
		by := e.CreatedBy
		if by == "" {
			by = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Host, dashIfEmpty(e.Program),
			dashIfEmpty(e.Match), dateOrNever(e.Added), dateOrNever(e.Expires), e.Source, by, finding, e.Reason)
	}
	return tw.Flush()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func runKnownsAdd(args []string) {
	fs, dbPath := knownsFlagSet("knowns add")
	host := fs.String("host", "", "Host glob: a hostname, lab*, or *")
	program := fs.String("program", "", "Program glob; drops all of its lines on the host and mutes its anomalies")
	match := fs.String("match", "", "Regex on the message; drops only matching lines")
	reason := fs.String("reason", "", "Why, in your own words")
	expiresFlag := fs.String("expires", "", "Date (YYYY-MM-DD) after which the entry lapses")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("knowns add takes flags only (got %s)", strings.Join(extra, " "))
	}
	if *host == "" || *reason == "" {
		fatal("usage: syslog-reporter knowns add --host GLOB (--program GLOB | --match REGEX) --reason TEXT [--expires YYYY-MM-DD] [--db <path>]")
	}
	expires, err := parseKnownsExpiry(*expiresFlag)
	if err != nil {
		fatal("%v", err)
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	e, err := knownsAdd(lib, *host, *program, *match, *reason, expires)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("known-known %d added: %s\n", e.ID, describeKnown(e))
}

// parseKnownsExpiry is a plain date: expiry is judged against the log slice
// date, so unlike a token's expiry it is not a wall-clock instant and a
// past date is a legitimate (if odd) thing to import.
func parseKnownsExpiry(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, fmt.Errorf("--expires must be a date (YYYY-MM-DD): %v", err)
	}
	return &t, nil
}

func knownsAdd(lib *reporter.LibraryStore, host, program, match, reason string, expires *time.Time) (*reporter.KnownEntry, error) {
	entries, err := lib.AddKnownEntries([]reporter.KnownEntryInput{{
		Host: host, Program: program, Match: match, Reason: reason,
		Added: time.Now(), Expires: expires, Source: reporter.KnownSourceCLI}})
	if err != nil {
		return nil, err
	}
	return entries[0], nil
}

func describeKnown(e *reporter.KnownEntry) string {
	parts := []string{"host " + e.Host}
	if e.Program != "" {
		parts = append(parts, "program "+e.Program)
	}
	if e.Match != "" {
		parts = append(parts, "match "+strconv.Quote(e.Match))
	}
	return strings.Join(parts, ", ")
}

func runKnownsRemove(args []string) {
	fs, dbPath := knownsFlagSet("knowns remove")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter knowns remove <id> [--db <path>]")
	}
	id, err := strconv.ParseInt(positionals[0], 10, 64)
	if err != nil {
		fatal("knowns remove: %q is not an entry id (see 'knowns list')", positionals[0])
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	ok, err := lib.DeleteKnownEntry(id)
	if err != nil {
		fatal("%v", err)
	}
	if !ok {
		fatal("no known-known with id %d (see 'knowns list')", id)
	}
	fmt.Printf("known-known %d removed\n", id)
}

func runKnownsImport(args []string) {
	fs, dbPath := knownsFlagSet("knowns import")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter knowns import <known_knowns.toml> [--db <path>]")
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	entries, err := knownsImport(lib, positionals[0])
	if err != nil {
		fatal("%v", err)
	}
	for _, e := range entries {
		fmt.Printf("known-known %d imported: %s\n", e.ID, describeKnown(e))
	}
	fmt.Fprintf(os.Stderr, "%d entries imported from %s; the file was left in place and is no longer read\n",
		len(entries), positionals[0])
}

// tomlKnowns is the pre-migration-5 [[known]] file shape. Dates are
// toml.LocalDate so bare TOML dates parse without a time part. This is
// the only TOML left in the binary; it exists for the one-shot import.
type tomlKnowns struct {
	Known []struct {
		Host    string          `toml:"host"`
		Reason  string          `toml:"reason"`
		Match   string          `toml:"match"`
		Program string          `toml:"program"`
		Added   *toml.LocalDate `toml:"added"`
		Expires *toml.LocalDate `toml:"expires"`
	} `toml:"known"`
}

func localDate(d *toml.LocalDate, fallback time.Time) time.Time {
	if d == nil {
		return fallback
	}
	return time.Date(d.Year, time.Month(d.Month), d.Day, 0, 0, 0, 0, time.UTC)
}

// knownsImport inserts every entry of a TOML file as a cli-sourced row. It
// does not dedupe: importing twice makes duplicates, which 'knowns remove'
// fixes. The whole file is validated before anything is written.
func knownsImport(lib *reporter.LibraryStore, path string) ([]*reporter.KnownEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw tomlKnowns
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(raw.Known) == 0 {
		return nil, fmt.Errorf("%s: no [[known]] entries", path)
	}
	today := time.Now().UTC()
	inputs := make([]reporter.KnownEntryInput, 0, len(raw.Known))
	for i, r := range raw.Known {
		if r.Host == "" || r.Reason == "" {
			return nil, fmt.Errorf("%s: entry %d needs both 'host' and 'reason'", path, i+1)
		}
		in := reporter.KnownEntryInput{Host: r.Host, Program: r.Program, Match: r.Match, Reason: r.Reason,
			Added: localDate(r.Added, today), Source: reporter.KnownSourceCLI}
		if r.Expires != nil {
			exp := localDate(r.Expires, today)
			in.Expires = &exp
		}
		inputs = append(inputs, in)
	}
	return lib.AddKnownEntries(inputs)
}
