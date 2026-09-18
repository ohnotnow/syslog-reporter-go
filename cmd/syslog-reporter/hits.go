package main

// knowns hits: what the known-knowns caught on one day's dump (ait
// srg-M3Yny.6, ant ADR srg-uHwCr). Hit counts exist only during a filter
// pass, so this re-runs the filter over a dump with the drop hook on and
// prints; it writes nothing. The overview answers "did my new rules fire,
// and how much"; --id answers "what exactly did that one eat".

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// hitRow is one entry's tally for the day.
type hitRow struct {
	Entry  *reporter.KnownEntry
	Lines  int
	Hosts  map[string]int
	Caught []string // raw lines, kept only for the entry --id asks about
}

func runKnownsHits(args []string) {
	fs, dbPath := knownsFlagSet("knowns hits")
	dateStr := fs.String("date", "", "ISO date (YYYY-MM-DD) the dump covers, for expiry (default: from the dump, else yesterday)")
	var since sinceFlag
	fs.Var(&since, "since", sinceUsage)
	source := fs.String("source", "", "Only entries with this source: "+strings.Join(reporter.KnownSources, ", "))
	all := fs.Bool("all", false, "Include the bundled noise rules in the overview")
	id := fs.Int64("id", 0, "Show what this one entry caught, grouped by message")
	raw := fs.Bool("raw", false, "With --id: print the caught lines verbatim instead of grouping")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter knowns hits <dump> [--since 1h|3d|2w|YYYY-MM-DD] [--source S] [--all] [--id N [--raw]] [--db <path>]")
	}
	if *source != "" && !containsString(reporter.KnownSources, *source) {
		fatal("--source must be one of %s (got %q)", strings.Join(reporter.KnownSources, ", "), *source)
	}
	path := positionals[0]
	lines, sourceDate, _, err := readLogSource(path, isNDJSONPath(path))
	if err != nil {
		fatal("%v", err)
	}
	logDate, err := hitsLogDate(*dateStr, sourceDate)
	if err != nil {
		fatal("%v", err)
	}
	lib := openUserStore(*dbPath)
	knowns, err := lib.LoadKnownKnowns(logDate)
	lib.Close()
	if err != nil {
		fatal("%v", err)
	}
	rows := tallyHits(lines, knowns, *id)
	if *id != 0 {
		printHitDetail(os.Stdout, rows, *id, *raw)
		return
	}
	printHitOverview(os.Stdout, rows, &since, *source, *all)
}

func hitsLogDate(dateStr string, sourceDate *time.Time) (time.Time, error) {
	if dateStr != "" {
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return time.Time{}, fmt.Errorf("--date must be YYYY-MM-DD: %v", err)
		}
		return t, nil
	}
	if sourceDate != nil {
		return *sourceDate, nil
	}
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1), nil
}

// tallyHits runs the filter with the drop hook on and returns one row per
// entry that fired, in HitEntries order. Raw lines are kept only for
// keepID (0 keeps none), so a whole day's drops never sit in memory twice.
func tallyHits(lines []string, knowns *reporter.KnownKnowns, keepID int64) []*hitRow {
	rows := map[*reporter.KnownEntry]*hitRow{}
	f := reporter.NewLogFilter(lines, knowns)
	f.OnKnownDrop = func(e *reporter.KnownEntry, line string) {
		r := rows[e]
		if r == nil {
			r = &hitRow{Entry: e, Hosts: map[string]int{}}
			rows[e] = r
		}
		r.Lines++
		if parts := strings.Fields(line); len(parts) > 3 {
			r.Hosts[parts[3]]++
		}
		if keepID != 0 && e.ID == keepID {
			r.Caught = append(r.Caught, strings.TrimRight(line, "\n"))
		}
	}
	f.Run()
	var out []*hitRow
	for _, e := range knowns.HitEntries() {
		if r := rows[e]; r != nil {
			out = append(out, r)
		}
	}
	return out
}

// printHitOverview is the table: newest entries first. Bundled rules are
// hidden unless asked for, so a noise report is not itself noise.
func printHitOverview(w io.Writer, rows []*hitRow, since *sinceFlag, source string, all bool) {
	var shown []*hitRow
	totalLines, bundledLines := 0, 0
	for _, r := range rows {
		totalLines += r.Lines
		if r.Entry.Source == reporter.KnownSourceBundled {
			bundledLines += r.Lines
		}
		if !since.Includes(r.Entry.CreatedAt) {
			continue
		}
		if source != "" && r.Entry.Source != source {
			continue
		}
		if !all && source == "" && r.Entry.Source == reporter.KnownSourceBundled {
			continue
		}
		shown = append(shown, r)
	}
	sort.SliceStable(shown, func(i, j int) bool {
		a, b := shown[i].Entry, shown[j].Entry
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
		return a.ID > b.ID
	})
	if len(shown) == 0 {
		fmt.Fprintln(w, "no matching entries fired on this dump")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSOURCE\tCREATED\tHOST\tLINES\tHOSTS\tMATCH\tREASON")
		for _, r := range shown {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", r.Entry.ID, r.Entry.Source,
				r.Entry.CreatedAt.UTC().Format("2006-01-02 15:04"), r.Entry.Host, r.Lines, len(r.Hosts),
				dashIfEmpty(r.Entry.Match), r.Entry.Reason)
		}
		tw.Flush()
	}
	fmt.Fprintf(w, "%d entries fired, %d lines dropped (%d by bundled rules)\n", len(rows), totalLines, bundledLines)
}

// printHitDetail shows one entry's catch grouped by message shape (pid
// stripped, timestamp and host dropped), most frequent first, or the raw
// lines in dump order with --raw. Over-matching shows up as the odd shape
// at the bottom of the list.
func printHitDetail(w io.Writer, rows []*hitRow, id int64, raw bool) {
	var row *hitRow
	for _, r := range rows {
		if r.Entry.ID == id {
			row = r
		}
	}
	if row == nil {
		fmt.Fprintf(w, "entry %d did not fire on this dump\n", id)
		return
	}
	fmt.Fprintf(w, "known-known %d: %s (%s)\n%d lines on %d hosts\n\n", id, describeKnown(row.Entry), row.Entry.Reason, row.Lines, len(row.Hosts))
	if raw {
		for _, line := range row.Caught {
			fmt.Fprintln(w, line)
		}
		return
	}
	type shape struct {
		text  string
		lines int
		hosts map[string]bool
	}
	shapes := map[string]*shape{}
	for _, line := range row.Caught {
		// Fields, not SplitN: a single-digit day is padded with two spaces.
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		key := reporter.StripPID(strings.Join(parts[4:], " "))
		sh := shapes[key]
		if sh == nil {
			sh = &shape{text: key, hosts: map[string]bool{}}
			shapes[key] = sh
		}
		sh.lines++
		sh.hosts[parts[3]] = true
	}
	list := make([]*shape, 0, len(shapes))
	for _, sh := range shapes {
		list = append(list, sh)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].lines != list[j].lines {
			return list[i].lines > list[j].lines
		}
		return list[i].text < list[j].text
	})
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LINES\tHOSTS\tMESSAGE")
	for _, sh := range list {
		fmt.Fprintf(tw, "%d\t%d\t%s\n", sh.lines, len(sh.hosts), sh.text)
	}
	tw.Flush()
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
