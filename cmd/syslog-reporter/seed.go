package main

// knowns seed: load the bundled noise rules (internal/reporter/noiserules.go,
// ait srg-M3Yny.2, ant ADR srg-uHwCr) into the known_knowns table, or an
// edited copy of the file by path. Seeding is idempotent and never deletes.

import (
	"fmt"
	"os"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func runKnownsSeed(args []string) {
	fs, dbPath := knownsFlagSet("knowns seed")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) > 1 {
		fatal("usage: syslog-reporter knowns seed [<rules.txt>] [--db <path>]")
	}
	var (
		rules []reporter.NoiseRule
		err   error
		name  = "the bundled noise rules"
	)
	if len(positionals) == 1 {
		name = positionals[0]
		f, err := os.Open(name)
		if err != nil {
			fatal("%v", err)
		}
		rules, err = reporter.ParseNoiseRules(f)
		f.Close()
		if err != nil {
			fatal("%s: %v", name, err)
		}
	} else if rules, err = reporter.BundledNoiseRules(); err != nil {
		fatal("%s: %v", name, err)
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	added, skipped, err := knownsSeed(lib, rules)
	if err != nil {
		fatal("%v", err)
	}
	for _, e := range added {
		fmt.Printf("known-known %d seeded: %s\n", e.ID, describeKnown(e))
	}
	fmt.Fprintf(os.Stderr, "%d added, %d already present, from %s\n", len(added), skipped, name)
}

// knownsSeed adds every rule not already present as a (host, match) pair,
// whatever its source, as a bundled entry. It returns the entries added
// and how many were skipped.
func knownsSeed(lib *reporter.LibraryStore, rules []reporter.NoiseRule) ([]*reporter.KnownEntry, int, error) {
	existing, err := lib.ListKnownEntries()
	if err != nil {
		return nil, 0, err
	}
	type key struct{ host, match string }
	present := make(map[key]bool, len(existing))
	for _, e := range existing {
		present[key{e.Host, e.Match}] = true
	}
	var inputs []reporter.KnownEntryInput
	skipped := 0
	for _, r := range rules {
		k := key{r.Host, r.Match}
		if present[k] {
			skipped++
			continue
		}
		present[k] = true // a rule listed twice in the file seeds once
		inputs = append(inputs, reporter.KnownEntryInput{Host: r.Host, Match: r.Match, Reason: r.Reason,
			Added: time.Now(), Source: reporter.KnownSourceBundled})
	}
	if len(inputs) == 0 {
		return nil, skipped, nil
	}
	added, err := lib.AddKnownEntries(inputs)
	return added, skipped, err
}
