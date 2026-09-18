package main

// Tests for knowns seed. Fictional hosts only.

import (
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func TestKnownsSeedIsIdempotentAndSkipsWhatExists(t *testing.T) {
	lib := knownsTestStore(t)
	// An operator entry with the same (host, match) as a bundled rule is
	// left alone and counts as present; so does a rule listed twice.
	if _, err := knownsAdd(lib, "*", "", "Hello recv from server", "mine first", nil); err != nil {
		t.Fatal(err)
	}
	rules, err := reporter.ParseNoiseRules(strings.NewReader("Hello recv from server\nUSB disconnect\nUSB disconnect\nhost=*lab* kernel\n"))
	if err != nil {
		t.Fatal(err)
	}
	added, skipped, err := knownsSeed(lib, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 || skipped != 2 {
		t.Fatalf("first seed: added %d skipped %d, want 2 and 2", len(added), skipped)
	}
	for _, e := range added {
		if e.Source != reporter.KnownSourceBundled || e.Reason != reporter.DefaultNoiseReason {
			t.Errorf("seeded entry %d has source %q reason %q", e.ID, e.Source, e.Reason)
		}
	}
	added, skipped, err = knownsSeed(lib, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 0 || skipped != 4 {
		t.Errorf("second seed: added %d skipped %d, want 0 and 4", len(added), skipped)
	}
	all, err := lib.ListKnownEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("table has %d rows, want 3", len(all))
	}
	if all[0].Source != reporter.KnownSourceCLI || all[0].Reason != "mine first" {
		t.Errorf("operator entry was touched: %+v", all[0])
	}
}

func TestAddKnownEntriesAcceptsTheFourSourcesOnly(t *testing.T) {
	lib := knownsTestStore(t)
	for _, src := range reporter.KnownSources {
		if _, err := lib.AddKnownEntries([]reporter.KnownEntryInput{{Host: "*", Match: "x", Reason: src, Source: src}}); err != nil {
			t.Errorf("source %q refused: %v", src, err)
		}
	}
	if _, err := lib.AddKnownEntries([]reporter.KnownEntryInput{{Host: "*", Match: "x", Reason: "r", Source: "toml"}}); err == nil {
		t.Error("source \"toml\" accepted")
	}
}
