package main

// Tests for the knowns command. Fictional hosts only.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func knownsTestStore(t *testing.T) *reporter.LibraryStore {
	t.Helper()
	lib, err := reporter.OpenLibraryStore(filepath.Join(t.TempDir(), "knowns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	return lib
}

func TestKnownsAddRefusesEntriesTheRunWouldRefuse(t *testing.T) {
	lib := knownsTestStore(t)
	if _, err := knownsAdd(lib, "scopebox", "", "", "no matcher", nil); err == nil {
		t.Error("expected an error with neither program nor match")
	}
	if _, err := knownsAdd(lib, "scopebox", "", "(", "broken regex", nil); err == nil {
		t.Error("expected the regex compile error")
	}
	var out bytes.Buffer
	if err := knownsList(lib, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no known-knowns") {
		t.Errorf("refused adds wrote rows:\n%s", out.String())
	}
}

func TestKnownsImportRoundTripsThroughList(t *testing.T) {
	lib := knownsTestStore(t)
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	doc := `
[[known]]
host = "scopebox"
match = "port 1234"
reason = "microscope attached for the optics experiment"
added = 2026-08-27
expires = 2030-09-01

[[known]]
host = "*"
program = "kernel"
reason = "fleet-wide igmp eye-roll"
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := knownsImport(lib, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Match != "port 1234" || entries[1].Program != "kernel" ||
		entries[0].Source != reporter.KnownSourceCLI {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Added == nil || entries[0].Added.Format("2006-01-02") != "2026-08-27" ||
		entries[0].Expires == nil || entries[0].Expires.Format("2006-01-02") != "2030-09-01" {
		t.Errorf("dates = %v / %v", entries[0].Added, entries[0].Expires)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("import must leave the file in place")
	}
	var out bytes.Buffer
	if err := knownsList(lib, false, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"scopebox", "port 1234", "2030-09-01", "kernel", "cli", "fleet-wide igmp eye-roll"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list missing %q:\n%s", want, out.String())
		}
	}

	if ok, err := lib.DeleteKnownEntry(entries[0].ID); err != nil || !ok {
		t.Fatalf("remove: ok=%v err=%v", ok, err)
	}
	out.Reset()
	if err := knownsList(lib, false, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "port 1234") || !strings.Contains(out.String(), "kernel") {
		t.Errorf("list after remove:\n%s", out.String())
	}
}

func TestKnownsImportRefusesABrokenFileWholesale(t *testing.T) {
	lib := knownsTestStore(t)
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	doc := "[[known]]\nhost = \"scopebox\"\nprogram = \"kernel\"\nreason = \"fine\"\n\n" +
		"[[known]]\nhost = \"scopebox\"\nmatch = \"port [\"\nreason = \"broken\"\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := knownsImport(lib, path); err == nil {
		t.Fatal("expected the regex error")
	}
	rows, err := lib.ListKnownEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a refused import wrote %d rows", len(rows))
	}
}

func TestKnownsListHidesLapsedEntriesUnlessAll(t *testing.T) {
	lib := knownsTestStore(t)
	exp, _ := parseKnownsExpiry("2020-01-01")
	if _, err := knownsAdd(lib, "oldbox", "cron", "", "lapsed", exp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := knownsList(lib, false, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "oldbox") {
		t.Error("lapsed entry shown without --all")
	}
	out.Reset()
	if err := knownsList(lib, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "oldbox") {
		t.Error("lapsed entry hidden with --all")
	}
}
