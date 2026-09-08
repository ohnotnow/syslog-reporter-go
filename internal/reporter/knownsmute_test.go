package reporter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var muteDay = day(2026, 9, 8)

func issueDetail(hosts []string, example, service string) *FindingDetail {
	return &FindingDetail{ID: 42, Kind: "issue", Hosts: hosts,
		Issue: &IssuePayload{Issue: Issue{Issue: "No free leases", ExampleLogEntry: example,
			AffectedHost: hosts, AffectedService: service}}}
}

func TestDeriveKnownEntriesFromAnAnomaly(t *testing.T) {
	d := &FindingDetail{ID: 7, Kind: "peer", Hosts: []string{"web01.example.test"},
		Anomaly: &ExplainedAnomaly{Host: "web01.example.test", Program: "sshd"}}
	entries, err := DeriveKnownEntries(d, "scanner target", muteDay, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Host != "web01.example.test" || entries[0].Program != "sshd" ||
		entries[0].Match != "" || entries[0].Reason != "scanner target" {
		t.Errorf("entries = %+v", entries[0])
	}
	if entries[0].Added == nil || !entries[0].Added.Equal(muteDay) {
		t.Errorf("added = %v", entries[0].Added)
	}
}

func TestDeriveKnownEntriesParsesTheIssueExampleOnePerHost(t *testing.T) {
	d := issueDetail([]string{"dhcp01.example.test", "dhcp02.example.test"},
		"Sep  7 10:00:01 dhcp01.example.test dhcpd[712]: DHCPDISCOVER from 00:11:22:33:44:55: no free leases",
		"DHCP server")
	expires := day(2027, 1, 31)
	entries, err := DeriveKnownEntries(d, "no pool by design", muteDay, &expires)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want one per host", len(entries))
	}
	for i, host := range []string{"dhcp01.example.test", "dhcp02.example.test"} {
		if entries[i].Host != host || entries[i].Program != "dhcpd" || entries[i].Expires == nil {
			t.Errorf("entry %d = %+v", i, entries[i])
		}
	}
}

func TestDeriveKnownEntriesFallsBackToATokenLikeService(t *testing.T) {
	d := issueDetail([]string{"web01.example.test"}, "not a syslog line at all", "nginx")
	entries, err := DeriveKnownEntries(d, "expected", muteDay, nil)
	if err != nil || len(entries) != 1 || entries[0].Program != "nginx" {
		t.Errorf("entries = %+v, err = %v", entries, err)
	}
}

func TestDeriveKnownEntriesRefusesProseServiceAndEmptyHosts(t *testing.T) {
	d := issueDetail([]string{"web01.example.test"}, "not a syslog line", "the web server")
	if _, err := DeriveKnownEntries(d, "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveProgram) {
		t.Errorf("prose service err = %v", err)
	}
	d = issueDetail(nil, "Sep  7 10:00:01 web01.example.test nginx[1]: boom", "nginx")
	if _, err := DeriveKnownEntries(d, "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveProgram) {
		t.Errorf("no hosts err = %v", err)
	}
}

// Hosts come from the LLM and become path.Match globs in the file, so a
// host that is not a plain hostname refuses the whole finding
// (SECURITY_REVIEW.md SR-06).
func TestDeriveKnownEntriesRefusesHostsThatAreNotPlainHostnames(t *testing.T) {
	example := "Sep  7 10:00:01 web01.example.test nginx[1]: boom"
	for _, host := range []string{"*", "web[0-9]", "a b", "?", `a\b`, "-leading"} {
		d := issueDetail([]string{"web01.example.test", host}, example, "nginx")
		if _, err := DeriveKnownEntries(d, "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveHost) {
			t.Errorf("host %q: err = %v, want ErrCannotDeriveHost", host, err)
		}
	}
	for _, host := range []string{"web01", "db-2.example.test", "web_01", "fd00::1", "10.0.0.7"} {
		d := issueDetail([]string{host}, example, "nginx")
		entries, err := DeriveKnownEntries(d, "x", muteDay, nil)
		if err != nil || len(entries) != 1 || entries[0].Host != host {
			t.Errorf("host %q: entries = %v, err = %v", host, entries, err)
		}
	}
}

func TestAppendKnownEntriesCreatesAppendsAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	e := mustEntry(t, "dhcp01.example.test", `no pool "by design"`, "", "dhcpd", nil)
	e.Added = &muteDay
	written, err := AppendKnownEntries(path, []*KnownEntry{e})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("written = %d", len(written))
	}
	kk, err := LoadKnownKnowns(path, muteDay)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(kk.Active) != 1 || kk.Active[0].Reason != `no pool "by design"` || kk.Active[0].Program != "dhcpd" {
		t.Errorf("reloaded = %+v", kk.Active)
	}
	if !kk.LineIgnored("dhcp01.example.test", "dhcpd", "dhcpd[1]: no free leases") {
		t.Error("the written entry must drop lines end to end")
	}

	// Same host+program again: skipped; a new host: appended after the old text.
	again := mustEntry(t, "dhcp01.example.test", "again", "", "dhcpd", nil)
	other := mustEntry(t, "dhcp02.example.test", "also expected", "", "dhcpd", nil)
	written, err = AppendKnownEntries(path, []*KnownEntry{again, other})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || written[0].Host != "dhcp02.example.test" {
		t.Errorf("second append wrote %+v", written)
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "[[known]]") != 2 || strings.Contains(string(raw), `"again"`) {
		t.Errorf("file:\n%s", raw)
	}
	if written, err := AppendKnownEntries(path, []*KnownEntry{again}); err != nil || written != nil {
		t.Errorf("all-duplicate append = %+v, %v; want nil, nil", written, err)
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp")); len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestAppendKnownEntriesLeavesAHandEditedFileIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	hand := "# my notes\n[[known]]\nhost = \"*\"\nmatch = \"port 1234\"\nreason = \"microscope\"\n"
	if err := os.WriteFile(path, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	e := mustEntry(t, "web01.example.test", "expected", "", "sshd", nil)
	if _, err := AppendKnownEntries(path, []*KnownEntry{e}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), hand) {
		t.Errorf("hand-written prefix altered:\n%s", raw)
	}
	kk, err := LoadKnownKnowns(path, time.Now())
	if err != nil || len(kk.Active) != 2 {
		t.Errorf("reload: %v, active = %d", err, len(kk.Active))
	}
}

func TestAppendKnownEntriesRefusesABrokenExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	if err := os.WriteFile(path, []byte("[[known]]\nhost = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := mustEntry(t, "web01.example.test", "expected", "", "sshd", nil)
	if _, err := AppendKnownEntries(path, []*KnownEntry{e}); err == nil {
		t.Error("expected the existing file's missing reason to be reported")
	}
}

// Concurrent mutes must all land: the append is serialised process-wide
// (SECURITY_REVIEW.md SR-04). Run with -race.
func TestAppendKnownEntriesSerialisesConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	added := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	const n = 8
	entryFor := func(host string) []*KnownEntry {
		e, err := newKnownEntry(host, "expected", "", "cron", &added, nil)
		if err != nil {
			t.Fatal(err)
		}
		return []*KnownEntry{e}
	}
	run := func(hostFor func(i int) string) {
		t.Helper()
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if _, err := AppendKnownEntries(path, entryFor(hostFor(i))); err != nil {
					errs <- err
				}
			}(i)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("append: %v", err)
		}
	}

	run(func(i int) string { return fmt.Sprintf("web%02d.example.test", i) })
	kk, err := LoadKnownKnowns(path, added)
	if err != nil {
		t.Fatal(err)
	}
	if len(kk.Active) != n {
		t.Fatalf("distinct concurrent mutes left %d entries, want %d", len(kk.Active), n)
	}

	run(func(int) string { return "db01.example.test" })
	kk, err = LoadKnownKnowns(path, added)
	if err != nil {
		t.Fatal(err)
	}
	if len(kk.Active) != n+1 {
		t.Fatalf("identical concurrent mutes left %d entries, want %d", len(kk.Active), n+1)
	}
}
