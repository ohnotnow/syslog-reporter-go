package main

// Tests for knowns hits. Fictional hosts only.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

var hitsFixture = []string{
	"Sep  8 06:25:01 dhcpbox CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)",
	"Sep  8 06:25:01 dnsbox CROND[289]: (root) CMD (run-parts /etc/cron.hourly)",
	"Sep  8 06:25:02 dnsbox CROND[290]: (root) CMD (run-parts /etc/cron.hourly)",
	"Sep  8 14:00:05 scopebox widgetd[12]: retry on port 1234",
	"Sep  8 14:00:06 scopebox widgetd[13]: retry on port 1234",
	"Sep  8 14:00:07 otherbox widgetd[14]: retry on port 1234",
	"Sep  8 14:00:08 labbox kernel: usb 1-1: new high-speed USB device number 4",
	"Sep  8 14:00:09 webbox badservice[123]: catastrophic widget failure",
}

// seedHitsStore adds one entry per source and returns the loaded knowns
// plus the ids, so tests can name entries the way an admin would.
func seedHitsStore(t *testing.T) (*reporter.KnownKnowns, map[string]int64) {
	t.Helper()
	lib := knownsTestStore(t)
	entries, err := lib.AddKnownEntries([]reporter.KnownEntryInput{
		{Host: "*", Match: `CROND?\[\d+\]: \([^)]+\) CMD`, Reason: "cron ran a job", Added: time.Now(), Source: reporter.KnownSourceBundled},
		{Host: "scopebox", Match: "port 1234", Reason: "microscope kit", Added: time.Now(), Source: reporter.KnownSourceCLI},
		{Host: "*lab*", Match: "(?i)usb", Reason: "lab usb chatter", Added: time.Now(), Source: reporter.KnownSourceJev},
		{Host: "*", Match: "never matches anything", Reason: "silent", Added: time.Now(), Source: reporter.KnownSourceCLI},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, e := range entries {
		ids[e.Reason] = e.ID
	}
	knowns, err := lib.LoadKnownKnowns(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return knowns, ids
}

func TestTallyHitsCountsLinesAndHostsPerEntry(t *testing.T) {
	knowns, ids := seedHitsStore(t)
	rows := tallyHits(hitsFixture, knowns, ids["microscope kit"])
	got := map[string]*hitRow{}
	for _, r := range rows {
		got[r.Entry.Reason] = r
	}
	if len(rows) != 3 || got["silent"] != nil {
		t.Fatalf("want 3 fired rows and no silent one, got %d", len(rows))
	}
	if r := got["cron ran a job"]; r.Lines != 3 || len(r.Hosts) != 2 || len(r.Caught) != 0 {
		t.Errorf("cron row: lines %d hosts %d caught %d, want 3, 2, 0 (raw lines kept only for --id)", r.Lines, len(r.Hosts), len(r.Caught))
	}
	if r := got["microscope kit"]; r.Lines != 2 || len(r.Hosts) != 1 || len(r.Caught) != 2 {
		t.Errorf("microscope row: lines %d hosts %d caught %d, want 2, 1, 2", r.Lines, len(r.Hosts), len(r.Caught))
	}
	if r := got["lab usb chatter"]; r.Lines != 1 || r.Hosts["labbox"] != 1 {
		t.Errorf("lab row: %+v", r)
	}
}

func TestHitOverviewHidesBundledUnlessAskedAndFiltersBySource(t *testing.T) {
	knowns, _ := seedHitsStore(t)
	rows := tallyHits(hitsFixture, knowns, 0)

	var out bytes.Buffer
	printHitOverview(&out, rows, &sinceFlag{}, "", false)
	text := out.String()
	if strings.Contains(text, "cron ran a job") {
		t.Errorf("bundled entry shown without --all:\n%s", text)
	}
	for _, want := range []string{"microscope kit", "lab usb chatter", "3 entries fired, 6 lines dropped (3 by bundled rules)"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}

	out.Reset()
	printHitOverview(&out, rows, &sinceFlag{}, "", true)
	if !strings.Contains(out.String(), "cron ran a job") {
		t.Errorf("--all should show the bundled entry:\n%s", out.String())
	}

	out.Reset()
	printHitOverview(&out, rows, &sinceFlag{}, reporter.KnownSourceJev, false)
	text = out.String()
	if !strings.Contains(text, "lab usb chatter") || strings.Contains(text, "microscope kit") {
		t.Errorf("--source jev should show only the jev entry:\n%s", text)
	}
}

func TestHitOverviewSinceUsesCreatedAtNewestFirst(t *testing.T) {
	now := time.Now()
	older := &reporter.KnownEntry{ID: 1, Host: "*", Reason: "older", Source: reporter.KnownSourceCLI, CreatedAt: now.Add(-2 * time.Hour)}
	newer := &reporter.KnownEntry{ID: 2, Host: "*", Reason: "newer", Source: reporter.KnownSourceCLI, CreatedAt: now.Add(-time.Minute)}
	rows := []*hitRow{{Entry: older, Lines: 5, Hosts: map[string]int{"a": 5}}, {Entry: newer, Lines: 1, Hosts: map[string]int{"a": 1}}}

	var out bytes.Buffer
	printHitOverview(&out, rows, &sinceFlag{}, "", false)
	if i, j := strings.Index(out.String(), "newer"), strings.Index(out.String(), "older"); i < 0 || j < 0 || i > j {
		t.Errorf("newest entry should come first:\n%s", out.String())
	}

	since := sinceFlag{now: func() time.Time { return now }}
	if err := since.Set("1h"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	printHitOverview(&out, rows, &since, "", false)
	text := out.String()
	if strings.Contains(text, "older") || !strings.Contains(text, "newer") {
		t.Errorf("--since 1h should hide the two-hour-old entry:\n%s", text)
	}
	if !strings.Contains(text, "2 entries fired, 6 lines dropped") {
		t.Errorf("the totals line should count everything that fired, filtered or not:\n%s", text)
	}
}

func TestHitDetailGroupsByMessageMostFrequentFirst(t *testing.T) {
	knowns, ids := seedHitsStore(t)
	id := ids["cron ran a job"]
	rows := tallyHits(hitsFixture, knowns, id)

	var out bytes.Buffer
	printHitDetail(&out, rows, id, false)
	text := out.String()
	if !strings.Contains(text, "3 lines on 2 hosts") {
		t.Errorf("missing the summary line:\n%s", text)
	}
	hourly := strings.Index(text, "CROND: (root) CMD (run-parts /etc/cron.hourly)")
	check := strings.Index(text, "CRON: (root) CMD (/var/dhcp/check.update.needed")
	if hourly < 0 || check < 0 || hourly > check {
		t.Errorf("expected the two-line shape (pid stripped) before the one-line shape:\n%s", text)
	}
	if strings.Contains(text, "dnsbox") || strings.Contains(text, "[289]") {
		t.Errorf("grouped view should drop host and pid:\n%s", text)
	}

	out.Reset()
	printHitDetail(&out, rows, id, true)
	if !strings.Contains(out.String(), hitsFixture[0]) || !strings.Contains(out.String(), hitsFixture[2]) {
		t.Errorf("--raw should print the caught lines verbatim:\n%s", out.String())
	}

	out.Reset()
	printHitDetail(&out, rows, ids["silent"], false)
	if !strings.Contains(out.String(), "did not fire on this dump") {
		t.Errorf("an entry that never fired:\n%s", out.String())
	}
}
