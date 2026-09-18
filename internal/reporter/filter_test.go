package reporter

// Tests for the deterministic noise filter. Hostnames are
// fictional, as there.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPidDifferencesDoNotDefeatTheDedupeCap(t *testing.T) {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, fmt.Sprintf(
			"Aug 26 0%d:17:01 cronbox CRON[%d]: (munin) CMD (/usr/bin/munin-cron)", i, 1000+i))
	}
	// a pid-varying line dedupes to the 3-copy cap like an identical one
	if got := NewLogFilter(nil, nil).removeDuplicates(lines); len(got) != 3 {
		t.Errorf("expected 3 lines after dedupe, got %d", len(got))
	}
}

// bundledKnowns builds the known-knowns a seeded database would give the
// run, so these tests pin the shipped rules, not an empty filter.
func bundledKnowns(t *testing.T) *KnownKnowns {
	t.Helper()
	rules, err := BundledNoiseRules()
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]*KnownEntry, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, mustEntry(t, r.Host, r.Reason, r.Match, "", nil))
	}
	return NewKnownKnowns(entries, sliceDate)
}

func filterOne(t *testing.T, line string) []string {
	t.Helper()
	return NewLogFilter([]string{line}, bundledKnowns(t)).Run()
}

func TestNamedRefusedScannerChatterIsDropped(t *testing.T) {
	for _, message := range []string{
		"client @0x7f6d 167.248.133.11#31871 (1.2.3.4.in-addr.arpa): " +
			"query (cache) '1.2.3.4.in-addr.arpa/MX/IN' denied",
		"client @0x7f6d 167.248.133.11#31871 (1.2.3.4.in-addr.arpa): " +
			"query failed (REFUSED) for 1.2.3.4.in-addr.arpa/IN/MX at query.c:7148",
		"client @0x7f6d 1.2.3.4#5 (4.4.8.in-addr.arpa): " +
			"rate limit slip REFUSED error response to 1.2.3.4/24",
	} {
		line := "Aug 26 14:00:05 dnsbox named[32325]: " + message
		if got := filterOne(t, line); len(got) != 0 {
			t.Errorf("expected drop for %q, got %#v", message, got)
		}
	}
}

func TestNamedServfailIsNormalisedNotDropped(t *testing.T) {
	line := "Aug 26 14:00:05 dnsbox named[32325]: client @0x7f6d 10.0.0.1#31871 " +
		"(x.example.com): query failed (SERVFAIL) for x.example.com/IN/A at query.c:7100"
	want := []string{"Aug 26 14:00:05 dnsbox named SERVFAIL query failure"}
	if got := filterOne(t, line); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCronJobAnnouncementsAreDropped(t *testing.T) {
	for _, line := range []string{
		"Aug 26 06:25:01 dhcpbox CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)",
		"Aug 26 06:25:01 dnsbox CROND[288]: (root) CMD (run-parts /etc/cron.hourly)",
		"Aug 26 06:25:01 gatebox crontab[132]: (root) LIST (root)",
		"Aug 26 06:25:01 scanbox CRON[301]: (CRON) info (No MTA installed, discarding output)",
	} {
		if got := filterOne(t, line); len(got) != 0 {
			t.Errorf("expected drop for %q, got %#v", line, got)
		}
	}
}

func TestErrorShapedLinesStillSurvive(t *testing.T) {
	for _, line := range []string{
		"Aug 26 14:00:05 labbox dhcpcd[884]: dhcpcd is not running",
		"Aug 26 14:00:05 dnsbox named[32325]: zone example.ac.uk/IN: " +
			"refresh: could not refresh zone",
	} {
		if got := filterOne(t, line); !reflect.DeepEqual(got, []string{line}) {
			t.Errorf("expected %q kept, got %#v", line, got)
		}
	}
}

func TestProgramOnlyKnownEntryDropsLinesThroughTheFilter(t *testing.T) {
	entry := mustEntry(t, "dhcp01.example.test", "no pool by design", "", "dhcpd", nil)
	knowns := NewKnownKnowns([]*KnownEntry{entry}, sliceDate)
	lines := []string{
		"Aug 26 14:00:05 dhcp01.example.test dhcpd[7]: DHCPDISCOVER from 00:11:22:33:44:55: no free leases",
		"Aug 26 14:00:06 dhcp02.example.test dhcpd[8]: DHCPDISCOVER from 00:11:22:33:44:66: no free leases",
		"Aug 26 14:00:07 dhcp01.example.test sshd[9]: error: kex_exchange_identification: read: Connection reset",
		"malformed line from dhcp01.example.test dhcpd: no free leases",
	}
	// Run() also normalises surviving lines, so pin the drop, not the text.
	got := NewLogFilter(lines, knowns).Run()
	if len(got) != 3 {
		t.Errorf("kept %d lines, want 3: %#v", len(got), got)
	}
	for _, line := range got {
		if strings.HasPrefix(line, "Aug 26 14:00:05 dhcp01.example.test dhcpd") {
			t.Errorf("the dhcp01 dhcpd line should have been dropped: %q", line)
		}
	}
	if entry.Hits != 1 {
		t.Errorf("hits = %d, want 1", entry.Hits)
	}
}
