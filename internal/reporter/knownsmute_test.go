package reporter

import (
	"errors"
	"testing"
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
	entries, err := DeriveKnownEntries(d, nil, "", "scanner target", muteDay, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Host != "web01.example.test" || entries[0].Program != "sshd" ||
		entries[0].Match != "" || entries[0].Reason != "scanner target" {
		t.Errorf("entries = %+v", entries[0])
	}
	if !entries[0].Added.Equal(muteDay) || entries[0].Source != KnownSourceAPI ||
		entries[0].FindingID == nil || *entries[0].FindingID != 7 {
		t.Errorf("added/provenance = %+v", entries[0])
	}
}

func TestDeriveKnownEntriesParsesTheIssueExampleOnePerHost(t *testing.T) {
	d := issueDetail([]string{"dhcp01.example.test", "dhcp02.example.test"},
		"Sep  7 10:00:01 dhcp01.example.test dhcpd[712]: DHCPDISCOVER from 00:11:22:33:44:55: no free leases",
		"DHCP server")
	expires := day(2027, 1, 31)
	entries, err := DeriveKnownEntries(d, nil, "", "no pool by design", muteDay, &expires)
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
	entries, err := DeriveKnownEntries(d, nil, "", "expected", muteDay, nil)
	if err != nil || len(entries) != 1 || entries[0].Program != "nginx" {
		t.Errorf("entries = %+v, err = %v", entries, err)
	}
}

func TestDeriveKnownEntriesRefusesProseServiceAndEmptyHosts(t *testing.T) {
	d := issueDetail([]string{"web01.example.test"}, "not a syslog line", "the web server")
	if _, err := DeriveKnownEntries(d, nil, "", "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveProgram) {
		t.Errorf("prose service err = %v", err)
	}
	d = issueDetail(nil, "Sep  7 10:00:01 web01.example.test nginx[1]: boom", "nginx")
	if _, err := DeriveKnownEntries(d, nil, "", "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveProgram) {
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
		if _, err := DeriveKnownEntries(d, nil, "", "x", muteDay, nil); !errors.Is(err, ErrCannotDeriveHost) {
			t.Errorf("host %q: err = %v, want ErrCannotDeriveHost", host, err)
		}
	}
	for _, host := range []string{"web01", "db-2.example.test", "web_01", "fd00::1", "10.0.0.7"} {
		d := issueDetail([]string{host}, example, "nginx")
		entries, err := DeriveKnownEntries(d, nil, "", "x", muteDay, nil)
		if err != nil || len(entries) != 1 || entries[0].Host != host {
			t.Errorf("host %q: entries = %v, err = %v", host, entries, err)
		}
	}
}

func TestDeriveKnownEntriesNarrowsToTheFindingsOwnHosts(t *testing.T) {
	d := issueDetail([]string{"dhcp01.example.test", "dhcp02.example.test", "dhcp03.example.test"},
		"Sep  7 10:00:01 dhcp01.example.test dhcpd[712]: no free leases", "dhcpd")
	entries, err := DeriveKnownEntries(d, []string{"dhcp03.example.test", "dhcp01.example.test"}, "", "x", muteDay, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Finding order, not request order.
	if len(entries) != 2 || entries[0].Host != "dhcp01.example.test" || entries[1].Host != "dhcp03.example.test" {
		t.Errorf("entries = %+v", entries)
	}
	var notOn *HostNotOnFindingError
	_, err = DeriveKnownEntries(d, []string{"dhcp01.example.test", "dhcp09.example.test"}, "", "x", muteDay, nil)
	if !errors.As(err, &notOn) || notOn.Host != "dhcp09.example.test" || notOn.FindingID != 42 {
		t.Errorf("host off the finding: err = %v", err)
	}
}

func TestDeriveKnownEntriesCompilesTheMatchLikeTheRun(t *testing.T) {
	d := issueDetail([]string{"dhcp01.example.test"},
		"Sep  7 10:00:01 dhcp01.example.test dhcpd[712]: no free leases", "dhcpd")
	if _, err := DeriveKnownEntries(d, nil, "no free (", "x", muteDay, nil); !errors.Is(err, ErrBadMatch) {
		t.Errorf("bad regex err = %v", err)
	}
	entries, err := DeriveKnownEntries(d, nil, `no free leases$`, "x", muteDay, nil)
	if err != nil || len(entries) != 1 || entries[0].Match != `no free leases$` || entries[0].Program != "dhcpd" {
		t.Errorf("entries = %+v, err = %v", entries, err)
	}
}
