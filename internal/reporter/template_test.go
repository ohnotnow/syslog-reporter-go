package reporter

import (
	"regexp"
	"testing"
)

func TestMaskMessageTokens(t *testing.T) {
	const host = "mx1.example.test"
	cases := []struct{ in, want string }{
		// emails first: an address at the logging host must not leak its
		// local part once the host mask has eaten the domain
		{"to=<someone.name@mx1.example.test>, relay=mail.example.test[10.0.0.1]:25", "to=<<email>>, relay=<fqdn>[<ip>]:<n>"},
		{"from=<> to=alice@gmail.com bounced", "from=<> to=<email> bounced"},
		{"connection from mx1.example.test and mx1 refused", "connection from <host> and <host> refused"},
		{"client 192.168.1.10#53 (a.b.c): query denied", "client <ip>#<n> (<fqdn>): query denied"},
		{"link fe80::1 down; 2001:db8::ff00:42:8329 up", "link <ip6> down; <ip6> up"},
		{"at 12:00:01.000 FuMain ready; flooding on port [::]:8080", "at <n>:<n>:<n>.<n> FuMain ready; flooding on port [<ip6>]:<n>"},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334 seen", "<ip6> seen"},
		{"version 1.2.3 of tool", "version <n>.<n>.<n> of tool"},
		{"session id 0123456789abcdef0123 opened", "session id <hex> opened"},
		{"Failed password for invalid user admin from 10.1.1.1 port 22", "Failed password for invalid user <user> from <ip> port <n>"},
		{"Accepted publickey for bob from 10.1.1.1", "Accepted publickey for <user> from <ip>"},
		{"pam_unix(sshd:session): session opened for user root by (uid=0)", "pam_unix(sshd:session): session opened for user <user> by (uid=<n>)"},
		{"CPU3: Core temperature/speed normal", "CPU<n>: Core temperature/speed normal"},
	}
	for _, c := range cases {
		if got := MaskMessage(c.in, host); got != c.want {
			t.Errorf("MaskMessage(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestTemplateSplitsProgramFromMaskedMessage(t *testing.T) {
	program, template, rest, ok := Template("Sep  8 06:25:01 dhcpbox CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)")
	// a dotted filename masks as <fqdn> too: over-wide for grouping is fine,
	// and the regex it becomes is \S+ either way
	if !ok || program != "CRON" || template != "(root) CMD (/var/dhcp/<fqdn> >/dev/null <n>>&<n>)" ||
		rest != "CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)" {
		t.Errorf("got %q %q %q %v", program, template, rest, ok)
	}
	if _, _, _, ok := Template("not a syslog line"); ok {
		t.Error("a malformed line should not template")
	}
}

func TestTemplateRegexMatchesItsOwnLinesAndNotOtherPrograms(t *testing.T) {
	lines := []string{
		"Sep  8 06:25:01 dhcpbox CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)",
		"Sep  8 06:26:01 dhcpbox CRON[301]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)",
	}
	program, template, _, _ := Template(lines[0])
	re := regexp.MustCompile("(?m)" + TemplateRegex(program, template))
	for _, line := range lines {
		_, _, rest, _ := Template(line)
		if !re.MatchString(rest) {
			t.Errorf("regex %q should match %q", re, rest)
		}
	}
	if re.MatchString("anacron[5]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)") {
		t.Error("regex should be pinned to the program")
	}
	if !re.MatchString("CRON (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)") {
		t.Error("a tag with neither pid nor colon should still match")
	}
	if err := CheckLinePattern(TemplateRegex("named", "client <ip>#<n> (<fqdn>): query denied")); err != nil {
		t.Errorf("generated regex does not compile: %v", err)
	}
}
