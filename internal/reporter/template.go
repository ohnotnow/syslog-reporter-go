package reporter

// Message templating for the Jev noise finder (ait srg-M3Yny.9, ant ADR
// srg-FGSKN): collapse a day's lines into message shapes by masking the
// parts that vary (addresses, hosts, numbers, users) so one shape stands
// for many lines, and turn a shape back into a known-known regex. The
// mask order matters: emails first, or masking the host breaks the domain
// part and the address leaks (the exposure incident in srg-FGSKN).

import (
	"regexp"
	"strings"
)

var (
	maskEmail = regexp.MustCompile(`[^\s<>@]+@[^\s<>]+`)
	maskIPv4  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// Either a full 6-to-8-group address or anything with a '::' in it; a
	// looser form (two or more hex groups) also matched clock times.
	maskIPv6 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){5,7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?`)
	// RE2 has no lookahead, so the "must contain a letter" test that keeps
	// version numbers out of the FQDN mask is done in code.
	maskFQDN  = regexp.MustCompile(`\b[\w-]+(?:\.[\w-]+){2,}\b`)
	maskHex   = regexp.MustCompile(`\b[0-9a-fA-F-]{16,}\b`)
	maskUser1 = regexp.MustCompile(`(?i)\b(user[= ])(\S+)`)
	maskUser2 = regexp.MustCompile(`\bfor (invalid user )?(\S+) from\b`)
	// A token or a digit run: tokens are matched first so the 6 in <ip6>
	// survives the digit mask.
	maskNum   = regexp.MustCompile(`<[a-z0-9]+>|\d+`)
	hasLetter = regexp.MustCompile(`[a-zA-Z]`)
)

// MaskMessage replaces the varying parts of a syslog message with tokens:
// <email>, <host> (the logging host's own name, long or short), <ip>,
// <ip6>, <fqdn>, <hex>, <user>, <n>.
func MaskMessage(msg, host string) string {
	m := maskEmail.ReplaceAllString(msg, "<email>")
	if host != "" {
		m = strings.ReplaceAll(m, host, "<host>")
		if short, _, _ := strings.Cut(host, "."); len(short) > 2 {
			m = regexp.MustCompile(`\b`+regexp.QuoteMeta(short)+`\b`).ReplaceAllString(m, "<host>")
		}
	}
	m = maskIPv4.ReplaceAllString(m, "<ip>")
	m = maskIPv6.ReplaceAllString(m, "<ip6>")
	m = maskFQDN.ReplaceAllStringFunc(m, func(s string) string {
		if hasLetter.MatchString(s) {
			return "<fqdn>"
		}
		return s
	})
	m = maskHex.ReplaceAllString(m, "<hex>")
	m = maskUser1.ReplaceAllString(m, "${1}<user>")
	m = maskUser2.ReplaceAllString(m, "for ${1}<user> from")
	m = maskNum.ReplaceAllStringFunc(m, func(s string) string {
		if s[0] == '<' {
			return s
		}
		return "<n>"
	})
	return m
}

// Template parses one syslog line and returns its program, its masked
// message, and rest: the 'program[pid]: message' text after the hostname,
// which is what a known-known match sees. ok is false for a line
// ParseLine rejects.
func Template(line string) (program, template, rest string, ok bool) {
	p := ParseLine(line)
	if p == nil {
		return "", "", "", false
	}
	rest = strings.TrimRight(splitWS(line, 4)[4], "\n")
	_, msg, _ := strings.Cut(rest, " ") // drop the 'program[pid]:' tag
	return p.Program, MaskMessage(msg, p.Host), rest, true
}

// tokenRegex is what each mask token becomes in a known-known match.
var tokenRegex = map[string]string{
	"<n>":     `\d+`,
	"<ip>":    `\d{1,3}(?:\.\d{1,3}){3}`,
	"<ip6>":   `\S+`,
	"<host>":  `\S+`,
	"<fqdn>":  `\S+`,
	"<hex>":   `\S+`,
	"<user>":  `\S+`,
	"<email>": `\S+`,
}

// TemplateRegex turns a program and masked message into a match regex for
// a host * known-known: the program tag (pid and colon both optional; the
// ELK renderer emits 'kcare INFO: ...' for records with neither), then the
// template with each token widened. The result is matched against the
// text after the hostname, which is what LineIgnored sees.
func TemplateRegex(program, template string) string {
	var b strings.Builder
	b.WriteString(regexp.QuoteMeta(program))
	b.WriteString(`(?:\[\d+\])?:? `)
	rest := regexp.QuoteMeta(template)
	for tok, re := range tokenRegex {
		rest = strings.ReplaceAll(rest, regexp.QuoteMeta(tok), re)
	}
	b.WriteString(rest)
	return b.String()
}
