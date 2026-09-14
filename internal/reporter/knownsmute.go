package reporter

// Mute-by-finding-id (ait srg-Kj5Q8.6, ant ADRs srg-yYpms and srg-gzXn6):
// the API takes a finding id and a reason and this file turns the finding
// into one host+program entry per affected host, ready for the store. The
// program is never supplied by the client; it is derived here.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// programToken is what a syslog program name looks like once ParseLine has
// had it: no spaces, no quotes, nothing a glob would misread.
var programToken = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// hostToken is a literal hostname (or IP literal): letters, digits, dots,
// hyphens, underscores and colons. Hosts in the known-knowns table are
// globs (path.Match), and an issue's hosts come from the LLM, so a host
// carrying a glob metacharacter must never be copied into an entry: a
// single API mute would become an estate-wide rule.
var hostToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// ErrCannotDeriveProgram means the finding carries no usable program name,
// so muting it is a job for the box (the knowns CLI).
var ErrCannotDeriveProgram = fmt.Errorf("cannot derive a program name for this finding")

// ErrBadMatch wraps a match regex that does not compile.
var ErrBadMatch = fmt.Errorf("bad match regex")

// HostNotOnFindingError is a requested host the finding does not list.
type HostNotOnFindingError struct {
	Host      string
	FindingID int64
}

func (e *HostNotOnFindingError) Error() string {
	return fmt.Sprintf("host %q is not on finding %d", e.Host, e.FindingID)
}

// ErrCannotDeriveHost means a host on the finding is not a plain hostname,
// so muting it is a job for the box (SECURITY_REVIEW.md SR-06).
var ErrCannotDeriveHost = fmt.Errorf("a host on this finding is not a plain hostname")

// DeriveKnownEntries builds one host+program entry per affected host. An
// anomaly finding names both directly. An issue finding's program is parsed
// from its example log line (the same parse logcontext.go uses to anchor
// the example), falling back to the LLM's affected_service only when that
// already looks like a program token; otherwise ErrCannotDeriveProgram.
// Every host must be a literal hostname (hostToken), else
// ErrCannotDeriveHost: the whole finding is refused, never partly muted.
//
// onlyHosts, when non-empty, narrows the entries to those hosts; each must
// be one of the finding's own (HostNotOnFindingError otherwise), so the
// client can subtract from the finding's host set but never add to it.
// match, when non-empty, is a regex the run will compile exactly the same
// way (ErrBadMatch if it cannot); the entry then carries both program and
// match, so the (host, program) anomaly is muted and only matching lines
// drop, the TOML-era semantics for an entry with both fields.
func DeriveKnownEntries(d *FindingDetail, onlyHosts []string, match, reason string, added time.Time, expires *time.Time) ([]KnownEntryInput, error) {
	var hosts []string
	var program string
	switch {
	case d.Anomaly != nil:
		hosts, program = []string{d.Anomaly.Host}, d.Anomaly.Program
	case d.Issue != nil:
		hosts = d.Hosts
		if p := ParseLine(strings.TrimSpace(d.Issue.ExampleLogEntry)); p != nil {
			program = p.Program
		} else if programToken.MatchString(d.Issue.AffectedService) {
			program = d.Issue.AffectedService
		}
	}
	if program == "" || !programToken.MatchString(program) || len(hosts) == 0 {
		return nil, ErrCannotDeriveProgram
	}
	if match != "" {
		if _, err := compileLinePattern(match); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadMatch, err)
		}
	}
	if len(onlyHosts) > 0 {
		for _, want := range onlyHosts {
			if !slices.Contains(hosts, want) {
				return nil, &HostNotOnFindingError{Host: want, FindingID: d.ID}
			}
		}
		hosts = slices.DeleteFunc(slices.Clone(hosts), func(h string) bool { return !slices.Contains(onlyHosts, h) })
	}
	fid := d.ID
	var entries []KnownEntryInput
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if !hostToken.MatchString(host) {
			return nil, ErrCannotDeriveHost
		}
		entries = append(entries, KnownEntryInput{Host: host, Program: program, Match: match, Reason: reason,
			Added: added, Expires: expires, Source: KnownSourceAPI, FindingID: &fid})
	}
	if len(entries) == 0 {
		return nil, ErrCannotDeriveProgram
	}
	return entries, nil
}
