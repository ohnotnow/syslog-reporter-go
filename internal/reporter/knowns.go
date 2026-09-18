package reporter

// Operator-maintained "known knowns": estate oddities the team has already
// eye-rolled at and no longer wants in every report. Entries live in the
// known_knowns table of the shared database (migration 5, ant ADR
// srg-gzXn6; knownsstore.go reads and writes them):
//
//	host     glob pattern: "blah", "lab*", or "*"
//	match    optional: regex on the message; drops only matching lines
//	program  optional: glob; drops the program's lines on the host
//	         AND mutes its (host, program) anomalies
//	reason   why, in the operator's words
//	added    the day the entry was made
//	expires  optional: entry lapses after this slice date
//
// Each entry needs a reason and at least one of match / program. Host plus
// program mutes the lot; host plus match mutes specific lines (ant ADR
// srg-zX4An, owner decision 2026-09-08). Expiry is judged against the date
// of the log slice being processed, not the wall clock, so historical
// backfills behave historically. Entries are created by the API's mute
// endpoint (from a finding) or the knowns CLI (free-form, on the box).

import (
	"fmt"
	"path"
	"regexp"
	"time"
)

type KnownEntry struct {
	ID      int64 // database row id; 0 for an entry not yet stored
	Host    string
	Reason  string
	Match   string
	Program string
	Added   *time.Time
	Expires *time.Time
	Hits    int

	// Provenance (migration 5): who created the entry and from what.
	Source      string    // one of KnownSources
	CreatedBy   string    // username for API entries; "" for CLI
	TokenPrefix string    // api_tokens prefix for API entries; "" for CLI
	FindingID   *int64    // the finding a mute derived from; nil for free-form
	CreatedAt   time.Time // wall-clock instant the row was written; zero for an unstored entry

	matchRe *regexp.Regexp
}

func newKnownEntry(host, reason, match, program string, added, expires *time.Time) (*KnownEntry, error) {
	e := &KnownEntry{Host: host, Reason: reason, Match: match, Program: program,
		Added: added, Expires: expires}
	if e.Match == "" && e.Program == "" {
		return nil, fmt.Errorf(
			"known-known entry for host '%s' (%q) needs at least one of 'match' or 'program'",
			e.Host, e.Reason)
	}
	// Compile eagerly so a bad regex fails loudly at startup, not
	// silently on every line.
	if e.Match != "" {
		re, err := compileLinePattern(e.Match)
		if err != nil {
			return nil, fmt.Errorf("known-known entry for host '%s': bad match regex: %w", e.Host, err)
		}
		e.matchRe = re
	}
	return e, nil
}

func (e *KnownEntry) isActive(logDate time.Time) bool {
	return e.Expires == nil || !logDate.After(*e.Expires)
}

func (e *KnownEntry) matchesHost(host string) bool {
	ok, err := path.Match(e.Host, host)
	return err == nil && ok
}

type KnownKnowns struct {
	Active  []*KnownEntry
	Expired []*KnownEntry
}

func NewKnownKnowns(entries []*KnownEntry, logDate time.Time) *KnownKnowns {
	k := &KnownKnowns{}
	for _, e := range entries {
		if e.isActive(logDate) {
			k.Active = append(k.Active, e)
		} else {
			k.Expired = append(k.Expired, e)
		}
	}
	return k
}

// LineIgnored reports whether an active entry drops this line from host. A
// match entry drops the lines its regex matches; a program-only entry drops
// every line from that program. program is the token ParseLine extracts,
// or "" for a line it cannot parse, so program entries never fire on odd
// lines. First hit wins and is counted for the report footer.
func (k *KnownKnowns) LineIgnored(host, program, message string) bool {
	return k.IgnoringEntry(host, program, message) != nil
}

// IgnoringEntry is LineIgnored returning the entry that fired, or nil, for
// callers that need to know which rule caught a line ('knowns hits').
func (k *KnownKnowns) IgnoringEntry(host, program, message string) *KnownEntry {
	for _, e := range k.Active {
		if !e.matchesHost(host) {
			continue
		}
		switch {
		case e.matchRe != nil:
			if !e.matchRe.MatchString(message) {
				continue
			}
		case program == "":
			continue
		default:
			if ok, err := path.Match(e.Program, program); err != nil || !ok {
				continue
			}
		}
		e.Hits++
		return e
	}
	return nil
}

// AnomalyMuted reports whether an active entry mutes this (host, program).
func (k *KnownKnowns) AnomalyMuted(host, program string) bool {
	for _, e := range k.Active {
		if e.Program == "" || !e.matchesHost(host) {
			continue
		}
		if ok, err := path.Match(e.Program, program); err == nil && ok {
			e.Hits++
			return true
		}
	}
	return false
}

// HitEntries returns the active entries that suppressed something this run.
func (k *KnownKnowns) HitEntries() []*KnownEntry {
	var hit []*KnownEntry
	for _, e := range k.Active {
		if e.Hits > 0 {
			hit = append(hit, e)
		}
	}
	return hit
}
