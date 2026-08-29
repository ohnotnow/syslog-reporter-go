package reporter

// Port of agents/known_knowns.py: operator-maintained "known knowns", estate
// oddities the team has already eye-rolled at and no longer wants in every
// report. Entries live in a TOML file, gitignored by default because the
// content is inherently estate-identifying.
//
//	[[known]]
//	host = "blah"              # glob pattern: "blah", "lab*", or "*"
//	match = "port 1234"        # optional: regex, applied after the hostname
//	program = "kernel"         # optional: glob, mutes (host, program) anomalies
//	reason = "microscope attached for the optics experiment"
//	added = 2026-08-27
//	expires = 2030-09-01       # optional: entry lapses after this slice date
//
// Each entry needs a reason and at least one of match / program. Expiry is
// judged against the date of the log slice being processed, not the wall
// clock, so historical backfills behave historically.

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type KnownEntry struct {
	Host    string
	Reason  string
	Match   string
	Program string
	Added   *time.Time
	Expires *time.Time
	Hits    int

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

// rawKnownsFile mirrors the TOML shape. Dates are toml.LocalDate so bare
// TOML dates (2026-08-27, no time part) parse without a time component.
type rawKnownsFile struct {
	Known []rawKnownEntry `toml:"known"`
}

type rawKnownEntry struct {
	Host    string          `toml:"host"`
	Reason  string          `toml:"reason"`
	Match   string          `toml:"match"`
	Program string          `toml:"program"`
	Added   *toml.LocalDate `toml:"added"`
	Expires *toml.LocalDate `toml:"expires"`
}

func localDateToTime(d *toml.LocalDate) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Date(d.Year, time.Month(d.Month), d.Day, 0, 0, 0, 0, time.UTC)
	return &t
}

// LoadKnownKnowns reads the TOML file at tomlPath; a missing file just means
// no known knowns. Malformed entries fail loudly by design.
func LoadKnownKnowns(tomlPath string, logDate time.Time) (*KnownKnowns, error) {
	data, err := os.ReadFile(tomlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewKnownKnowns(nil, logDate), nil
		}
		return nil, err
	}
	var raw rawKnownsFile
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", tomlPath, err)
	}
	var entries []*KnownEntry
	for _, r := range raw.Known {
		if r.Host == "" || r.Reason == "" {
			return nil, fmt.Errorf(
				"known-known entry %+v in %s needs both 'host' and 'reason'", r, tomlPath)
		}
		e, err := newKnownEntry(r.Host, r.Reason, r.Match, r.Program,
			localDateToTime(r.Added), localDateToTime(r.Expires))
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return NewKnownKnowns(entries, logDate), nil
}

// LineIgnored reports whether a line from host (message = everything after
// the hostname, i.e. program + text) matches an active entry.
func (k *KnownKnowns) LineIgnored(host, message string) bool {
	for _, e := range k.Active {
		if e.matchRe != nil && e.matchesHost(host) && e.matchRe.MatchString(message) {
			e.Hits++
			return true
		}
	}
	return false
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
