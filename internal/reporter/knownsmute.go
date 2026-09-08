package reporter

// Mute-by-finding-id (ait srg-Kj5Q8.6, ant ADR srg-yYpms): the API never
// accepts a host, program or regex from a client. It takes a finding id and
// a reason, and this file turns the finding into host+program entries and
// appends them to the operator's known-knowns TOML. The file stays the
// single suppression mechanism; the API is just another editor of it.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// programToken is what a syslog program name looks like once ParseLine has
// had it: no spaces, no quotes, nothing a glob would misread.
var programToken = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// hostToken is a literal hostname (or IP literal): letters, digits, dots,
// hyphens, underscores and colons. Hosts in the known-knowns file are
// globs (path.Match), and an issue's hosts come from the LLM, so a host
// carrying a glob metacharacter must never be copied into an entry: a
// single API mute would become an estate-wide rule.
var hostToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

var appendMu sync.Mutex

// ErrCannotDeriveProgram means the finding carries no usable program name,
// so muting it is a job for the box (edit the TOML or use the CLI).
var ErrCannotDeriveProgram = fmt.Errorf("cannot derive a program name for this finding")

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
func DeriveKnownEntries(d *FindingDetail, reason string, added time.Time, expires *time.Time) ([]*KnownEntry, error) {
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
	var entries []*KnownEntry
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if !hostToken.MatchString(host) {
			return nil, ErrCannotDeriveHost
		}
		e, err := newKnownEntry(host, reason, "", program, &added, expires)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, ErrCannotDeriveProgram
	}
	return entries, nil
}

// AppendKnownEntries adds entries to the TOML at path, creating the file if
// it is missing and skipping any whose host+program is already active (a
// match entry never counts as a duplicate). It returns the entries actually
// written. The new file is written beside the old one and renamed over it,
// so a daily run reading concurrently sees the old file or the new, never
// a partial one; the candidate is re-parsed before the rename so a bad
// write can never break the next run.
func AppendKnownEntries(path string, entries []*KnownEntry) ([]*KnownEntry, error) {
	// One writer at a time: the rename makes each write atomic for readers,
	// but two concurrent load-dedupe-write sequences would both start from
	// the same file and the last rename would discard the other's entries,
	// with both callers told 200 (SECURITY_REVIEW.md SR-04). A server has
	// one known-knowns path, so one process-wide mutex is enough; hand
	// edits from another process are not coordinated (ant ADR srg-ZE9vQ).
	appendMu.Lock()
	defer appendMu.Unlock()
	today := time.Now().UTC()
	existing, err := LoadKnownKnowns(path, today)
	if err != nil {
		return nil, err
	}
	active := map[[2]string]bool{}
	for _, e := range existing.Active {
		if e.Match == "" && e.Program != "" {
			active[[2]string{e.Host, e.Program}] = true
		}
	}
	var fresh []*KnownEntry
	var block strings.Builder
	for _, e := range entries {
		key := [2]string{e.Host, e.Program}
		if active[key] {
			continue
		}
		active[key] = true
		fresh = append(fresh, e)
		block.WriteString(e.tomlBlock())
	}
	if len(fresh) == 0 {
		return nil, nil
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var out strings.Builder
	out.Write(old)
	if len(old) > 0 && !strings.HasSuffix(string(old), "\n") {
		out.WriteString("\n")
	}
	if len(old) > 0 {
		out.WriteString("\n")
	}
	out.WriteString(block.String())

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	cleanup := func() { os.Remove(tmpPath) }
	if _, err := tmp.WriteString(out.String()); err != nil {
		tmp.Close()
		cleanup()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := LoadKnownKnowns(tmpPath, today); err != nil {
		cleanup()
		return nil, fmt.Errorf("refusing to write an unparseable known-knowns file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return nil, err
	}
	return fresh, nil
}

// tomlBlock renders one [[known]] table in the header comment's field order.
func (e *KnownEntry) tomlBlock() string {
	var b strings.Builder
	b.WriteString("[[known]]\n")
	fmt.Fprintf(&b, "host = %s\n", tomlString(e.Host))
	if e.Program != "" {
		fmt.Fprintf(&b, "program = %s\n", tomlString(e.Program))
	}
	if e.Match != "" {
		fmt.Fprintf(&b, "match = %s\n", tomlString(e.Match))
	}
	fmt.Fprintf(&b, "reason = %s\n", tomlString(e.Reason))
	if e.Added != nil {
		fmt.Fprintf(&b, "added = %s\n", e.Added.Format("2006-01-02"))
	}
	if e.Expires != nil {
		fmt.Fprintf(&b, "expires = %s\n", e.Expires.Format("2006-01-02"))
	}
	b.WriteString("\n")
	return b.String()
}

// tomlString is a TOML basic string: backslash and double quote escaped.
// Control characters are refused upstream (the API caps and cleans the
// reason), so nothing else needs escaping.
func tomlString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
