package reporter

// Known-knowns in the database (migration 5, ant ADR srg-gzXn6). Rows are
// built into KnownEntry values through newKnownEntry, so a bad regex or an
// entry with neither program nor match is refused before it is written and
// again, loudly, if one ever appears in the table by other means.

import (
	"database/sql"
	"fmt"
	"time"
)

const (
	KnownSourceAPI = "api"
	KnownSourceCLI = "cli"
)

// KnownEntryInput is what a caller supplies; ID and created_at come from
// the store. Empty CreatedBy and TokenPrefix are stored as NULL.
type KnownEntryInput struct {
	Host, Program, Match, Reason string
	Added                        time.Time
	Expires                      *time.Time
	Source                       string
	CreatedBy, TokenPrefix       string
	FindingID                    *int64
}

// AddKnownEntries writes the inputs in one transaction and returns the
// stored entries with ids, in input order. Every input is validated first,
// so one bad regex writes nothing. It does not dedupe; callers decide.
func (s *LibraryStore) AddKnownEntries(in []KnownEntryInput) ([]*KnownEntry, error) {
	entries := make([]*KnownEntry, 0, len(in))
	for _, i := range in {
		if i.Host == "" || i.Reason == "" {
			return nil, fmt.Errorf("known-known entry needs both 'host' and 'reason'")
		}
		if i.Source != KnownSourceAPI && i.Source != KnownSourceCLI {
			return nil, fmt.Errorf("known-known entry source must be %q or %q", KnownSourceAPI, KnownSourceCLI)
		}
		added := i.Added.UTC().Truncate(24 * time.Hour)
		e, err := newKnownEntry(i.Host, i.Reason, i.Match, i.Program, &added, i.Expires)
		if err != nil {
			return nil, err
		}
		e.Source, e.CreatedBy, e.TokenPrefix, e.FindingID = i.Source, i.CreatedBy, i.TokenPrefix, i.FindingID
		entries = append(entries, e)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	for _, e := range entries {
		res, err := tx.Exec(`INSERT INTO known_knowns
			(host, program, match, reason, added, expires, source, created_by, token_prefix, finding_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.Host, e.Program, e.Match, e.Reason, dayString(e.Added), dayString(e.Expires),
			e.Source, nullString(e.CreatedBy), nullString(e.TokenPrefix), nullInt(e.FindingID), now)
		if err != nil {
			return nil, err
		}
		if e.ID, err = res.LastInsertId(); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ListKnownEntries returns every stored entry, active or lapsed, by id.
func (s *LibraryStore) ListKnownEntries() ([]*KnownEntry, error) {
	return s.knownEntriesWhere("1 = 1")
}

// KnownEntriesForFinding returns the entries a mute of findingID created.
func (s *LibraryStore) KnownEntriesForFinding(findingID int64) ([]*KnownEntry, error) {
	return s.knownEntriesWhere("finding_id = ?", findingID)
}

// DeleteKnownEntry removes one row; false means there was no such row.
func (s *LibraryStore) DeleteKnownEntry(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM known_knowns WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// LoadKnownKnowns reads every entry and splits it active/expired against
// logDate, the date of the log slice being processed (not the wall clock,
// so backfills behave historically).
func (s *LibraryStore) LoadKnownKnowns(logDate time.Time) (*KnownKnowns, error) {
	entries, err := s.ListKnownEntries()
	if err != nil {
		return nil, err
	}
	return NewKnownKnowns(entries, logDate), nil
}

func (s *LibraryStore) knownEntriesWhere(cond string, args ...any) ([]*KnownEntry, error) {
	rows, err := s.db.Query(`SELECT id, host, program, match, reason, added, expires,
		source, created_by, token_prefix, finding_id FROM known_knowns WHERE `+cond+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*KnownEntry
	for rows.Next() {
		var (
			id                                   int64
			host, program, match, reason, source string
			added                                string
			expires, createdBy, tokenPrefix      sql.NullString
			findingID                            sql.NullInt64
		)
		if err := rows.Scan(&id, &host, &program, &match, &reason, &added, &expires,
			&source, &createdBy, &tokenPrefix, &findingID); err != nil {
			return nil, err
		}
		addedT, err := parseDay(added)
		if err != nil {
			return nil, fmt.Errorf("known-known %d: bad added date %q", id, added)
		}
		var expiresT *time.Time
		if expires.Valid {
			t, err := parseDay(expires.String)
			if err != nil {
				return nil, fmt.Errorf("known-known %d: bad expires date %q", id, expires.String)
			}
			expiresT = t
		}
		e, err := newKnownEntry(host, reason, match, program, addedT, expiresT)
		if err != nil {
			return nil, fmt.Errorf("known-known %d: %w", id, err)
		}
		e.ID, e.Source, e.CreatedBy, e.TokenPrefix = id, source, createdBy.String, tokenPrefix.String
		if findingID.Valid {
			v := findingID.Int64
			e.FindingID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func dayString(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format("2006-01-02")
}

func parseDay(s string) (*time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(i *int64) any {
	if i == nil {
		return nil
	}
	return *i
}
