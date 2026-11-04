package reporter

// The noise review page's store (migration 9, ait epic srg-OymJL): the
// latest day's surviving message shapes, reviewers' verdicts on them, and
// the cached "model's view" of each. Verdicts and model views key on
// program + template so they outlive the daily replacement of the pool.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// NoiseShape is one message template's tally for a day, as the run's
// templating (Template, then accumulate in cmd/syslog-reporter) saw it.
type NoiseShape struct {
	ID                int64 // set by the store; ignored on write
	Day               time.Time
	Program, Template string
	Example           string // one 'program[pid]: message', Template's rest
	ExampleHost       string
	Lines, Hosts      int
}

// Verdict values for RecordNoiseVerdicts' rows.
const (
	NoiseVerdictNoise    = "noise"
	NoiseVerdictNotNoise = "not_noise"
)

// ReplaceNoiseShapes makes shapes THE pool, tagged with day. A day older
// than the pool already stored is a no-op returning false, so a backfill
// or a hand re-run of an old date never replaces newer data; the same or
// a newer day replaces every row in one transaction.
func (s *LibraryStore) ReplaceNoiseShapes(day time.Time, shapes []NoiseShape) (bool, error) {
	d := day.Format("2006-01-02")
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var newest sql.NullString
	if err := tx.QueryRow("SELECT MAX(day) FROM noise_shapes").Scan(&newest); err != nil {
		return false, err
	}
	if newest.Valid && newest.String > d {
		return false, nil
	}
	if _, err := tx.Exec("DELETE FROM noise_shapes"); err != nil {
		return false, err
	}
	for _, sh := range shapes {
		if _, err := tx.Exec(`INSERT INTO noise_shapes
			(day, program, template, example, example_host, lines, hosts) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			d, sh.Program, sh.Template, sh.Example, sh.ExampleHost, sh.Lines, sh.Hosts); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

const noiseShapeColumns = "id, day, program, template, example, example_host, lines, hosts"

func scanNoiseShape(row interface{ Scan(...any) error }) (*NoiseShape, error) {
	var sh NoiseShape
	var day string
	if err := row.Scan(&sh.ID, &day, &sh.Program, &sh.Template, &sh.Example, &sh.ExampleHost, &sh.Lines, &sh.Hosts); err != nil {
		return nil, err
	}
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return nil, fmt.Errorf("noise shape %d: bad day %q: %w", sh.ID, day, err)
	}
	sh.Day = t
	return &sh, nil
}

// SampleNoiseShapes returns up to n shapes from the pool in random order,
// leaving out any shape with a verdict (either kind) at or after
// notBefore and any for which skip (may be nil) returns true. Fewer than n
// come back once the pool is spent. Random order is the one deliberately
// non-deterministic output in the project.
func (s *LibraryStore) SampleNoiseShapes(n int, notBefore time.Time, skip func(NoiseShape) bool) ([]NoiseShape, error) {
	rows, err := s.db.Query(`SELECT `+noiseShapeColumns+` FROM noise_shapes ns
		WHERE NOT EXISTS (SELECT 1 FROM noise_verdicts v
			WHERE v.program = ns.program AND v.template = ns.template AND v.created_at >= ?)
		ORDER BY random()`, rfc3339(notBefore))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NoiseShape
	for rows.Next() && len(out) < n {
		sh, err := scanNoiseShape(rows)
		if err != nil {
			return nil, err
		}
		if skip != nil && skip(*sh) {
			continue
		}
		out = append(out, *sh)
	}
	return out, rows.Err()
}

// NoiseShape loads one pool row by id; a missing id returns sql.ErrNoRows
// (as GetFinding does).
func (s *LibraryStore) NoiseShape(id int64) (*NoiseShape, error) {
	return scanNoiseShape(s.db.QueryRow("SELECT "+noiseShapeColumns+" FROM noise_shapes WHERE id = ?", id))
}

// NoiseShapesDay is the pool's day, or false when the pool is empty.
func (s *LibraryStore) NoiseShapesDay() (time.Time, bool, error) {
	var day sql.NullString
	if err := s.db.QueryRow("SELECT MAX(day) FROM noise_shapes").Scan(&day); err != nil || !day.Valid {
		return time.Time{}, false, err
	}
	t, err := time.Parse("2006-01-02", day.String)
	return t, err == nil, err
}

// RecordNoiseVerdicts writes one verdict row per shape for userID, all
// stamped now, in one transaction.
func (s *LibraryStore) RecordNoiseVerdicts(userID int64, noise, notNoise []NoiseShape, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	at := rfc3339(now)
	for _, group := range []struct {
		verdict string
		shapes  []NoiseShape
	}{{NoiseVerdictNoise, noise}, {NoiseVerdictNotNoise, notNoise}} {
		for _, sh := range group.shapes {
			if _, err := tx.Exec(`INSERT INTO noise_verdicts (program, template, verdict, user_id, created_at)
				VALUES (?, ?, ?, ?, ?)`, sh.Program, sh.Template, group.verdict, userID, at); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// NoiseModelView is the cached "model's view" of one shape. Score is nil
// when it was not scored or the model refused (Refused says which).
type NoiseModelView struct {
	Score        *float64
	ScoreModel   string
	Refused      bool
	Explanation  string
	ExplainModel string
	CreatedAt    time.Time
}

// NoiseModelView returns the cached view of a shape, or nil when there is
// none.
func (s *LibraryStore) NoiseModelView(program, template string) (*NoiseModelView, error) {
	var v NoiseModelView
	var score sql.NullFloat64
	var scoreModel, explanation, explainModel sql.NullString
	var created string
	err := s.db.QueryRow(`SELECT score, score_model, refused, explanation, explain_model, created_at
		FROM noise_model_views WHERE program = ? AND template = ?`, program, template).
		Scan(&score, &scoreModel, &v.Refused, &explanation, &explainModel, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if score.Valid {
		v.Score = &score.Float64
	}
	v.ScoreModel, v.Explanation, v.ExplainModel = scoreModel.String, explanation.String, explainModel.String
	if v.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return nil, fmt.Errorf("noise model view: bad created_at %q: %w", created, err)
	}
	return &v, nil
}

// SaveNoiseModelView stores (or replaces) a shape's view; CreatedAt is
// stamped by the store.
func (s *LibraryStore) SaveNoiseModelView(program, template string, v NoiseModelView) error {
	var score any
	if v.Score != nil {
		score = *v.Score
	}
	_, err := s.db.Exec(`INSERT INTO noise_model_views
		(program, template, score, score_model, refused, explanation, explain_model, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (program, template) DO UPDATE SET score = excluded.score,
			score_model = excluded.score_model, refused = excluded.refused,
			explanation = excluded.explanation, explain_model = excluded.explain_model,
			created_at = excluded.created_at`,
		program, template, score, nullString(v.ScoreModel), v.Refused,
		nullString(v.Explanation), nullString(v.ExplainModel), rfc3339(time.Now()))
	return err
}

func rfc3339(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}
