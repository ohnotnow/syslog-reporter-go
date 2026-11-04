package web

// The noise review page (ait srg-OymJL.3): ten random message shapes from
// the latest run's surviving lines; tick the noise and save. Ticked
// shapes become host * mutes (source web, created_by the user); the rest
// are recorded as "not noise" and stay out of the draw for
// noiseVerdictDays. Saving needs a login: a mute silences lines across
// the estate, and the API already demands a token for that.

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const (
	noiseSampleSize  = 10
	noiseVerdictDays = 30
)

type noiseView struct {
	Day       string // the pool's slice date; "" when there is no pool
	Empty     bool   // no pool at all (the daily run has not filled it)
	Rows      []reporter.NoiseShape
	CanSave   bool
	Status    string   // after a save: what happened
	Errors    []string // shapes that could not be muted
	AutoFocus bool     // after an htmx save, focus the first fresh row
	ModelView bool     // rows get a "Model's view" reveal (logged in, and a model configured)
}

// noiseSample draws a fresh set, leaving out shapes a current mute
// already drops (the pool is as old as the morning run; mutes made since
// would otherwise reappear) and shapes judged in the last
// noiseVerdictDays.
func (s *Server) noiseSample(now time.Time) (noiseView, error) {
	day, ok, err := s.lib.NoiseShapesDay()
	if err != nil || !ok {
		return noiseView{Empty: true}, err
	}
	knowns, err := s.lib.LoadKnownKnowns(now)
	if err != nil {
		return noiseView{}, err
	}
	rows, err := s.lib.SampleNoiseShapes(noiseSampleSize, now.AddDate(0, 0, -noiseVerdictDays),
		func(sh reporter.NoiseShape) bool {
			return knowns.LineIgnored(sh.ExampleHost, sh.Program, sh.Example)
		})
	if err != nil {
		return noiseView{}, err
	}
	return noiseView{Day: day.Format("2006-01-02"), Rows: rows}, nil
}

func (s *Server) handleNoise(w http.ResponseWriter, r *http.Request) {
	view, err := s.noiseSample(time.Now())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	user := s.auth.CurrentUser(r)
	view.CanSave = user != nil
	view.ModelView = user != nil && s.modelViewAvailable()
	render(w, "noise.html", pageData{Version: s.cfg.Version, Path: r.URL.Path, User: user, Data: view})
}

func (s *Server) handleNoiseSave(w http.ResponseWriter, r *http.Request) {
	user := s.auth.CurrentUser(r)
	if user == nil {
		http.Error(w, "Saving needs a login: run serve with --auth local.", http.StatusForbidden)
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ticked := map[int64]bool{}
	for _, v := range r.PostForm["noise"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ticked[id] = true
		}
	}
	now := time.Now()
	var mute, keep []reporter.NoiseShape
	var inputs []reporter.KnownEntryInput
	var problems []string
	seen := map[int64]bool{}
	for _, v := range r.PostForm["shown"] {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		sh, err := s.lib.NoiseShape(id)
		if errors.Is(err, sql.ErrNoRows) {
			continue // the pool was replaced since the page was drawn
		}
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if !ticked[id] {
			keep = append(keep, *sh)
			continue
		}
		match, err := reporter.ShapeMatch(sh.Program, sh.Template, sh.Example)
		if err != nil {
			// No verdict either: an unmuted shape must not vanish for a month.
			problems = append(problems, fmt.Sprintf("Could not mute %s %q: %v", sh.Program, sh.Template, err))
			continue
		}
		mute = append(mute, *sh)
		inputs = append(inputs, reporter.KnownEntryInput{
			Host: "*", Match: match, Added: now, Source: reporter.KnownSourceWeb, CreatedBy: user.Username,
			Reason: fmt.Sprintf("web review: %d lines on %d hosts on %s", sh.Lines, sh.Hosts, sh.Day.Format("2006-01-02")),
		})
	}
	if len(inputs) > 0 {
		if _, err := s.lib.AddKnownEntries(inputs); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	if err := s.lib.RecordNoiseVerdicts(user.ID, mute, keep, now); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "" {
		http.Redirect(w, r, "/noise", http.StatusSeeOther)
		return
	}
	view, err := s.noiseSample(now)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	view.CanSave, view.Errors, view.AutoFocus = true, problems, true
	view.ModelView = s.modelViewAvailable()
	view.Status = fmt.Sprintf("Muted %d, kept %d.", len(mute), len(keep))
	renderBlock(w, "noise.html", "noise-partial", pageData{Version: s.cfg.Version, Path: "/noise", User: user, Data: view})
}
