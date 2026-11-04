package web

// The noise review page's "Model's view" (ait srg-OymJL.4): opened on
// demand per shape, fetched once and cached on noise_model_views. The
// score is the attention question discover asks (Decisions when
// configured, else Jev); the explanation is a short note from the issue
// model. Both are opinion beside an attacker-influenced line, so the page
// always shows the raw example and labels them as such. Needs a login,
// like Save: it spends money and sends the line out. Not under the daily
// prompt-token budget and not recorded in llm_spend (that ledger is one
// row a day that run reads at startup); the cache bounds it to one set of
// calls per shape.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/jev"
	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// modelViewTimeout bounds one reveal; the SDKs' patient retry budget is
// for batch runs, not someone waiting on a page.
const modelViewTimeout = 90 * time.Second

// scoreModel is the scorer the model view would use, or "" when none is
// configured with credentials.
func (s *Server) scoreModel() string {
	if s.cfg.DecisionsModel != "" {
		if llm.CheckDecisionsModel(s.cfg.DecisionsModel) != nil {
			return ""
		}
		return s.cfg.DecisionsModel
	}
	if jev.CheckCredentials() != nil {
		return ""
	}
	return "jev/" + jev.Model()
}

// explainModel is the explanation model, or "" without its credentials.
func (s *Server) explainModel() string {
	if s.cfg.ExplainModel == "" || llm.CheckCredentials(s.cfg.ExplainModel) != nil {
		return ""
	}
	return s.cfg.ExplainModel
}

// modelViewAvailable decides, at page render time, whether rows get a
// "Model's view" at all.
func (s *Server) modelViewAvailable() bool {
	return s.scoreModel() != "" || s.explainModel() != ""
}

type modelViewData struct {
	Message string // replaces everything else when set
	reporter.NoiseModelView
	Percent                    string
	ScoreFailed, ExplainFailed bool
}

func (s *Server) handleNoiseModelView(w http.ResponseWriter, r *http.Request) {
	if s.auth.CurrentUser(r) == nil {
		http.Error(w, "Log in to see the model's view.", http.StatusForbidden)
		return
	}
	// htmx does not swap error responses by default, so the cases a
	// person should read come back as 200 fragments.
	frag := func(d modelViewData) {
		renderBlock(w, "noise.html", "model-view", pageData{Version: s.cfg.Version, Data: d})
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		frag(modelViewData{Message: "That shape is no longer in the pool."})
		return
	}
	sh, err := s.lib.NoiseShape(id)
	if errors.Is(err, sql.ErrNoRows) {
		frag(modelViewData{Message: "That shape is no longer in the pool."})
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	cached, err := s.lib.NoiseModelView(sh.Program, sh.Template)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if cached != nil {
		frag(withPercent(modelViewData{NoiseModelView: *cached}))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelViewTimeout)
	defer cancel()
	d := s.fetchModelView(ctx, *sh)
	// Cache only a complete answer, so a part that failed is retried on
	// the next open rather than missing for good.
	if !d.ScoreFailed && !d.ExplainFailed {
		if err := s.lib.SaveNoiseModelView(sh.Program, sh.Template, d.NoiseModelView); err != nil {
			s.warn("noise model view: caching shape %d: %v", sh.ID, err)
		}
	}
	frag(withPercent(d))
}

// fetchModelView makes the calls. Errors are logged, never shown: they
// can carry the provider's URL (the Azure resource name).
func (s *Server) fetchModelView(ctx context.Context, sh reporter.NoiseShape) modelViewData {
	var d modelViewData
	if m := s.scoreModel(); m != "" {
		decisions := ""
		if s.cfg.DecisionsModel != "" {
			decisions = m
		}
		score, _, err := reporter.ScoreAttention(ctx, decisions, reporter.AttentionShape{
			Program: sh.Program, Template: sh.Template, Lines: sh.Lines, Hosts: sh.Hosts, Days: 1})
		d.ScoreModel = m
		switch {
		case errors.Is(err, llm.ErrRefused):
			d.Refused = true
		case err != nil:
			d.ScoreFailed = true
			s.warn("noise model view: scoring shape %d with %s: %v", sh.ID, m, err)
		default:
			d.Score = &score
		}
	}
	if m := s.explainModel(); m != "" {
		text, err := reporter.ExplainNoiseShape(ctx, m, sh)
		if err != nil {
			d.ExplainFailed = true
			s.warn("noise model view: explaining shape %d with %s: %v", sh.ID, m, err)
		} else {
			d.Explanation, d.ExplainModel = text, m
		}
	}
	return d
}

// withPercent words the score: it is P(needs attention), not P(noise).
func withPercent(d modelViewData) modelViewData {
	if d.Score == nil {
		return d
	}
	switch p := math.Round(*d.Score * 100); {
	case p < 1 && *d.Score > 0:
		d.Percent = "under 1%"
	default:
		d.Percent = fmt.Sprintf("%.0f%%", p)
	}
	return d
}

func (s *Server) warn(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Warn(format, args...)
	}
}
