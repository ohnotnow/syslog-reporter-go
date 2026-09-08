package web

// The sysadmin API's write endpoints (ait srg-Kj5Q8.6): mute a finding by
// id, and record feedback. Both name the token's user.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const maxReasonRunes = 200

// apiParams reads the request body as JSON (Content-Type application/json)
// or as a form, into a flat string map. Either is fine from curl.
func apiParams(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	limitForm(w, r)
	params := map[string]string{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad JSON body")
			return nil, false
		}
		for k, v := range body {
			if str, ok := v.(string); ok {
				params[k] = str
			} else if v != nil {
				params[k] = fmt.Sprint(v)
			}
		}
		return params, true
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body")
		return nil, false
	}
	for k := range r.PostForm {
		params[k] = r.PostFormValue(k)
	}
	return params, true
}

// cleanReason validates the operator's reason: present, one line, bounded.
func cleanReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", errors.New("reason is required")
	}
	if utf8.RuneCountInString(reason) > maxReasonRunes {
		return "", fmt.Errorf("reason too long (%d character limit)", maxReasonRunes)
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return "", errors.New("reason must be a single line without control characters")
		}
	}
	return reason, nil
}

type muteEntry struct {
	Host    string  `json:"host"`
	Program string  `json:"program"`
	Reason  string  `json:"reason"`
	Added   string  `json:"added"`
	Expires *string `json:"expires"`
}

// POST /api/findings/{id}/mute - reason (required), expires (optional
// YYYY-MM-DD after today). Host and program come from the finding, never
// the client (ant ADR srg-yYpms).
func (s *Server) handleAPIMute(w http.ResponseWriter, r *http.Request) {
	d := s.loadAPIFinding(w, r)
	if d == nil {
		return
	}
	params, ok := apiParams(w, r)
	if !ok {
		return
	}
	reason, err := cleanReason(params["reason"])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var expires *time.Time
	if raw := strings.TrimSpace(params["expires"]); raw != "" {
		day, err := time.Parse("2006-01-02", raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "expires must be a date (YYYY-MM-DD)")
			return
		}
		if !day.After(time.Now().UTC().Truncate(24 * time.Hour)) {
			writeJSONError(w, http.StatusBadRequest, "expires must be after today")
			return
		}
		expires = &day
	}
	user, tok := apiUser(r), apiToken(r)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	stamped := fmt.Sprintf("%s (finding %d, muted by %s via API)", reason, d.ID, user.Username)
	entries, err := reporter.DeriveKnownEntries(d, stamped, today, expires)
	if errors.Is(err, reporter.ErrCannotDeriveProgram) {
		writeJSONError(w, http.StatusUnprocessableEntity,
			"cannot derive a program name for this finding; mute it on the box")
		return
	}
	if errors.Is(err, reporter.ErrCannotDeriveHost) {
		writeJSONError(w, http.StatusUnprocessableEntity,
			"a host on this finding is not a plain hostname; mute it on the box")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	// The cap counts attempts that would write, checked before the write so
	// a refused call costs nothing on disk.
	key := strconv.FormatInt(tok.ID, 10)
	if blocked, wait := s.mutes.blocked(key); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSONError(w, http.StatusTooManyRequests,
			fmt.Sprintf("mute limit reached (%d per token per 24 hours)", s.cfg.MuteLimit))
		return
	}
	written, err := reporter.AppendKnownEntries(s.cfg.KnownsPath, entries)
	if err != nil {
		s.cfg.logWarn("mute of finding %d by %s failed: %v", d.ID, user.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "could not update the known-knowns file")
		return
	}
	if len(written) == 0 {
		writeJSONError(w, http.StatusConflict, "already muted")
		return
	}
	s.mutes.record(key)
	s.cfg.logWarn("finding %d muted by %s: %d new entries in %s", d.ID, user.Username,
		len(written), s.cfg.KnownsPath)
	out := make([]muteEntry, 0, len(written))
	for _, e := range written {
		m := muteEntry{Host: e.Host, Program: e.Program, Reason: e.Reason,
			Added: e.Added.Format("2006-01-02")}
		if e.Expires != nil {
			exp := e.Expires.Format("2006-01-02")
			m.Expires = &exp
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"entries": out})
}

// POST /api/findings/{id}/feedback - verdict (worked | didnt_work), comment.
func (s *Server) handleAPIFeedback(w http.ResponseWriter, r *http.Request) {
	d := s.loadAPIFinding(w, r)
	if d == nil {
		return
	}
	params, ok := apiParams(w, r)
	if !ok {
		return
	}
	comment := strings.TrimSpace(params["comment"])
	if utf8.RuneCountInString(comment) > maxCommentRunes {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("comment too long (%d character limit)", maxCommentRunes))
		return
	}
	user := apiUser(r)
	if err := s.lib.RecordFeedback(d.ID, &user.ID, params["verdict"], comment); err != nil {
		if errors.Is(err, reporter.ErrBadVerdict) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	s.writeAPIFindingDetail(w, d)
}
