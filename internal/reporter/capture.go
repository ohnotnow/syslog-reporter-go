package reporter

// CaptureRun persists one report run's findings into the library (ait
// srg-2KY5X.2), so history accumulates from day one, before any UI exists.
// It repeats the render-time issue-to-resolution pairing (verbatim title
// match via ByIssue) and stores each issue merged with its resolution
// rather than as two separate lists; the pairing only exists here and at
// render time, nowhere in the db. Idempotent per day via beginRun's
// replace semantics. rawLines/filteredLines are the day's ingest funnel
// (srg-YHETx.1), persisted here rather than at report time so the history
// keeps accumulating even if nobody asks for a management report.
//
// The whole capture is ONE transaction (srg-so8ja.2): a failure part-way
// (disk full, bad payload) rolls back to the previous complete run instead
// of destroying it and leaving a partial replacement - which matters
// because runBatch deliberately treats capture failure as non-fatal.

import "time"

// kind is RunKindDaily for the daily pipeline or RunKindDigest for the
// weekly digest (ait srg-xiBoC); replacement is per (date, kind). A
// negative rawLines/filteredLines records NULL (the digest has no funnel).
func CaptureRun(lib *LibraryStore, logDate time.Time, kind, model string,
	rawLines, filteredLines int,
	issues *IssueList, resolutions *ResolutionList, anomalies []*ExplainedAnomaly) (err error) {
	// Ids are only real once the transaction lands. Every failure path,
	// not just a failed Commit, must clear them: an insert that fails
	// part-way has already stamped the earlier objects, and runBatch
	// renders those same objects after logging the capture error, so the
	// report would advertise numbers that do not exist
	// (SECURITY_REVIEW.md SR-07).
	defer func() {
		if err == nil {
			return
		}
		for _, issue := range issuesOf(issues) {
			issue.ID = 0
		}
		for _, a := range anomalies {
			a.ID = 0
		}
	}()
	tx, err := lib.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	runID, err := beginRun(tx, logDate, kind, model)
	if err != nil {
		return err
	}
	if err := setRunStats(tx, runID, rawLines, filteredLines); err != nil {
		return err
	}
	var byIssue map[string]*Resolution
	if resolutions != nil {
		byIssue = resolutions.ByIssue()
	}
	if issues != nil {
		for _, issue := range issues.Issues {
			payload := IssuePayload{Issue: *issue, Resolution: byIssue[issue.Issue]}
			id, err := addFinding(tx, runID, "issue", issue.Severity, issue.Issue,
				issue.AffectedService, issue.AffectedHost, payload)
			if err != nil {
				return err
			}
			issue.ID = id
		}
	}
	for _, a := range anomalies {
		id, err := addFinding(tx, runID, a.Kind, "", a.Headline, a.Program,
			[]string{a.Host}, a)
		if err != nil {
			return err
		}
		a.ID = id
	}
	return tx.Commit()
}

func issuesOf(l *IssueList) []*Issue {
	if l == nil {
		return nil
	}
	return l.Issues
}
