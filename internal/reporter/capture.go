package reporter

// CaptureRun persists one report run's findings into the library (ait
// srg-2KY5X.2), so history accumulates from day one, before any UI exists.
// It repeats the render-time issue-to-resolution pairing (verbatim title
// match via ByIssue) and stores each issue merged with its resolution
// rather than as two separate lists; the pairing only exists here and at
// render time, nowhere in the db. Idempotent per day via BeginRun's
// replace semantics.

import "time"

func CaptureRun(lib *LibraryStore, logDate time.Time, model string,
	issues *IssueList, resolutions *ResolutionList, anomalies []*ExplainedAnomaly) error {
	runID, err := lib.BeginRun(logDate, model)
	if err != nil {
		return err
	}
	var byIssue map[string]*Resolution
	if resolutions != nil {
		byIssue = resolutions.ByIssue()
	}
	if issues != nil {
		for _, issue := range issues.Issues {
			payload := IssuePayload{Issue: *issue, Resolution: byIssue[issue.Issue]}
			if _, err := lib.AddFinding(runID, "issue", issue.Severity, issue.Issue,
				issue.AffectedService, issue.AffectedHost, payload); err != nil {
				return err
			}
		}
	}
	for _, a := range anomalies {
		if _, err := lib.AddFinding(runID, a.Kind, "", a.Headline, a.Program,
			[]string{a.Host}, a); err != nil {
			return err
		}
	}
	return nil
}
