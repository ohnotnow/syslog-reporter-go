package reporter

// Masking secrets in the example lines the emails quote: the detector
// flags a secret written to the log (issue_detection.tmpl), and the email
// that says "rotate this key" should not also carry it. Only the email
// layouts mask; the library, web UI and API keep the raw line so the team
// can find the real entry.

import "regexp"

const secretMask = "<redacted>"

var secretPatterns = []*regexp.Regexp{
	// --key=v, --api-key v, api_key=v, password: v, token=v. The name must
	// END in the secret word, so keyid=19277 and --port are left alone.
	regexp.MustCompile(`(?i)(--[\w-]*(?:key|token|secret|passw(?:or)?d)[= ])[^\s'"]+`),
	regexp.MustCompile(`(?i)(\b[\w-]*(?:key|token|secret|passw(?:or)?d)[=:] ?)[^\s'"&,;]+`),
	// Authorization: Bearer v
	regexp.MustCompile(`(?i)(\b(?:bearer|basic) )[^\s'"]+`),
	// scheme://user:password@host
	regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+(@)`),
}

// MaskSecrets replaces secret-looking values in a log line with <redacted>,
// keeping the names so the reader can see what was exposed.
func MaskSecrets(line string) string {
	for i, re := range secretPatterns {
		repl := "${1}" + secretMask
		if i == len(secretPatterns)-1 {
			repl += "${2}"
		}
		line = re.ReplaceAllString(line, repl)
	}
	return line
}
