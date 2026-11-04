// Package skills embeds the Claude Code skill folders so the web UI can
// hand out the copy that matches this binary's API (ait srg-xDjoC.6).
// go:embed cannot reach above a package's directory, hence this file here.
package skills

import "embed"

// FS holds syslog-reporter/ and everything under it.
//
//go:embed syslog-reporter
var FS embed.FS
