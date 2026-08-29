package main

// Per-command --help text (ait srg-prklV). Where a command's real interface
// is environment variables, the help names them; the full reference stays in
// TECHNICAL_OVERVIEW.md. Keep each command's output around a screenful.

import (
	"flag"
	"fmt"
)

const runHelpIntro = `Run the daily batch pipeline over one day of syslog and write the report.
usage: syslog-reporter run <logfile> [flags]
       (omit the logfile or pass -- to read raw text from stdin)
flags:
`

const runHelpEnv = `environment (full reference in TECHNICAL_OVERVIEW.md):
  model:  SYSLOG_DEFAULT_MODEL, SYSLOG_REASONING_EFFORT, SYSLOG_REDACT,
          OPENAI_API_KEY / ANTHROPIC_API_KEY / AZURE_OPENAI_ENDPOINT + _API_KEY
  store:  SYSLOG_DB_PATH, SYSLOG_DB_KEEP_DAYS, SYSLOG_KNOWN_KNOWNS, SYSLOG_BLANKET_IGNORE
  email:  SYSLOG_SMTP_SERVER, SYSLOG_SMTP_SENDER, SYSLOG_SMTP_RECIPIENTS
`

const serveHelpIntro = `Serve the findings library web UI from the shared SQLite file.
usage: syslog-reporter serve [--debug]
flags:
`

const serveHelpEnv = `configuration is environment-only:
  SYSLOG_WEB_LISTEN          host:port to bind (default 127.0.0.1:7373)
  SYSLOG_AUTH_MODE           none (default), local, or oidc (not built yet)
  SYSLOG_WEB_TLS_CERT/_KEY   certificate pair; set both to serve HTTPS
                             (the pair hot-reloads, no restart on renewal)
  SYSLOG_WEB_SECURE_COOKIES  set to 1 behind a TLS-terminating reverse proxy
  SYSLOG_DB_PATH             SQLite file to serve (default syslog_aggregates.db)
`

const mgmtHelpIntro = `Render the management summary (HTML file plus plain text on stdout).
usage: syslog-reporter mgmt-report [flags]
flags:
`

const mgmtHelpEnv = `environment:
  SYSLOG_MGMT_RECIPIENTS               recipients for --send-email (required
                                       with it; separate list from the daily
                                       digest, no fallback between them)
  SYSLOG_SMTP_SERVER, SYSLOG_SMTP_SENDER  the SMTP relay and From address
  SYSLOG_DB_PATH                       SQLite file to read (--db overrides)
`

const userHelp = `Manage local-auth accounts for serve mode (SYSLOG_AUTH_MODE=local).
usage: syslog-reporter user add <username> <email> [--password-stdin] [--db <path>]
The password is prompted for twice without echo, or read from stdin with
--password-stdin for scripted use. It is never accepted as an argument.
`

// setUsage wires a FlagSet's --help output: intro, the flag list, then the
// env block for commands whose real interface is environment variables.
func setUsage(fs *flag.FlagSet, intro, env string) {
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), intro)
		fs.PrintDefaults()
		if env != "" {
			fmt.Fprint(fs.Output(), env)
		}
	}
}
