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
  model:  SYSLOG_DEFAULT_MODEL, SYSLOG_LOGSCAN_MODEL, SYSLOG_ISSUE_MODEL,
          SYSLOG_REASONING_EFFORT, SYSLOG_REDACT, SYSLOG_CONTEXT_LINES,
          OPENAI_API_KEY / ANTHROPIC_API_KEY / AZURE_OPENAI_ENDPOINT + _API_KEY
  store:  SYSLOG_DB_PATH (aggregates, findings, known-knowns), SYSLOG_DB_KEEP_DAYS,
          SYSLOG_BLANKET_IGNORE
  email:  SYSLOG_SMTP_SERVER, SYSLOG_SMTP_SENDER, SYSLOG_SMTP_RECIPIENTS
`

const serveHelpIntro = `Serve the findings library web UI from the shared SQLite file.
usage: syslog-reporter serve [flags]
flags (each defaults from its environment variable; the flag wins):
`

const serveHelpEnv = `environment fallbacks, for systemd units and the like:
  SYSLOG_WEB_LISTEN          --listen   (default 127.0.0.1:7373)
  SYSLOG_AUTH_MODE           --auth     (default none)
  SYSLOG_WEB_TLS_CERT/_KEY   --tls-cert / --tls-key; set both to serve HTTPS
                             (the pair hot-reloads, no restart on renewal)
  SYSLOG_WEB_SECURE_COOKIES  --secure-cookies (1/true/yes/on)
  SYSLOG_DB_PATH             --db       (default syslog_aggregates.db)
  SYSLOG_API_MUTE_LIMIT      mutes allowed per API token per 24 hours
                             (default 20, no flag)
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

const digestHelpIntro = `Email the weekly digest: the findings that kept recurring across the
window's daily runs, ranked by how many days they were seen, with fresh
resolutions from the digest model. Reads the library only - no dump, no
stored state; a missed week is recovered with a bigger --days.
usage: syslog-reporter digest [flags]
flags:
`

const digestHelpEnv = `environment:
  SYSLOG_DIGEST_MODEL                  the digest's model (then SYSLOG_ISSUE_MODEL,
                                       then --model / SYSLOG_DEFAULT_MODEL)
  SYSLOG_REASONING_EFFORT, SYSLOG_REDACT  as for run
  OPENAI_API_KEY / ANTHROPIC_API_KEY / AZURE_OPENAI_ENDPOINT + _API_KEY
  SYSLOG_SMTP_SERVER, SYSLOG_SMTP_SENDER, SYSLOG_SMTP_RECIPIENTS  as for run
  SYSLOG_DB_PATH                       SQLite file to read (--db overrides)
`

const userHelp = `Manage local-auth accounts for serve mode (auth mode local).

usage: syslog-reporter user <add|list|passwd|remove> [flags]

  add <username> <email>   create an account; --password-stdin for scripts
  list                     every account
  passwd <username>        change a password; --password-stdin for scripts
  remove <username>        delete an account (its votes become anonymous)

Passwords are prompted for twice without echo, or read from stdin with
--password-stdin; they are never accepted as an argument.

The store must already exist (a report run creates it); --db and
SYSLOG_DB_PATH name it as in the other commands.
`

const tokenHelp = `Manage bearer tokens for the sysadmin API served by serve mode.

usage: syslog-reporter token <create|list|revoke> [flags]

  create <username>   mint a token for an existing user ('user add');
                      optional --expires YYYY-MM-DD
  list                each token's 8-character prefix, owner, last use
                      and expiry
  revoke <prefix>     stop a token by that prefix

create prints the new token once, alone on stdout, and never again; the
store keeps only a hash. Several live tokens per user are fine: one per
machine means a leak costs one token, not the person.

The store must already exist (a report run creates it); --db and
SYSLOG_DB_PATH name it as in the other commands.
`

const knownsHelp = `Manage known-knowns: estate oddities the daily run suppresses.

usage: syslog-reporter knowns <list|add|remove|import> [flags]

  list                  what is muted; --all includes lapsed entries
  add                   a free-form entry: --host GLOB, then --program GLOB
                        and/or --match REGEX, --reason TEXT, and an optional
                        --expires YYYY-MM-DD
  remove <id>           delete one entry by the id list shows
  import <file.toml>    read the pre-database known_knowns.toml once and add
                        every [[known]] entry (leaves the file alone; does
                        not dedupe, so import a file once)

Host plus program mutes the lot: that program's lines on the host, and
its anomalies. Host plus match drops only the lines the regex matches.
Both together mute the anomaly and drop only matching lines. A bad regex
is refused here, not on the next run.

Mutes from a finding are made through the sysadmin API (API.md); this
command is for the box. The store must already exist (a report run
creates it); --db and SYSLOG_DB_PATH name it as in the other commands.
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
