# syslog-reporter

Turns a noisy, org-wide syslog stream into a short, prioritised morning
email for sysadmins to look over.

Uses a bunch of 'background' noise filters to strip out the routine log
lines, then uses a LLM to explain what is left - and make concrete suggestions
for investigation and fixing them.

Also highlights things like boxes that suddenly become noisy, or conversely boxes
that go suspiciously quiet.

New here? [GETTING_STARTED.md](GETTING_STARTED.md) walks from "I have a
pile of syslog" to the daily email and the findings library, one free
step at a time. For a high-level tour of the process see
[HOW_IT_WORKS.md](HOW_IT_WORKS.md); for a deeper dive see
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

The binary also supports a historical library of findings and a web UI to browse them and mark them as good or bad solutions (to support later work on letting agents run 'known good' runbooks)

![The findings library web UI: a filterable table of findings with date, kind, severity, service, hosts and outcome columns](docs/findings-list.png)

## What it does

- Filters a day of raw syslog text (or an ELK NDJSON dump) down to the
  lines that are unusual.
- Sends what is left to the LLM of your choice, which writes up genuine
  issues with severity, likely cause, and copy-pasteable investigate and
  fix commands. Any command that changes state is flagged
  `# CHANGES STATE:`.
- Compares every host and program against its fleet peers, its own recent
  history, and its own habits at that time of day, then has the LLM
  explain the strongest anomalies.
- Renders a short email digest plus a longer full report, and
  optionally sends them over as an email.
- Files every run's findings into a local SQLite library, browsable
  through a built-in web UI or from the terminal, with a
  worked / didn't-work vote on each finding so the team learns which
  suggested fixes actually fix things.

## Getting started

Grab a binary from the [releases page](https://github.com/ohnotnow/syslog-reporter-go/releases),
or build from source with Go:

```bash
git clone https://github.com/ohnotnow/syslog-reporter-go.git
cd syslog-reporter-go
go build -o syslog-reporter ./cmd/syslog-reporter
```

Then point it at a day of your own syslog. The first run is free: it
only does the deterministic filtering and anomaly checks, with no LLM
calls and no API key.

```bash
./syslog-reporter run /var/log/messages-20260827 --no-llm
```

[GETTING_STARTED.md](GETTING_STARTED.md) takes it from there: giving
it a model, choosing one with `eval`, tuning the noise filter to your
estate, and the server install that turns it into a daily email.
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) is the full flag and
environment-variable reference.

## The findings library

Each batch run also records what it found (issues merged with their
suggested fixes, plus the explained anomalies) in the same SQLite file
as the history, so the morning report stops being throwaway. The
database uses SQLite's WAL mode, so a plain `cp` of a live file can
silently miss the most recent writes - back it up with
`sqlite3 syslog_aggregates.db ".backup backup.db"`, or copy it while
nothing is running. To browse the accumulated findings:

```bash
# a small web UI on http://127.0.0.1:7373
./syslog-reporter serve

# or straight from the terminal
./syslog-reporter findings list --host web-01 --severity high
./syslog-reporter findings show 42
./syslog-reporter findings feedback 42 worked --comment "cache cleared, sorted"
```

The web UI is the same single binary with no extra services: search and
filters over every past finding, and a worked / didn't-work vote (with
an optional note) on each one. By default it listens on localhost only
with no login; for a shared box there is a local-accounts mode
(`syslog-reporter user add`) and optional TLS. See
[HOW_IT_WORKS.md](HOW_IT_WORKS.md) for a tour with screenshots and
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) for the full reference.

## The sysadmin API

The same `serve` process exposes a small JSON API under `/api/`, so the
team can query and act on findings from Claude Code (or plain curl)
without installing anything on their own machines. Reads: findings with
the same filters as the CLI, one finding in full, the daily runs, and
per-day line counts for trend questions. Writes: record feedback, and
mute a finding by its number. A mute takes only a reason; the server
works out the host and program from the finding and appends the entry to
the known-knowns file, so nobody sends a regex over the network.

Every call needs a personal bearer token, whatever `--auth` the web UI
runs with. An admin mints them on the server:

```bash
./syslog-reporter token create jbloggs --expires 2027-01-31   # prints the token once
./syslog-reporter token list                                   # who has one, last used, expiry
./syslog-reporter token revoke 5210c8e0                        # by the 8-character prefix
```

Each person then sets two environment variables and can check them with:

```bash
export SYSLOG_API_URL=http://reports.example.test:7373
export SYSLOG_API_TOKEN=...
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/me"
```

The daily email prints a `syslog-mute 1234 "reason"` line under each
finding. That is a shell function, not a command in the binary; paste
one of these into your shell profile:

```bash
# bash / zsh (~/.bashrc or ~/.zshrc)
syslog-mute() {
  if [ -z "$SYSLOG_API_URL" ] || [ -z "$SYSLOG_API_TOKEN" ]; then
    echo "syslog-mute: set SYSLOG_API_URL and SYSLOG_API_TOKEN first (see README, The sysadmin API)" >&2
    return 2
  fi
  case "$1" in
    ''|*[!0-9]*) echo "usage: syslog-mute <finding-id> \"reason\"" >&2; return 2 ;;
  esac
  if [ -z "$2" ]; then
    echo "syslog-mute: a reason is required, e.g. syslog-mute $1 \"dhcpd has no pool on this box\"" >&2
    return 2
  fi
  curl -sS -X POST -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
    --data-urlencode "reason=$2" \
    "$SYSLOG_API_URL/api/findings/$1/mute"
  echo
}
```

```powershell
# PowerShell ($PROFILE)
function syslog-mute($id, $reason) {
  if (-not $env:SYSLOG_API_URL -or -not $env:SYSLOG_API_TOKEN) {
    Write-Error "syslog-mute: set SYSLOG_API_URL and SYSLOG_API_TOKEN first (see README, The sysadmin API)"
    return
  }
  if ($id -notmatch '^[0-9]+$') {
    Write-Error 'usage: syslog-mute <finding-id> "reason"'
    return
  }
  if (-not $reason) {
    Write-Error "syslog-mute: a reason is required, e.g. syslog-mute $id `"dhcpd has no pool on this box`""
    return
  }
  Invoke-RestMethod -Method Post -Uri "$env:SYSLOG_API_URL/api/findings/$id/mute" `
    -Headers @{ Authorization = "Bearer $env:SYSLOG_API_TOKEN" } `
    -Body @{ reason = $reason } -SkipHttpErrorCheck
}
```

Mutes made this way record who made them and which finding they came
from, and each token gets twenty a day (`SYSLOG_API_MUTE_LIMIT`).

For Claude Code, copy [skills/syslog-reporter](skills/syslog-reporter)
into `~/.claude/skills/` and ask in plain words: "what did the syslog
report find today?", "look at finding 1234", "mute the dhcp one on
dhcp01, it has no pool by design". The skill carries the endpoint list,
the JSON shapes and the etiquette (read a finding before muting it,
always confirm, never invent a reason). The full endpoint reference is in
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

## The management report

Once a few weeks of history have accumulated, the same binary can render
a periodic summary for management: headline numbers,
a daily volume chart, issues by severity and the team's feedback votes,
as a self-contained HTML email.

```bash
# writes mgmt_report.html covering the last 30 days
./syslog-reporter mgmt-report

# a weekly flavour, emailed to the management list
SYSLOG_MGMT_RECIPIENTS=manager@example.ac.uk ./syslog-reporter mgmt-report --days 7 --send-email
```

## Example of an issue

```markdown
## 1. Sustained CPU overheating and saturation

**Severity:** critical · **Affected:** example-host · **OS:** Rocky Linux 9

example-host repeatedly reaches near-total CPU utilization while package and core temperatures exceed thresholds and clock throttling occurs, indicating a persistent thermal and workload problem.

**Likely cause:** example-host has a persistent CPU workload combined with inadequate cooling or thermal/hypervisor contention, causing throttling and unsafe temperatures.

**Have a look:**

# Identify CPU consumers, temperatures, frequencies, throttling, and hardware errors on example-host
ssh example-host 'uptime; ps -eo pid,ppid,user,pcpu,pmem,etime,cmd --sort=-pcpu | head -30; vmstat 1 5; sensors 2>/dev/null; for f in /sys/class/thermal/thermal_zone*/temp; do echo "$f $(cat "$f")"; done; grep -iE "thermal|thrott|mce|hardware error" /var/log/messages /var/log/kern.log 2>/dev/null | tail -100'

**Try:**

# Check scheduled jobs and PCP alarm context
ssh example-host 'sudo systemctl list-timers --all; sudo crontab -l -u root; sudo journalctl -u pcp-pmie --since today --no-pager -n 100'
# Check CPU frequency, thermal zones, and virtualization metadata
ssh example-host 'lscpu; cpupower monitor 2>/dev/null | head -80; systemd-detect-virt; sudo ipmitool sdr elist 2>/dev/null | grep -Ei "temp|fan|power" || true'
# CHANGES STATE: Stop an identified runaway nonessential job before temperatures worsen
ssh example-host 'sudo systemctl stop <identified-runaway-unit>'
# CHANGES STATE: Move or disable the offending scheduled job after confirming ownership
ssh example-host 'sudo systemctl disable --now <identified-runaway-unit>'
# Recheck temperature and utilization after workload reduction
ssh example-host 'uptime; sensors 2>/dev/null; ps -eo pid,pcpu,pmem,cmd --sort=-pcpu | head -15'

_Note: Replace unit placeholders only after identifying the actual runaway unit; take example-host offline or power it down if temperatures remain beyond hardware limits._
```

The same write-ups land in the findings library, where each one can
later be marked as having fixed the problem or not:

![A finding's detail page in the web UI: the issue write-up with severity, impact, an example log entry, and suggested investigate and fix commands](docs/finding-detail.png)

## Contributing

Clone the repo, `go build`, `go test ./...`, and send a pull request.
Test fixtures use fictional hostnames only; please keep real estate
names out of code, tests and commits.

## Licence

Copyright (C) 2026 ohnotnow

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version. See [LICENSE](LICENSE) for the full text.
