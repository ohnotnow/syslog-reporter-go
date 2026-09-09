# syslog-reporter

Turns a noisy, org-wide syslog stream into a short, prioritised morning
email for sysadmins to look over.

Uses a bunch of 'background noise' filters to strip out the routine log
lines, then uses a LLM to explain what is left - and make concrete suggestions
for investigation and fixing them.

Also highlights things like boxes that suddenly become noisy, or conversely boxes that go suspiciously quiet.

The binary also supports a historical library of findings and a web UI to browse them and mark them as good or bad solutions (to support later work on letting agents run 'known good' runbooks)

![The findings library web UI: a filterable table of findings with date, kind, severity, service, hosts and outcome columns](docs/findings-list.png)

## Getting started

New here? [GETTING_STARTED.md](GETTING_STARTED.md) walks from "I have a
pile of syslogs" to the daily email and the findings library, one free
step at a time. For a high-level tour of the process see
[HOW_IT_WORKS.md](HOW_IT_WORKS.md); for a deeper dive see
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

## In a rush?

Grab a binary from the [releases page](https://github.com/ohnotnow/syslog-reporter-go/releases),
or build from source with Go:

```bash
git clone https://github.com/ohnotnow/syslog-reporter-go.git
cd syslog-reporter-go
go build -o syslog-reporter ./cmd/syslog-reporter
```

Then point it at a day of your own syslog. The first run is free: no LLM
calls and no API key.

```bash
./syslog-reporter run /var/log/messages-20260827 --no-llm
```

[GETTING_STARTED.md](GETTING_STARTED.md) takes it from there.

## The findings library

Each run also records what it found. To browse the accumulated findings:

```bash
# a small web UI on http://127.0.0.1:7373
./syslog-reporter serve

# or straight from the terminal
./syslog-reporter findings list --host web-01 --severity high
./syslog-reporter findings show 42
./syslog-reporter findings feedback 42 worked --comment "cache cleared, sorted"
```

By default the web UI listens on localhost only with no login; for a
shared box there is a local-accounts mode (`syslog-reporter user add`)
and optional TLS.

## The sysadmin API

The same `serve` process exposes a small JSON API under `/api/`, for
querying and acting on findings from Claude Code or plain curl.
[API.md](API.md) has the tokens, the `syslog-mute` shell function the
daily email refers to, and the endpoints.

## The management report

Once a few weeks of history have accumulated, `mgmt-report` renders a
summary for management as a self-contained HTML email.

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
