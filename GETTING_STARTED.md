# Getting started

Yesterday's syslog goes in, a short prioritised report comes out. This
guide runs in the order you will actually live it: try it on one day of
your own logs for free, give it a model, tune it to your estate, then
put it on a server as a daily email and live with what it finds.

## 1. Try it

Grab a binary from the
[releases page](https://github.com/ohnotnow/syslog-reporter-go/releases),
or build it if you have the [go compiler](https://go.dev/) installed:

```bash
git clone https://github.com/ohnotnow/syslog-reporter-go.git
cd syslog-reporter-go
go build -o syslog-reporter ./cmd/syslog-reporter
```

Pull a day's logs out - `/var/log/syslog` on Debian, or `/var/log/messages`
on RHEL-alikes:

```bash
# single-digit days are padded: `Aug 28 ` but `Aug  8 `
grep '^Aug 28 ' /var/log/syslog > yesterday.log
```

(If you're fancy and have ELK instead, `tools/elk_dump.py` pulls a day
out of a cluster into a format the tool reads - usage notes at the top
of the script. Files named `*.ndjson` or `*.ndjson.gz` are picked up as
ELK dumps, anything else as raw syslog text.)

Run it:

```bash
./syslog-reporter run yesterday.log --no-llm
```

The digest prints to stdout and the full report lands in
`email_attachment.md`. A `--no-llm` run only does the mechanistic
checks, and two of its three anomaly detectors compare against history
that won't exist yet - so a first report is likely to be a bit scanty.

Example output without the fancy LLM part:

```markdown
# Syslog digest - 29/08/2026

_Issue analysis was skipped (--no-llm run) - only the deterministic anomaly checks ran._

## Unusual activity (top 1)

Hosts behaving unlike their peers or their own recent normal - worth a glance.

### auth01.example.test / sshd

_Louder than its peers_ (unknown)

428 events vs a fleet median of 11.5 across peer hosts.

(no explanation generated)
```

## 2. Give it a model

Put a model and its key in the environment, or a `.env` in the
directory you run it from:

```bash
SYSLOG_DEFAULT_MODEL=openai/gpt-5.6-luna
OPENAI_API_KEY=sk-...
```

The model is named litellm-style, `provider/model`; `anthropic/` models
take `ANTHROPIC_API_KEY`, and `azure/` deployments take
`AZURE_OPENAI_ENDPOINT` plus `AZURE_OPENAI_API_KEY`.
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) has the full environment
reference.

Run the same day again as a full 'agentic' run and feel all superior and
futuristic:

```bash
./syslog-reporter run yesterday.log
```

Example output _with_ the LLM part:

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
# CHANGES STATE: Stop an identified runaway nonessential job before temperatures worsen
ssh example-host 'sudo systemctl stop <identified-runaway-unit>'
# Recheck temperature and utilization after workload reduction
ssh example-host 'uptime; sensors 2>/dev/null; ps -eo pid,pcpu,pmem,cmd --sort=-pcpu | head -15'

_Note: Replace unit placeholders only after identifying the actual runaway unit; take example-host offline or power it down if temperatures remain beyond hardware limits._
```

### Which model?

`eval` runs the detection, deduplication and resolution stages over a
log sample and writes a report fragment with timings and token counts,
so you can compare providers before committing to one:

```sh
for MODEL in openai/gpt-5.6-luna anthropic/claude-sonnet-5; do
  ./syslog-reporter eval --model "${MODEL}" --input yesterday.log
done
```

Leave `--input` off to use the bundled sample of fictional log lines.
The noise filter runs first, so the model only sees what a real run
would send it - a full day through eval costs about the same as a full
day's real run, per model. Each run writes its result to its own
`eval_<model>_<timestamp>.md`, with the model name, time taken, line and
token counts up top (you'll have to check your provider to work out how
that maps to the cost).

The pipeline can also split across two models: a cheap one for the bulk
log scanning (`SYSLOG_LOGSCAN_MODEL`) and a stronger one for the
resolutions and explanations people actually read
(`SYSLOG_ISSUE_MODEL`). `eval --scan-model` and `--issue-model` try a
combination without touching your `.env`; the stage variables win over
`--model`, so set both flags to force a single model when a split is
configured.

## 3. Make it yours

Every estate has its own background noise, and the first few reports
will tell you what yours is. Three tools, in the order you'll reach for
them.

**See what the filter lets through.** `--dump-filtered` prints the
post-filter lines and exits, so you can eyeball exactly what the model
would be sent:

```bash
./syslog-reporter run yesterday.log --dump-filtered | less
```

**Drop your own routine chatter.** `SYSLOG_BLANKET_IGNORE` is a
comma-separated list of substrings appended to the built-in noise filter
at runtime. It is the home for estate-identifying entries (hostnames,
internal IPs) so the filter in the code stays estate-neutral:

```bash
SYSLOG_BLANKET_IGNORE="backup-agent heartbeat,10.20.30."
```

**Ignore things you already know about.** Some oddities are expected,
not wrong: the DHCP server with no pool by design, the lab box with a
raw socket held open for an instrument. Once they have been eye-rolled
at, they should stop appearing in every report. That is what the
known-knowns file is for.

It is a TOML file called `known_knowns.toml` in the working directory
(`/var/lib/syslog-reporter` when you deploy with the helper scripts). Point
somewhere else with `--known-knowns` or `SYSLOG_KNOWN_KNOWNS`. It is
gitignored because it names your real hosts, and a missing file simply
means nothing is suppressed.

```toml
[[known]]
host = "dhcp01.example.test"    # glob: "dhcp01.example.test", "lab*", or "*"
program = "dhcpd"               # glob; drops dhcpd's lines on the host and
                                # mutes its unusual-activity entries
reason = "no pool on this box by design, the leases warning is expected"
added = 2026-09-08

[[known]]
host = "*"
match = "port 1234"             # regex on the message; drops only matching lines
reason = "microscope controller keeps a raw socket open"
added = 2026-09-08
expires = 2027-01-31            # entry lapses after this log-slice date
```

Field by field:

- `host` (required) - a glob matched against the hostname as it appears in
  the log.
- `program` - a glob matched against the syslog program token (`dhcpd` in
  `dhcpd[712]: ...`). Drops every line from that program on the host and
  mutes that host/program pair in the unusual-activity section.
- `match` - a regular expression (Go RE2 syntax) applied to the message
  after the hostname. Drops only the lines it matches.
- `reason` (required) - why, in your words. It is shown in the report
  footer when the entry fires, so write it for a colleague.
- `added` - a date, for your own bookkeeping.
- `expires` - a date after which the entry stops applying. Judged against
  the date of the log slice being processed, not today, so a backfill of
  old days behaves as it would have at the time.

Every entry needs a `reason` and at least one of `program` or `match`. In
one line: host plus program mutes the lot; host plus match mutes specific
lines.

Suppression is never silent. The report footer lists which entries fired
and how many have lapsed. A regex that does not compile fails the run at
startup rather than quietly matching nothing. `--dump-filtered` prints what
survives the filter, which is the quickest way to check an entry does what
you meant.

Once the daily email is going out, each finding in it carries a
`syslog-mute` line that adds a known-knowns entry from your own shell,
without editing the file by hand. The README's "sysadmin API" section
covers that.

## 4. Make it daily

The daily run is a cron job on a server that can reach your logs, your
mail relay and your LLM provider. The whole install is one script, run
as root from a checkout with the binary in it:

```bash
sudo ./scripts/install.sh
```

It does the following, and is safe to re-run:

1. Creates a `syslog-reporter` system user and its state directory,
   `/var/lib/syslog-reporter`, where the `.env`, the SQLite history, the
   dumps and the reports all live.
2. Installs the binary, `elk_dump.py`, `backfill.sh` and `daily-run.sh`
   into `/usr/local/bin`.
3. Drops [scripts/dotenv.example](scripts/dotenv.example) in as the
   `.env` (owned by the service user, mode 600) and opens it in your
   editor. Every line is commented: fill in the model and key, the SMTP
   relay and recipients, and the ELK credentials. An existing `.env` is
   left alone.
4. Writes `/etc/cron.d/syslog-reporter`: `daily-run.sh` at 07:30, retried
   on the half hour until it goes out, logging to `daily-run.log` in the
   state directory. It asks for a `MAILTO` address so cron tells you when
   an attempt fails.
5. Asks whether to run `backfill.sh` now: the last fortnight through
   `--no-llm` (free), so the history-based detectors have something to
   compare against from day one.
6. Asks whether to install the findings web UI as a systemd service
   (section 5).

Each question has a default, so `install.sh </dev/null` runs it
unattended. Everything it does is plain `useradd`, `install` and file
writes; read the script if you would rather do it by hand, and every
path is a variable at the top of each helper (`REPORTER`, `ELK_DUMP`,
`WORK_DIR`, `DUMP_DIR`), so trying one from a checkout looks like:

```bash
REPORTER=./syslog-reporter ELK_DUMP=./tools/elk_dump.py WORK_DIR=. \
  ./scripts/backfill.sh 3
```

How `daily-run.sh` behaves is worth knowing: it fetches yesterday's dump
with `elk_dump.py`, runs the pipeline, emails the report and leaves a
`syslog-<day>.sent` marker in the dumps directory. Every later attempt
that day exits quietly, so a flaky ELK proxy just costs a retry an hour
later, and a non-zero exit means that attempt did not send the report.
Pass a date to re-run a specific day by hand.

**No ELK?** Then there is nothing to fetch, and the wrapper is more than
you need. Slice yesterday's log however suits your estate and cron the
binary directly:

```cron
# in the syslog-reporter user's crontab: yesterday's rotated log, emailed
# at 07:30; the cd is so the .env and database in the state directory are found
30 7 * * * cd /var/lib/syslog-reporter && /usr/local/bin/syslog-reporter run /var/log/syslog.1 \
  --send-email >> /var/lib/syslog-reporter/daily-run.log 2>&1
```

There is no retry this way: a failed attempt is cron mail and a re-run
by hand.

**Behind a proxy?** On a server with no direct internet route, the LLM
calls need the standard proxy variables, and they need to be where the
*binary's* process can see them. `sudo -u` resets the environment and
cron starts with a near-empty one, so a proxy exported in your login
shell silently never arrives. The reliable place is the same `.env`,
which both the binary and `elk_dump.py` load before their first request:

```bash
https_proxy=http://proxy.example.ac.uk:3128
# keep internal traffic direct - without this, elk_dump.py would try
# to reach your ELK cluster THROUGH the proxy too
no_proxy=elk.example.ac.uk
```

Go and Python both honour upper- or lower-case spellings, real
environment variables win over the `.env`, and `no_proxy` takes a
comma-separated list (a bare domain matches its subdomains).

**Azure OpenAI? Size the deployment before the first real run.** The
issue detector sends the filtered log in 1000-line chunks, and a chunk of
syslog is roughly 35K tokens before the model writes a word. Azure
throttles each deployment on tokens per minute (TPM), so a 50K TPM
deployment holds barely one chunk a minute: the second request is
refused with "retry in 30 seconds", the retry lands in the same minute
and is refused again, and the run waits out its eight retries and then
fails. Give the deployment 200K TPM or more (`--sku-capacity 200` on
`az cognitiveservices account deployment create`, which also raises an
existing deployment in place), and leave `SYSLOG_REASONING_EFFORT` at its
default of `low` so reasoning tokens don't eat into the same budget. A
throttled run logs each wait as a WARN line, so `daily-run.log` will tell
you if it is still undersized.

## 5. Live with it

Every run files its findings into the same SQLite file as the history,
so the morning email stops being throwaway.

**The web UI.** `install.sh` offers to install
[scripts/syslog-reporter-web.service](scripts/syslog-reporter-web.service),
which serves the findings library on `127.0.0.1:7373` with local
accounts. It refuses to start until the database exists, so the backfill
or the first daily run comes first. Then add a login:

```bash
cd /var/lib/syslog-reporter
sudo -u syslog-reporter syslog-reporter user add jbloggs jbloggs@example.ac.uk
```

Search and filters over every past finding, and a worked / didn't-work
vote with an optional note on each one, so the team learns which
suggested fixes actually fix things.
[HOW_IT_WORKS.md](HOW_IT_WORKS.md) is a tour with screenshots. For a
shared box on a LAN, `--listen` and the TLS flags are in
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).

**From the terminal.** The same library, no browser:

```bash
cd /var/lib/syslog-reporter
sudo -u syslog-reporter syslog-reporter findings list --host web-01 --severity high
sudo -u syslog-reporter syslog-reporter findings show 42
sudo -u syslog-reporter syslog-reporter findings feedback 42 worked --comment "cache cleared, sorted"
```

**For management.** Once a few weeks of history have accumulated,
`mgmt-report` renders a periodic summary: headline numbers, a daily
volume chart, issues by severity and the team's feedback votes, as a
self-contained HTML email. `--days 7` for a weekly flavour, and
`--send-email` goes to `SYSLOG_MGMT_RECIPIENTS`, a separate list from
the daily digest.

**From your own machine.** The `serve` process also exposes a small JSON
API, so the team can query findings and mute the expected ones from
Claude Code or plain curl without a login to the server. The README's
"sysadmin API" section has the tokens and the `syslog-mute` shell
function.

`--help` on any command lists its flags, and `syslog-reporter
self-update` replaces the binary with the latest release.
