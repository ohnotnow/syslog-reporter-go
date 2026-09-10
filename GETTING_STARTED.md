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
of the script.)

Run it:

```bash
./syslog-reporter run yesterday.log --no-llm
```

The digest prints to stdout and the full report lands in
`email_attachment.md`. Two of the three anomaly detectors compare
against history that won't exist yet - so a first report is likely to
be a bit scanty.

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

That file holds a key, so `chmod 600 .env` and keep it owned by whoever
runs the tool. The model is named litellm-style, `provider/model`;
`anthropic/` models take `ANTHROPIC_API_KEY`, and `azure/` deployments
take `AZURE_OPENAI_ENDPOINT` plus `AZURE_OPENAI_API_KEY`. Reasoning
effort defaults to `low`, which suits a batch run
(`SYSLOG_REASONING_EFFORT` takes `low`, `medium`, `high`, `xhigh`,
`max`). [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) has the full
environment reference.

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
log sample and writes a report fragment with timings and token counts:

```sh
for MODEL in openai/gpt-5.6-luna anthropic/claude-sonnet-5; do
  ./syslog-reporter eval --model "${MODEL}" --input yesterday.log
done
```

Leave `--input` off to use the bundled sample of fictional log lines.
A full day through eval costs about the same as a full day's real run,
per model. Each run writes its result to its own
`eval_<model>_<timestamp>.md` (you'll have to check your provider to
work out how the token counts map to the cost).

The pipeline can also split across two models: a cheap one for the bulk
log scanning (`SYSLOG_LOGSCAN_MODEL`) and a stronger one for the
resolutions and explanations people actually read
(`SYSLOG_ISSUE_MODEL`). `eval --scan-model` and `--issue-model` try a
combination without touching your `.env`; the stage variables win over
`--model`, so set both flags to force a single model when a split is
configured. The weekly digest has its own variable, `SYSLOG_DIGEST_MODEL`
(section 4), so the daily runs can stay cheap while the one email people
read gets the strongest model.

## 3. Make it yours

Every estate has its own background noise, and the first few reports
will tell you what yours is. Three tools, in the order you'll reach for
them.

**See what the filter lets through.** `--dump-filtered` prints the
post-filter lines and exits:

```bash
./syslog-reporter run yesterday.log --dump-filtered | less
```

**Drop your own routine chatter.** `SYSLOG_BLANKET_IGNORE` is a
comma-separated list of substrings appended to the built-in noise
filter. It is the home for estate-identifying entries (hostnames,
internal IPs):

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
somewhere else with `--known-knowns` or `SYSLOG_KNOWN_KNOWNS`.

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
  footer when the entry fires.
- `added` - a date, for your own bookkeeping.
- `expires` - a date after which the entry stops applying. Judged against
  the date of the log slice being processed, not today.

Every entry needs a `reason` and at least one of `program` or `match`.

The report footer lists which entries fired and how many have lapsed. A
regex that does not compile fails the run at startup.

Once the daily email is going out, each finding in it carries a
`syslog-mute` line that adds a known-knowns entry from your own shell.
[API.md](API.md) covers that.

## 4. Make it daily

The daily run is a cron job on a server that can reach your logs, your
mail relay and your LLM provider. The whole install is one script, run
as root from a checkout:

```bash
sudo ./scripts/install.sh
```

It does the following:

1. Finds the binary: one already in the checkout (built, or a
   downloaded `syslog-reporter-linux-<arch>`), else the latest GitHub
   release, downloaded and checked against its `SHA256SUMS`, else
   `go build` if the compiler is installed. The download and the build
   each ask first, and with none of the three it stops here.
2. Creates a `syslog-reporter` system user and its state directory,
   `/var/lib/syslog-reporter`, where the `.env`, the database, the
   dumps and the reports all live.
3. Installs the binary, `elk_dump.py`, `backfill.sh` and `daily-run.sh`
   into `/usr/local/bin`.
4. Drops [scripts/dotenv.example](scripts/dotenv.example) in as the
   `.env` and opens it in your editor: fill in the model and key, the
   SMTP relay and recipients, and the ELK credentials. An existing
   `.env` is left alone.
5. Writes `/etc/cron.d/syslog-reporter`: `daily-run.sh --no-email` at
   07:30 every day, retried on the half hour, and `daily-run.sh --digest`
   on Mondays, logging to `daily-run.log` in the state directory. It asks
   for a `MAILTO` address.
6. Asks whether to run `backfill.sh` now: the last fortnight through
   `--no-llm` (free).
7. Asks whether to install the findings web UI as a systemd service
   (section 5).

Each question has a default, so `install.sh </dev/null` runs it
unattended. Read the script if you would rather do it by hand; every
path is a variable at the top of each helper (`REPORTER`, `ELK_DUMP`,
`WORK_DIR`, `DUMP_DIR`), so trying one from a checkout looks like:

```bash
REPORTER=./syslog-reporter ELK_DUMP=./tools/elk_dump.py WORK_DIR=. \
  ./scripts/backfill.sh 3
```

`daily-run.sh` fetches yesterday's dump with `elk_dump.py`, runs the
pipeline and leaves a `syslog-<day>.sent` marker in the dumps directory;
every later attempt that day exits quietly. A non-zero exit means that
attempt did not finish. Pass a date to re-run a specific day by hand.

**One email a week, not seven.** The crontab `install.sh` writes is the
weekly shape: every day runs and files its findings without emailing
anyone (`--no-email`), and on Monday the run is followed by the weekly
digest (`--digest`), which replaces that day's report:

```cron
30 7-17 * * 0,2-6 syslog-reporter /usr/local/bin/daily-run.sh --no-email >> /var/lib/syslog-reporter/daily-run.log 2>&1
30 7-17 * * 1     syslog-reporter /usr/local/bin/daily-run.sh --digest   >> /var/lib/syslog-reporter/daily-run.log 2>&1
```

The digest is the findings that kept recurring over the last seven
days, ranked by how many days they were seen, with resolutions written
fresh by `SYSLOG_DIGEST_MODEL`. So the `.env` holds cheap models for the
quiet daily runs (`SYSLOG_LOGSCAN_MODEL`, `SYSLOG_ISSUE_MODEL`) and the
best you have for the digest, and the expensive model runs once a week
over a short list. A daily email is one line with no options.

**Missed a Monday?** The digest keeps no state; its window simply ends
yesterday. Run it by hand with a wider window and the week is covered:

```bash
cd /var/lib/syslog-reporter
sudo -u syslog-reporter syslog-reporter digest --days 14 --send-email
```

**No ELK?** Slice yesterday's log however suits your estate and cron the
binary directly:

```cron
# in the syslog-reporter user's crontab: yesterday's rotated log, emailed
# at 07:30; the cd is so the .env and database in the state directory are found
30 7 * * * cd /var/lib/syslog-reporter && /usr/local/bin/syslog-reporter run /var/log/syslog.1 \
  --send-email >> /var/lib/syslog-reporter/daily-run.log 2>&1
```

There is no retry this way: a failed attempt is cron mail and a re-run
by hand.

**Behind a proxy?** The LLM calls need the standard proxy variables, and
they need to be where the *binary's* process can see them. `sudo -u`
resets the environment and cron starts with a near-empty one, so a proxy
exported in your login shell silently never arrives. The reliable place
is the same `.env`:

```bash
https_proxy=http://proxy.example.ac.uk:3128
# keep internal traffic direct - without this, elk_dump.py would try
# to reach your ELK cluster THROUGH the proxy too
no_proxy=elk.example.ac.uk
```

Real environment variables win over the `.env`. One edge that can lose
someone a day: `no_proxy` is a comma-separated list matched against the
hostname as written in `ELK_URL`, and a bare domain (`example.ac.uk`)
also covers its subdomains.

**Using Azure OpenAI?** There are gotchas, chiefly that an undersized
deployment makes every run fail on throttling. Read "Azure gotchas" in
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) before the first real
run.

## 5. Live with it

Every run files its findings into a findings library.

**The web UI.** `install.sh` offers to install
[scripts/syslog-reporter-web.service](scripts/syslog-reporter-web.service),
which serves the findings library on `127.0.0.1:7373` with local
accounts. It refuses to start until the database exists. Then add a
login:

```bash
cd /var/lib/syslog-reporter
sudo -u syslog-reporter syslog-reporter user add jbloggs jbloggs@example.ac.uk
```

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
`mgmt-report` renders a summary as a self-contained HTML email.
`--days 7` for a weekly flavour, and `--send-email` goes to
`SYSLOG_MGMT_RECIPIENTS`, a separate list from the daily digest.

**From your own machine.** The `serve` process also exposes a small JSON
API for Claude Code or plain curl. [API.md](API.md) has the tokens and
the `syslog-mute` shell function.

`syslog-reporter self-update` replaces the binary with the latest
release.

## 6. Backups

The history and the findings library are one SQLite file,
`syslog_aggregates.db` in the state directory, and it runs in WAL mode:
recent writes sit in the `-wal` sidecar until a checkpoint, so a plain
`cp` of a live file can silently miss them. Back it up with SQLite's own
tool, which takes a consistent copy while everything keeps running:

```bash
cd /var/lib/syslog-reporter
sudo -u syslog-reporter sqlite3 syslog_aggregates.db ".backup /var/backups/syslog-reporter.db"
```

Worth keeping alongside it: the `.env` and `known_knowns.toml`, which are
the only other things in that directory you cannot regenerate. "Backing
up the database" in [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) has
the detail.
