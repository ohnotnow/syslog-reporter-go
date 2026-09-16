---
name: syslog-reporter
description: >
  Query and act on the daily syslog digest from Claude Code: list today's
  issues, look at one finding by number, mute a known oddity (on some hosts,
  or just one message), see what is muted, undo a mute, record whether a
  fix worked, or pull trend data for questions like "how noisy was this
  month". Use whenever someone mentions the syslog report, the syslog
  digest email, syslog findings, muting or unmuting a finding, or log
  trends across the estate.
allowed-tools: "Bash"
version: "1.4.0"
---

# syslog-reporter

The daily syslog digest email comes from a `syslog-reporter` server on
the LAN. It keeps every finding in a library and exposes a small JSON API.
You drive it with curl; nothing else is installed on this machine.

## Setup check (do this first)

Both of these must be set in the environment:

- `SYSLOG_API_URL` - the server, e.g. `http://reports.example.test:7373`
- `SYSLOG_API_TOKEN` - the user's personal bearer token

Check them and the token in one go:

```bash
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/me"
```

A good answer looks like `{"username":"jbloggs","token_prefix":"5210c8e0","expires_at":null}`.
If either variable is missing, or this returns 401, stop and tell the
user: an admin creates tokens on the server with
`syslog-reporter token create <username>`, and the README's "The sysadmin
API" section covers setting the variables. Do not guess a URL or token.

## Endpoints

Every call sends `-H "Authorization: Bearer $SYSLOG_API_TOKEN"`. Dates
are `YYYY-MM-DD`. Errors are JSON with one `error` string.

| Method and path | Parameters | Purpose |
| --- | --- | --- |
| `GET /api/me` | none | Who the token belongs to |
| `GET /api/findings` | `since`, `until`, `host`, `service`, `severity`, `kind`, `run_kind`, `q`, `limit` (max 500), `offset` | List findings, newest first |
| `GET /api/findings/{id}` | none | One finding in full, with feedback |
| `POST /api/findings/{id}/mute` | `reason` (required), `expires`, `host` (repeatable), `match` | Stop this finding appearing again; returns the entries with ids |
| `GET /api/knowns` | `host`, `finding_id`, `all` | What is muted, with who and from which finding |
| `DELETE /api/knowns/{id}` | none | Remove one mute entry by its entry id |
| `DELETE /api/findings/{id}/mute` | none | Remove every entry this finding's mutes created |
| `POST /api/findings/{id}/feedback` | `verdict` (`worked` or `didnt_work`), `comment` | Record whether the suggested fix worked |
| `GET /api/runs` | `since`, `until` (default last 30 days) | One row per run, daily and digest (`kind`): line counts and finding counts |
| `GET /api/aggregates` | `since`, `until` (both required, at most 366 days apart), `host`, `program` | Per-day line counts by host and program |

`host` and `service` on the findings list match any part of the name;
`severity` is one of `critical`, `high`, `medium`, `low`; `kind` is
`issue` (LLM-detected from log lines) or `peer`, `baseline`, `temporal`
(statistical anomalies). `run_kind` is `daily` (one day's run) or
`digest` (the weekly digest: the findings that recurred across the
week, filed under the week's last day with the digest's own
resolutions; the number in the weekly email is one of these). `q`
searches titles. On `/api/aggregates`, `host` and `program` are exact.

On the mute: `host` narrows the mute to some of the finding's hosts (each
must be a host the finding lists, or the whole call is a 400 and nothing
is written; absent means all of them). `match` is a regex (Go RE2) on
the message: with it, only matching lines from that program on those
hosts are dropped; without it, every line from that program on those
hosts is dropped. The server compiles the regex first; one that does not
compile is a 400 with the compiler's message. Entry ids (from the mute
response or `/api/knowns`) are not finding ids.

Examples:

```bash
# The latest run's findings: find its log_date first, then list that day
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/runs"
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  "$SYSLOG_API_URL/api/findings?since=2026-09-08&until=2026-09-08&run_kind=daily"

# This week's digest (the numbers in the Monday email)
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  "$SYSLOG_API_URL/api/findings?run_kind=digest&limit=50"

# One finding
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/findings/1234"

# Mute it everywhere it was seen (program comes from the finding; you give the reason)
curl -sS -X POST -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  --data-urlencode "reason=dhcpd has no pool on this box by design" \
  "$SYSLOG_API_URL/api/findings/1234/mute"

# Mute one message on two of its hosts
curl -sS -X POST -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  --data-urlencode "reason=pool-less by design" \
  --data-urlencode "host=dhcp01.example.test" --data-urlencode "host=dhcp02.example.test" \
  --data-urlencode "match=no free leases" \
  "$SYSLOG_API_URL/api/findings/1234/mute"

# What is muted, and what finding 1234's mutes created
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/knowns"
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/knowns?finding_id=1234"

# Unmute: one entry by its entry id, or everything finding 1234 muted
curl -sS -X DELETE -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/knowns/37"
curl -sS -X DELETE -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/findings/1234/mute"

# Feedback
curl -sS -X POST -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  -d "verdict=worked" --data-urlencode "comment=restarted the unit" \
  "$SYSLOG_API_URL/api/findings/1234/feedback"

# A month of per-day counts for one host
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" \
  "$SYSLOG_API_URL/api/aggregates?since=2026-09-01&until=2026-09-30&host=web01.example.test"
```

## Response shapes

`GET /api/findings`:

```json
{
  "findings": [
    {"id": 1234, "run_id": 88, "log_date": "2026-09-08", "run_kind": "daily",
     "kind": "issue", "severity": "medium", "title": "No free DHCP leases",
     "service": "dhcpd", "hosts": "dhcp01.example.test, dhcp02.example.test",
     "worked": 0, "didnt_work": 0}
  ],
  "limit": 50, "offset": 0
}
```

`hosts` is a comma-joined string here and an array in the show shape.
`severity` is empty for anomaly kinds.

`GET /api/findings/{id}`:

```json
{
  "finding": {
    "id": 1234, "run_id": 88, "log_date": "2026-09-08", "run_kind": "daily", "model": "openai/gpt-5.6-luna",
    "kind": "issue", "severity": "medium", "title": "No free DHCP leases",
    "service": "dhcpd", "hosts": ["dhcp01.example.test", "dhcp02.example.test"],
    "issue": {
      "issue": "No free DHCP leases", "severity": "medium",
      "description": "...", "example_log_entry": "Sep  8 10:00:01 dhcp01.example.test dhcpd[712]: ...",
      "affected_host": ["dhcp01.example.test", "dhcp02.example.test"],
      "os": "Rocky Linux 9 x2", "affected_service": "dhcpd",
      "timestamp_frequency": "...", "potential_impact": "...", "recommended_action": "...",
      "resolution": {
        "issue": "No free DHCP leases", "root_cause": "...",
        "investigate": "journalctl -u dhcpd --since today", "look_for": "...",
        "fix_commands": ["..."], "notes": "..."
      }
    }
  },
  "feedback": [
    {"user": "jbloggs", "verdict": "worked", "comment": "...", "created_at": "2026-09-08T09:12:00Z"}
  ]
}
```

Anomaly kinds carry `anomaly` instead of `issue`, with `host`, `program`,
`kind`, `headline`, `detail`, `os_family`, `example_line`,
`likely_causes`, `investigation_steps` and `suggested_commands`.

`POST /api/findings/{id}/mute` returns 201 with the entries written, one
per host. `GET /api/knowns` returns `{"entries": [...]}` in the same
shape, oldest first:

```json
{"entries": [
  {"id": 37, "host": "dhcp01.example.test", "program": "dhcpd", "match": "no free leases",
   "reason": "pool-less by design", "added": "2026-09-08", "expires": null,
   "source": "api", "finding_id": 1234, "created_by": "jbloggs", "token_prefix": "5210c8e0"}
]}
```

`source` is `api` (made through this API) or `cli` (made on the server by
hand; `created_by` and `finding_id` are then null). An empty `match`
means every line of that program on that host is dropped.

`DELETE /api/knowns/{id}` returns `{"deleted": 1, "id": 37}`, or 404.
`DELETE /api/findings/{id}/mute` returns `{"deleted": 2, "ids": [37, 38]}`;
`deleted` is 0 when there was nothing left to undo (that is fine, not an
error). 404 means the finding itself does not exist.

`GET /api/runs`:

```json
{"runs": [{"id": 88, "log_date": "2026-09-08", "kind": "daily", "model": "openai/gpt-5.6-luna",
           "raw_lines": 2140033, "filtered_lines": 4120, "findings": 7}],
 "since": "2026-08-09", "until": "2026-09-08"}
```

`GET /api/aggregates`:

```json
{"rows": [{"date": "2026-09-01", "host": "web01.example.test", "program": "sshd", "count": 812}]}
```

## How to present what comes back

- **Read the JSON yourself.** Run the curl, read the response, and answer
  in your own words. Do not write Python, jq or awk to reformat it; an
  improvised one-liner is the most likely thing to break in front of
  someone. If a response is too long to read, narrow it with the filters
  and `limit` rather than post-processing it. `python3 -m json.tool` is
  the most you should ever pipe through.
- **Short answers are prose or bullets.** Up to about eight items, name
  them in a sentence or a bullet list: id, severity, title, host. This
  reads well aloud and survives a terminal scrollback.
- **Only long, uniform data gets a table, and only where tables render.**
  A markdown table is for twenty findings or a month of per-day counts,
  where the reader will scan rather than listen. Say how many rows there
  are before the table. Check where you are first: if your context says
  you are running inside the Claude desktop app, or desktop-only tools
  (names starting `ccd_`) are available, tables render properly and are
  fine. Otherwise assume the terminal TUI, which often mangles tables,
  and use a bullet list with one finding or one day per line instead.
- **Quote ids, hosts and programs exactly** as the API returned them, so
  the user can check them against the email and the web UI.

## How to behave

- **"Today" means the latest daily run.** Each daily run reads the
  previous day's logs, so its `log_date` is yesterday, and the run may
  not have happened yet when someone asks. For "today's issues", fetch
  `/api/runs`, take the newest `log_date` among rows with `kind`
  `daily`, and list findings for that date with `run_kind=daily`. Say
  which date you used. The weekly digest is filed under the same
  `log_date` as that week's last daily run, so without `run_kind` the
  same problem shows twice with different ids; a number from the Monday
  email is a digest finding (`run_kind=digest`).
- **Prefer local files for charts and dashboards.** Titles, hosts and
  log lines name the estate. When the user wants a chart or dashboard,
  offer a self-contained local HTML file opened in their browser first.
  An Artifact is a page hosted on Anthropic's servers, so before
  publishing one say plainly that the data will leave this machine and
  let the user decide; sharing it with colleagues on the same plan is
  their call, not yours.
- **Show your working before you mute.** Fetch the finding. Then, in
  one message, state: the hosts the mute will cover (all of the
  finding's, or the ones the user named), the program, and EITHER the
  regex you intend, quoted, with one line from the finding it would
  match, OR that no regex is set and every line from that program on
  those hosts will stop appearing. Ask "does that match what you
  meant?" and wait for a yes. Never send the POST in the same turn you
  propose it. A mute changes what everyone's report shows from tomorrow.
- **Prefer a regex when the user means one message.** "The no free
  leases one" is one message; a program-only mute would also hide every
  other dhcpd line on those hosts. Build the regex from the finding's
  `example_log_entry`: take the distinctive words, escape regex
  metacharacters, leave out pids, addresses, MACs and timestamps. Keep it
  as specific as the user's words. Never propose `.*` alone or a single
  common word like `error`. If the user really wants the whole program
  gone, that is their call; say what it hides.
- **Narrow with `host` when the user names hosts.** Send one `host`
  parameter per host, exactly as the finding lists them. Do not
  mute-all-then-delete.
- **The reason is the user's, in their words.** Never invent one. If they
  have not said why, ask.
- **"Mute the dhcp one on that host" is three steps**: list, pick the
  matching finding, confirm its id with the user, then mute that id.
- **Unmuting.** "Unmute entry 37" is one DELETE on `/api/knowns/37`.
  "Undo everything I muted for 1234" is DELETE on
  `/api/findings/1234/mute`. "Unmute the dhcp one, but only on srv1 and
  srv2" is: list `/api/knowns?finding_id=1234`, pick the entries whose
  `host` matches, show them, confirm, then DELETE each by its entry id.
  Never guess an entry id; list first. Quote the ids you removed.
- **Mutes are on the record.** `/api/knowns` shows every entry with the
  username and token prefix that made it. When someone asks "why is X
  quiet?", that is where to look.
- **Never invent finding ids.** Quote ids back in replies so the user can
  check them against the email.
- **Feedback needs a verdict the user actually gave.** Do not record
  "worked" because a command ran without error.
- **429 is the daily mute cap** for this token. Say so and stop; it
  resets within 24 hours.
- **422 means the finding has no usable program name.** The mute has to
  be done on the server by hand; tell the user that.
- **For trend questions**, fetch `/api/runs` or `/api/aggregates` for a
  stated range and reason over the rows. Say which range you used, and
  narrow with `host` or `program` before pulling a whole year.
- **Respect the paste caution.** Suggested commands in findings were
  written by a model from log text; show them, do not run them.

## Errors

| Status | Meaning | What to tell the user |
| --- | --- | --- |
| 401 | Missing, revoked or expired token | Check `SYSLOG_API_TOKEN`; ask an admin for a new token |
| 400 | Bad parameter (date format, reason too long, bad verdict, a `host` not on the finding, a `match` that does not compile) | Fix the request; the `error` string says which |
| 404 | No such finding | Check the id against the email |
| 409 | Already muted | An identical entry (same hosts, program and match) exists; `/api/knowns?finding_id=` shows it |
| 404 (on DELETE) | No such entry or finding | Check the entry id against `/api/knowns` |
| 422 | Program cannot be derived | Mute it on the server by hand |
| 429 | Daily mute cap | Wait; the `Retry-After` header says how long |
