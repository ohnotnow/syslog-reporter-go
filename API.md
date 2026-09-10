# The sysadmin API

The `serve` process that runs the findings web UI also exposes a small
JSON API under `/api/`, so you can query and act on findings from your
own machine with plain curl, a shell function, or Claude Code. Nothing
to install: a bearer token and a URL.

## Get a token

Every call needs a personal bearer token, whatever `--auth` the web UI
runs with. An admin mints them on the server:

```bash
./syslog-reporter token create jbloggs --expires 2027-01-31   # prints the token once
./syslog-reporter token list                                   # who has one, last used, expiry
./syslog-reporter token revoke 5210c8e0                        # by the 8-character prefix
```

Then set two environment variables and check them:

```bash
export SYSLOG_API_URL=http://reports.example.test:7373
export SYSLOG_API_TOKEN=...
curl -sS -H "Authorization: Bearer $SYSLOG_API_TOKEN" "$SYSLOG_API_URL/api/me"
```

## Muting from the daily email

The daily email prints a `syslog-mute 1234 "reason"` line under each
finding. That is a shell function, not a command in the binary; paste
one of these into your shell profile. A mute takes only a reason: the
server works out the host and program from the finding and appends the
entry to the known-knowns file.

```bash
# bash / zsh (~/.bashrc or ~/.zshrc)
syslog-mute() {
  if [ -z "$SYSLOG_API_URL" ] || [ -z "$SYSLOG_API_TOKEN" ]; then
    echo "syslog-mute: set SYSLOG_API_URL and SYSLOG_API_TOKEN first (see API.md)" >&2
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
    Write-Error "syslog-mute: set SYSLOG_API_URL and SYSLOG_API_TOKEN first (see API.md)"
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

## From Claude Code

Copy [skills/syslog-reporter](skills/syslog-reporter) into
`~/.claude/skills/` and ask in plain words: "what did the syslog report
find today?", "look at finding 1234", "mute the dhcp one on dhcp01, it
has no pool by design". The skill carries the endpoint list, the JSON
shapes and the etiquette (read a finding before muting it, always
confirm, never invent a reason).

## Endpoints

- `GET /api/me` - who this token is
- `GET /api/findings` - findings, with the same filters as the CLI
  (`host`, `service`, `severity`, `kind`, `run_kind`, `q`, `since`,
  `until`, `limit`, `offset`); every row carries `run_kind`, `daily` or
  `digest` (the weekly digest's own findings, filed under the window's
  end date)
- `GET /api/findings/{id}` - one finding in full, with its feedback
- `POST /api/findings/{id}/feedback` - `verdict` (worked / didnt-work)
  and an optional `comment`
- `POST /api/findings/{id}/mute` - `reason`, optional `expires`
- `GET /api/runs` - the runs over a date range, each with its `kind`
- `GET /api/aggregates` - per-day line counts, for trend questions

Every response is JSON and every error is `{"error": "..."}`. The full
reference, including limits and status codes, is the "The sysadmin API"
section of [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md).
