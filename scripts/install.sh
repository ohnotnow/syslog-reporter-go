#!/usr/bin/env bash
#
# The "Make it daily" section of GETTING_STARTED.md as one script: a
# system user, its state directory, the binary and helpers, a .env to
# fill in, two weeks of free history, the hourly cron job and, if you
# want it, the findings web UI as a systemd service.
#
# Run it as root from a checkout that has the syslog-reporter binary in
# it (built with `go build -o syslog-reporter ./cmd/syslog-reporter`,
# or downloaded from the releases page):
#
#   sudo ./scripts/install.sh
#
# It asks three things: an address for cron's failure mail, whether to
# run the backfill now, and whether to install the web UI service. Each
# has a default, and with no terminal (`install.sh </dev/null`) the
# defaults are taken, so it can run unattended.
#
# Re-running is safe: the binary and helpers are refreshed, the cron
# file and unit are rewritten, and an existing .env is left exactly as
# it is. Debian and RHEL-alikes with cron and systemd only.

set -euo pipefail

SERVICE_USER=${SERVICE_USER:-syslog-reporter}
WORK_DIR=${WORK_DIR:-/var/lib/syslog-reporter}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
BACKFILL_DAYS=${BACKFILL_DAYS:-14}

here=$(cd "$(dirname "$0")/.." && pwd)
binary="$here/syslog-reporter"

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
[ -x "$binary" ] || die "no binary at $binary - build one with
  go build -o syslog-reporter ./cmd/syslog-reporter
or download one from the releases page into the checkout"
command -v python3 >/dev/null || die "python3 is needed for elk_dump.py"
command -v flock >/dev/null || die "flock (util-linux) is needed by daily-run.sh"

# ask "question" "default"  - a yes/no with the default taken when there
# is no terminal to answer from.
ask() {
    local answer=
    if [ -t 0 ]; then
        read -r -p "$1 [$2] " answer
    fi
    answer=${answer:-$2}
    case "$answer" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

echo "== user and state directory"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "user $SERVICE_USER exists"
else
    useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
    echo "created user $SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -m 750 "$WORK_DIR"

echo "== binary and helpers into $BIN_DIR"
install -m 755 "$binary" "$here/tools/elk_dump.py" \
    "$here/scripts/backfill.sh" "$here/scripts/daily-run.sh" "$BIN_DIR/"

echo "== settings"
env_file="$WORK_DIR/.env"
if [ -e "$env_file" ]; then
    echo "$env_file exists, leaving it alone"
else
    install -o "$SERVICE_USER" -m 600 "$here/scripts/dotenv.example" "$env_file"
    if [ -t 0 ]; then
        echo "opening $env_file - fill in the model, key, SMTP and ELK lines, then save"
        "${EDITOR:-vi}" "$env_file"
    else
        echo "no terminal: edit $env_file before the first run"
    fi
fi

echo "== cron"
mailto=
if [ -t 0 ]; then
    read -r -p "address for cron's failure mail (blank for none): " mailto
fi
cron_file=/etc/cron.d/syslog-reporter
[ -d /etc/cron.d ] || die "/etc/cron.d is missing - install cron (cronie on RHEL) and re-run"
{
    echo "# syslog-reporter: yesterday's report to the team, first try at 07:30,"
    echo "# retried on the half hour until it goes out (daily-run.sh keeps a .sent marker)"
    if [ -n "$mailto" ]; then echo "MAILTO=$mailto"; fi
    echo "30 7-17 * * * $SERVICE_USER $BIN_DIR/daily-run.sh >> $WORK_DIR/daily-run.log 2>&1"
} > "$cron_file"
chmod 644 "$cron_file"
echo "wrote $cron_file"

echo "== history"
if ask "run backfill.sh for the last $BACKFILL_DAYS days now (free, no LLM)?" y; then
    runuser -u "$SERVICE_USER" -- "$BIN_DIR/backfill.sh" "$BACKFILL_DAYS" ||
        echo "backfill reported failures - check the ELK lines in $env_file and re-run: sudo -u $SERVICE_USER backfill.sh" >&2
else
    echo "skipped - run it later with: sudo -u $SERVICE_USER backfill.sh"
fi

echo "== web UI"
if ask "install the findings web UI as a systemd service (127.0.0.1:7373)?" n; then
    command -v systemctl >/dev/null || die "systemctl not found"
    install -m 644 "$here/scripts/syslog-reporter-web.service" /etc/systemd/system/
    systemctl daemon-reload
    if [ -e "$WORK_DIR/syslog_aggregates.db" ]; then
        systemctl enable --now syslog-reporter-web
        echo "enabled syslog-reporter-web; add a login with:"
        echo "  sudo -u $SERVICE_USER $BIN_DIR/syslog-reporter user add <name> <email> --db $WORK_DIR/syslog_aggregates.db"
    else
        systemctl enable syslog-reporter-web
        echo "enabled syslog-reporter-web but not started: serve needs the database, which the first run creates"
    fi
else
    echo "skipped - scripts/syslog-reporter-web.service has the by-hand steps"
fi

echo
echo "done. The next attempt at 07:30 sends yesterday's report; to send one now:"
echo "  sudo -u $SERVICE_USER $BIN_DIR/daily-run.sh"
