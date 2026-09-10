#!/usr/bin/env bash
#
# The "Make it daily" section of GETTING_STARTED.md as one script: a
# system user, its state directory, the binary and helpers, a .env to
# fill in, two weeks of free history, the hourly cron job and, if you
# want it, the findings web UI as a systemd service.
#
# Run it as root from a checkout:
#
#   sudo ./scripts/install.sh
#
# The binary comes from the first of: a syslog-reporter (or a release
# asset, syslog-reporter-linux-<arch>) already in the checkout; the
# latest GitHub release, downloaded and checked against its SHA256SUMS;
# or `go build`, if the go compiler is installed. The download and the
# build each ask first. With none of those it stops before creating
# anything.
#
# It then asks three things: an address for cron's failure mail, whether
# to run the backfill now, and whether to install the web UI service.
# Each question has a default, and with no terminal
# (`install.sh </dev/null`) the defaults are taken, so it can run
# unattended.
#
# Re-running is safe: the binary and helpers are refreshed, the cron
# file and unit are rewritten, and an existing .env is left exactly as
# it is. Debian and RHEL-alikes with cron and systemd only.

set -Eeuo pipefail

# Any command that fails unexpectedly stops the script (set -e); say
# which step and which command, so nobody is left guessing why it
# exited 1 or how far it got. The deliberate stops go through die().
step=starting
step() { step=$1; echo "== $step"; }
on_error() {
    echo "install.sh: failed during '$step' at line $1:" >&2
    echo "    $2" >&2
    echo "Steps before '$step' are done; fix the cause and re-run (re-running is safe)." >&2
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

SERVICE_USER=${SERVICE_USER:-syslog-reporter}
WORK_DIR=${WORK_DIR:-/var/lib/syslog-reporter}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
BACKFILL_DAYS=${BACKFILL_DAYS:-14}
RELEASE_URL=${RELEASE_URL:-https://github.com/ohnotnow/syslog-reporter-go/releases/latest/download}

here=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "install.sh: $*" >&2; exit 1; }

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

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
command -v python3 >/dev/null || die "python3 is needed for elk_dump.py"
command -v flock >/dev/null || die "flock (util-linux) is needed by daily-run.sh"

# The release workflow names assets by GOARCH; uname speaks differently.
case "$(uname -m)" in
    x86_64) asset=syslog-reporter-linux-amd64 ;;
    aarch64) asset=syslog-reporter-linux-arm64 ;;
    *) asset= ;;
esac

# Download the latest release asset for this arch into the checkout,
# verified against the published SHA256SUMS. Returns non-zero (and says
# why) rather than dying, so the caller can fall through to go build.
download_release() {
    [ -n "$asset" ] || { echo "no release asset for $(uname -m)"; return 1; }
    if ! curl -fsSLI --connect-timeout 10 -o /dev/null "$RELEASE_URL/SHA256SUMS"; then
        echo "cannot reach $RELEASE_URL"
        return 1
    fi
    ask "download the latest release ($asset) from GitHub?" y || return 1
    local tmp
    tmp=$(mktemp -d)
    if ! curl -fsSL -o "$tmp/$asset" "$RELEASE_URL/$asset" ||
       ! curl -fsSL -o "$tmp/SHA256SUMS" "$RELEASE_URL/SHA256SUMS"; then
        rm -rf "$tmp"
        echo "download failed"
        return 1
    fi
    if ! (cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c --quiet); then
        rm -rf "$tmp"
        echo "checksum mismatch on $asset - not installing it"
        return 1
    fi
    install -m 755 "$tmp/$asset" "$here/syslog-reporter"
    rm -rf "$tmp"
    echo "downloaded and verified $asset"
}

build_from_source() {
    command -v go >/dev/null || { echo "no go compiler on PATH"; return 1; }
    [ -f "$here/go.mod" ] || { echo "$here is not a source checkout (no go.mod)"; return 1; }
    ask "build syslog-reporter from source with go build?" y || return 1
    (cd "$here" && go build -o syslog-reporter ./cmd/syslog-reporter)
    echo "built $here/syslog-reporter"
}

step "binary"
binary=
for candidate in "$here/syslog-reporter" "$here/$asset"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        binary=$candidate
        echo "using $binary"
        break
    fi
done
if [ -z "$binary" ]; then
    download_release || build_from_source || die "no binary. Either
  download $asset from $RELEASE_URL into $here, or
  install go and run: go build -o syslog-reporter ./cmd/syslog-reporter
then re-run this script. Nothing has been changed."
    binary="$here/syslog-reporter"
fi
chmod 755 "$binary"
"$binary" --help >/dev/null 2>&1 || die "$binary does not run here (wrong architecture?)"

step "user and state directory"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "user $SERVICE_USER exists"
else
    useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
    echo "created user $SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -m 750 "$WORK_DIR"

step "binary and helpers into $BIN_DIR"
install -m 755 "$binary" "$BIN_DIR/syslog-reporter"
install -m 755 "$here/tools/elk_dump.py" \
    "$here/scripts/backfill.sh" "$here/scripts/daily-run.sh" "$BIN_DIR/"

step "settings"
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

step "cron"
mailto=
if [ -t 0 ]; then
    read -r -p "address for cron's failure mail (blank for none): " mailto
fi
cron_file=/etc/cron.d/syslog-reporter
[ -d /etc/cron.d ] || die "/etc/cron.d is missing - install cron (cronie on RHEL) and re-run"
# An existing schedule is the operator's: a re-run refreshes the binary
# and helpers, never the crontab. The weekly shape below is for a new
# install; to move an older daily-email install to it, edit the file.
if [ -e "$cron_file" ]; then
    echo "kept existing $cron_file (delete it and re-run for the weekly-digest schedule)"
else
{
    echo "# syslog-reporter: run and file every day, first try at 07:30 and retried"
    echo "# on the half hour (daily-run.sh keeps a .sent marker); on Mondays email the"
    echo "# weekly digest of recurring findings instead of a daily report. For a daily"
    echo "# email instead, use one line with no options: 30 7-17 * * * ... daily-run.sh"
    if [ -n "$mailto" ]; then echo "MAILTO=$mailto"; fi
    echo "30 7-17 * * 0,2-6 $SERVICE_USER $BIN_DIR/daily-run.sh --no-email >> $WORK_DIR/daily-run.log 2>&1"
    echo "30 7-17 * * 1     $SERVICE_USER $BIN_DIR/daily-run.sh --digest >> $WORK_DIR/daily-run.log 2>&1"
} > "$cron_file"
chmod 644 "$cron_file"
echo "wrote $cron_file"
fi

step "history"
if ask "run backfill.sh for the last $BACKFILL_DAYS days now (free, no LLM)?" y; then
    runuser -u "$SERVICE_USER" -- "$BIN_DIR/backfill.sh" "$BACKFILL_DAYS" ||
        echo "backfill reported failures - check the ELK lines in $env_file and re-run: sudo -u $SERVICE_USER backfill.sh" >&2
else
    echo "skipped - run it later with: sudo -u $SERVICE_USER backfill.sh"
fi

step "web UI"
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
echo "done. Cron runs yesterday's logs at 07:30 each day and emails the weekly digest"
echo "on Mondays ($cron_file has the schedule); to see a day's report now:"
echo "  sudo -u $SERVICE_USER $BIN_DIR/daily-run.sh"
