#!/usr/bin/env bash
# Installs a user systemd timer that runs scripts/nightly.sh every night.
#
#   ops/install-nightly.sh [build dir]     # install and start the timer
#   ops/install-nightly.sh --remove        # stop and remove it
#
# The build dir is where the heavy build output goes (several GB); it
# defaults to <repo>/target/nightly. Nothing here needs root. For the timer to
# fire while you are logged out: `loginctl enable-linger "$USER"`.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
UNITS=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
NAME=solana-thin-nightly

if [ "${1:-}" = "--remove" ]; then
  systemctl --user disable --now "$NAME.timer" 2>/dev/null || true
  rm -f "$UNITS/$NAME.service" "$UNITS/$NAME.timer"
  systemctl --user daemon-reload
  echo "removed $NAME"
  exit 0
fi

BUILD=${1:-$ROOT/target/nightly}
mkdir -p "$UNITS"
cat >"$UNITS/$NAME.service" <<UNIT
[Unit]
Description=solana-thin: nightly oracle, fuzz, fixture and tripwire checks

[Service]
Type=oneshot
WorkingDirectory=$ROOT
Environment=SOLANA_THIN_BUILD=$BUILD
Environment=PATH=$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$ROOT/scripts/nightly.sh
Nice=10
UNIT
cat >"$UNITS/$NAME.timer" <<UNIT
[Unit]
Description=solana-thin: nightly checks

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now "$NAME.timer"
systemctl --user list-timers "$NAME.timer" --no-pager
echo "run it now with: systemctl --user start $NAME.service"
echo "last result:     ${XDG_STATE_HOME:-$HOME/.local/state}/solana-thin/nightly/"
