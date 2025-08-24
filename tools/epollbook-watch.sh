#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLAYBOOK_DIR="$ROOT/ansible-configs"
PLAYBOOK="$PLAYBOOK_DIR/rebuild_restart.yml"

# Debounce between bursts (can override with env DEBOUNCE=3)
DEBOUNCE="${DEBOUNCE:-2}"
LOCK_FILE="$ROOT/.watcher.lock"

# Ensure ansible-playbook is found when run by systemd --user
PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"

# Watch ONLY backend code (no ansible/config paths)
WATCH_PATHS=( 'src' 'include' 'apps' 'CMakeLists.txt' )
EXCLUDE_REGEX='(\.git/|/build/|/output/|/\.cmake/)'

cd "$ROOT" || exit 1
echo "[watch] repo=$ROOT  playbook=$PLAYBOOK  debounce=${DEBOUNCE}s"

# Sanity checks
command -v inotifywait      >/dev/null || { echo "[watch] ERROR: inotifywait not found"; exit 1; }
command -v ansible-playbook >/dev/null || { echo "[watch] ERROR: ansible-playbook not found"; exit 1; }
[[ -f "$PLAYBOOK" ]] || { echo "[watch] ERROR: $PLAYBOOK does not exist"; exit 1; }

run_cycle() {
  # Non-blocking lock prevents overlapping runs
  exec {lfd}>"$LOCK_FILE" || true
  if ! flock -n "$lfd"; then
    echo "[watch] run already in progress; skipping"
    return 0
  fi
  echo "[watch] code change detected → rebuild+restart"
  if ! ansible-playbook "$PLAYBOOK"; then
    echo "[watch] rebuild_restart.yml failed"
  fi
}

# Start watching
inotifywait -m -r -e modify,close_write,move,create,delete \
  --exclude "$EXCLUDE_REGEX" \
  "${WATCH_PATHS[@]}" \
| while read -r _; do
    sleep "$DEBOUNCE"
    run_cycle
  done
