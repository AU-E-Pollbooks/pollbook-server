#!/usr/bin/env bash
set -euo pipefail
# Resolve repo root relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/.." && pwd)"
if docker compose watch --help >/dev/null 2>&1; then
    exec docker compose watch
else
    exec docker compose up -w
fi
