#!/usr/bin/env bash
set -euo pipefail
cd "/home/mahady/pollbook-server"
if docker compose watch --help >/dev/null 2>&1; then
  exec docker compose watch
else
  exec docker compose up -w
fi
