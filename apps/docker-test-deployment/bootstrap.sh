#!/bin/bash
# One-shot setup for the plain `docker compose` deployment.
#
#   ./bootstrap.sh [N]     N = number of clients, default 2 (client0 + client1)
#
# Run this once after cloning, BEFORE `docker compose up --build`. The image
# bakes this directory in at build time (Dockerfile: COPY apps/ apps/) and the
# containers do not share a filesystem with the host, so the certificates and
# voter lists have to exist here first.
#
# Idempotent: safe to re-run. It regenerates the PKI and re-stages the voter
# lists, and never touches the committed config.ini files.
#
# This is the manual/interactive path. For a multi-client fleet and the
# measurement runs, use the ansible path instead (see ansible-configs/).

set -euo pipefail

cd "$(dirname "$0")"
N="${1:-2}"

if [ "$N" -lt 2 ]; then
    echo "[ERR] need at least 2 clients (one untrusted, one trusted)" >&2
    exit 1
fi

echo "[1/3] Generating PKI for 2 servers and ${N} clients..."
# openssl is very chatty on stderr; keep the log so a real failure is debuggable.
if ! ./generate_keys.sh "$N" >bootstrap-keys.log 2>&1; then
    echo "[ERR] generate_keys.sh failed. Last lines of bootstrap-keys.log:" >&2
    tail -20 bootstrap-keys.log >&2
    exit 1
fi
echo "      one CA, server certs, ${N} client certs"

# The check-in service reads the voter roll AND the PIN mappings from the single
# file named by voter_list_file, so it needs the 9-column roll. The ID service
# parses positionally (field [1] == Last Name) and must get the PIN-less one.
# Both land as "voters.csv" because that is what each config.ini asks for.
echo "[2/3] Staging voter lists from ../../data/ ..."
cp ../../data/voters.csv    checkin_server/voters.csv
cp ../../data/id_voters.csv id_server/voters.csv
echo "      checkin_server/voters.csv  <- data/voters.csv    ($(wc -l < checkin_server/voters.csv) lines, with PINs)"
echo "      id_server/voters.csv       <- data/id_voters.csv ($(wc -l < id_server/voters.csv) lines, no PINs)"

# Trusted client ids are the odd ones, matching the compose service names
# (untrusted-client-0, trusted-client-1, ...). The check-in service refuses
# Phase 2 from any client id not listed here.
echo "[3/3] Writing checkin_server/trusted_clients.txt ..."
: >checkin_server/trusted_clients.txt
for ((i = 1; i < N; i += 2)); do
    echo "$i" >>checkin_server/trusted_clients.txt
done
echo "      trusted client ids: $(tr '\n' ' ' <checkin_server/trusted_clients.txt)"

cat <<'EOF'

Done. Next, from the repository root:

    docker compose up -d --build

--build matters: the certificates are baked into the image at build time, so
re-running this script without rebuilding leaves the containers on the old PKI.

Then open four terminals (see README.md, "Interactive walkthrough").
EOF
