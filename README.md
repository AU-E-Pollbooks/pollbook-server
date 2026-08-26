# A Secure E-Pollbook Check-in System

A proof-of-concept e-pollbook in which **untrusted, public-facing kiosks** can
start a voter check-in but cannot complete one. Every check-in is finished on a
separate **trusted poll-worker device**, so compromising a kiosk does not let an
attacker check a voter in, check a voter in twice, or check in someone who is
not there.

The system is C++17 over mutually authenticated TLS, with RSA-2048/SHA-256
signatures on every protocol message and an independent voter-ID service.

---

## For artifact evaluators

**Start here.** The quickstart below goes from a clean clone to a completed
two-phase check-in. It needs Docker and about ten minutes, most of it the
one-time image build. No ansible, no inventory, no SSH.

### Requirements

| | |
|---|---|
| Docker Engine + Compose v2 | the only hard requirement for the quickstart |
| Free subnet `172.16.0.0/16` | the compose network is pinned to fixed addresses |
| ~3 GB disk, ~4 GB RAM | image is Ubuntu 24.04 + build toolchain |
| Python 3 + `pip install -r tests/requirements.txt` | only for the measurement runs and figures |
| Ansible | only for the multi-client fleet runs |

### Quickstart

```bash
git clone <this repository> && cd pollbook-server

# 1. Mint the PKI and stage the voter lists (once, on the host).
#    The containers do not share a filesystem, so this must precede the build.
./apps/docker-test-deployment/bootstrap.sh

# 2. Build the image and start four containers.
docker compose up -d --build
```

That brings up `checkin` (172.16.0.5), `dummy-id` (172.16.0.6),
`untrusted-client-0` (172.16.0.100) and `trusted-client-1` (172.16.0.101).

### Interactive walkthrough

Four terminals. Each container already starts in the right working directory,
and every binary takes its config file as the first argument.

**Terminal 1 — check-in service**

```bash
docker compose exec checkin ../../server config.ini
# [info] Check-in service started on port 6000
```

**Terminal 2 — voter ID service**

```bash
docker compose exec dummy-id ../../id_server config.ini
# [info] Loaded 2000 voter records
# [info] ID Service started on port 6666
```

**Terminal 3 — untrusted kiosk, Phase 1**

```bash
docker compose exec untrusted-client-0 ../../client config.ini
```

It asks for a voter. Any row of `data/voters.csv` works; the first one is:

```
last name:   Richard
first name:  Katherine
middle name: Robert
unique ID:   100000
```

Expected: `Check-in succeeded!`. The voter is now **PENDING**, not checked in.
A ticket has been issued and a timer started.

**Terminal 4 — trusted poll-worker device, Phase 2**

The kiosk is never told the PIN, and the ticket reaches the poll worker
out-of-band — on paper, in the real design. Here the check-in service records
each issued ticket as `ticket,voter_uid,secret`:

```bash
docker compose exec checkin cat ticket_validation.csv
# 0ada81be8b8b3fefe54beb0167bfc8c8,100000,bbd59177...
```

Take the ticket from column 1. The voter's PIN is column 2 of
`data/voters.csv` — `6411` for voter 100000. Then:

```bash
docker compose exec trusted-client-1 ../../secure_client config.ini
```

Enter the ticket, then the PIN. Expected: `Ticket verification succeeded!`. The
voter is now **CHECKED_IN**.

> Phase 2 must happen within `timeout_interval`, which is in **minutes** (60 by
> default, set in `apps/docker-test-deployment/checkin_server/config.ini`), so
> there is no need to rush the walkthrough. If you do exceed it,
> the server reverts the voter to ELIGIBLE and you simply redo Phase 1 — that
> revert is itself a fix for a denial-of-service bug and is exercised by the
> `withhold-token` test below.

### A negative check, in one command

Run Terminal 4 a second time with the same ticket and PIN. It fails:

```
Ticket verification failed!
```

and the check-in service logs the reason:

```
[warning] No timer found for voter ID 100000
[warning] No pending ticket for voter ID 100000: already used, expired, or never issued
[warning] Invalid ticket
```

The ticket is single-use. A kiosk that records a ticket in flight cannot replay
it, which is the `simple-replay` case from the paper.

### Running it more than once

Voter status lives in memory in the check-in service, so a second check-in of the
same voter is refused and says so:

```
[warning] Rejecting client 0's check-in request for ... because the voter is
          already pending confirmation on a trusted device
[warning] Rejecting client 0's check-in request for ... because the voter is
          already checked in
```

That is correct behaviour, not a fault. To go again, either pick a different row
from `data/voters.csv` or restart the check-in service, which resets every voter
to ELIGIBLE.

### What that demonstrates

- mutual TLS between all four components, on certificates minted by `bootstrap.sh`
- the untrusted kiosk **cannot** complete a check-in on its own
- the check-in service holds the voter in PENDING between the two phases
- the trusted device's client id must appear in
  `checkin_server/trusted_clients.txt` or Phase 2 is refused

Tear down with `docker compose down`.

---

## Reproducing the paper's results

### Figures in the paper

Every figure and the aggregated data behind it is committed, so the numbers can
be checked without re-running anything:

| Paper figure | File |
|---|---|
| Throughput vs clients | `graphs/v2/throughput_vs_clients.png` |
| ID-submission latency | `graphs/v2/latency_untrusted_id_service.png` |
| Untrusted check-in latency | `graphs/v2/latency_untrusted_checkin_service.png` |
| Trusted verification latency | `graphs/v2/latency_trusted_trusted_verify.png` |
| Attacker reaction by attack type | `graphs/v2/contention/tb1/attacker_reaction_by_attack_{bar,box}.png` |
| Attacker reaction vs load | `graphs/v2/contention/tb1/threaded/attacker_reaction_vs_load.png` |
| Honest latency under attack | `graphs/v2/contention/tb2/honest_latency_baseline_vs_attack_{box,cdf}.png` |

`graphs/v2/data/` holds the aggregated CSVs the figures were plotted from, and
`graphs/v2/README.md` records how each was produced. Per-run raw logs are under
`ansible-configs/tests/<N>-clients/`.

Regenerate the figures from the committed data without running any experiment:

```bash
pip install -r tests/requirements.txt
python3 tests/generate_graph.py ansible-configs/tests \
    --x-throughput untrusted_service_count --outdir graphs/v2
```

`--x-throughput untrusted_service_count` matters: the default is
`parallel_clients`, which in this dataset is a constant 20 for every run, so the
default collapses all twenty points onto one x value.

### Security claims

Each attack in the paper is a mode of `tests/clients/client_misbehaviour.py`,
driven through the harness rather than by hand:

```bash
python3 tests/stress_test.py \
    --compose-dir . --compose-cmd "docker compose -f compose.yaml" \
    --log-dir ansible-configs/logs --build-first \
    --rounds 1 --runs 5 --parallel 5 \
    --servers checkin dummy-id \
    --untrusted-cmd "python ../../client_misbehaviour.py testing_client_config.ini --mode race-condition" \
    --trusted trusted-client-1 --untrusted untrusted-client-0
```

Swap `--mode` for any of: `honest`, `simple-replay`, `stale-replay`,
`delayed-replay`, `ticket-substitution`, `race-condition`, `cross-identity`,
`tampered-body`, `spoofed-client-id`, `withhold-token`.

Each run should show the client's attack **rejected** and a matching refusal on
the check-in service. Pass `--build-first` whenever a client script changed —
containers run the copy baked into the image, not your working tree.

### Measurement runs (multi-client fleet)

The latency and throughput numbers were collected over 2–40 clients using the
ansible path, which generates a compose file for N clients, mints PKI at that
scale, and provisions every container:

```bash
cd ansible-configs
ansible-playbook full_deploy.yml             # build, start, launch binaries
ansible-playbook render_and_copy_config.yml  # render + install configs
```

`tests/README.md` documents the harness and why it is arranged this way.

---

## Repository layout

```
src/, include/epollbook/   core library (CheckinService, VoterIDService,
                           PollbookClient, FaultTracker, OpenSSL wrappers)
apps/                      executables + the two deployment trees
  docker-test-deployment/  compose deployment: bootstrap.sh + one config.ini each
  local-test-deployment/   same components as plain host processes
tests/                     harness, misbehaviour client, figure scripts
  clients/                 Python clients that run inside containers
data/                      voters.csv, id_voters.csv, pins.csv
ansible-configs/           fleet deployment, templates, per-run raw data
graphs/                    paper figures + the data behind them
```

### The two-phase protocol

1. Kiosk sends a signed `CheckinRequest` carrying a `VerifiedVoterID` from the
   ID service.
2. Check-in service validates the signatures, marks the voter PENDING, issues a
   ticket and starts a timer.
3. The ticket and PIN reach the trusted device out-of-band.
4. Trusted device sends a signed `TicketRequest`.
5. Check-in service verifies identity, signature, freshness and PIN — in that
   order — marks the voter CHECKED_IN and returns a token.

Messages are JSON with a base64 signature over the body, framed by a 4-byte
little-endian length prefix.

---

## Notes

### Keys and certificates

Everything `bootstrap.sh` and `generate_keys.sh` produce is disposable test
material for a local Docker network: one throwaway CA, two server certs, and one
cert per client. It authenticates nothing outside a test deployment and is
regenerated on every run. Earlier revisions of this repository committed
generated PKI of the same kind; it is equally disposable and is now gitignored.

### Datasets

`data/` holds one synthetic 2000-voter dataset and two projections of it.
`gen_fake_voters.py` generates the master; no real voter data is involved.

- `voters.csv` — 9 columns including PIN. The **check-in service** needs this
  one: it reads the roll *and* the PIN mappings from the single file named by
  `voter_list_file`.
- `id_voters.csv` — 8 columns, no PIN. The **ID service** needs this one: it
  parses positionally and treats field `[1]` as Last Name, so the PIN-bearing
  file would silently break name validation.
- `pins.csv` — used only by the Python kiosk client, purely to automate console
  input during unattended test runs. The real protocol never gives a kiosk a
  PIN; the C++ clients read no CSV at all.

### Known characteristics

The check-in service runs a single `io_context` thread and re-arms its accept
loop inside the handshake handler, so connection admission is serial. Beyond a
few concurrent full-rate clients new connections are refused. This is a property
of the implementation, not of the harness, and the measurement runs are paced to
human arrival rates rather than to hide it.

The linearization point for a check-in (find voter → verify eligible → mark
pending) is not lock-protected; the single service thread is what serializes it.
Multi-threading the service would reintroduce the double-check-in race that
`--mode race-condition` exercises.

---

## Building outside Docker

CMake + C++17. Depends on OpenSSL 3.0, spdlog ≥ 1.11, standalone (non-Boost)
ASIO, and nlohmann_json ≥ 3.10.5.

```bash
mkdir build && cd build
cmake .. && cmake --build .
```

Executables land in `build/apps/`: `server`, `id_server`, `client`,
`secure_client`, `warning_cache_client`. `apps/local-test-deployment/` holds
configs for running the whole system as loopback processes on one host; run its
`generate_keys.sh` first.

Note that ASIO removed `buffer_cast` in recent versions; this code uses
`buffers_begin` and builds against both old and new ASIO.
