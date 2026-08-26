# Testing Setup and Decisions

This document records *why* the test infrastructure is arranged the way it is.
It is aimed at someone reading this repository for the first time.

## Layout

```
tests/
  clients/                    simulation clients, run INSIDE containers
    client.py                 untrusted kiosk (Phase 1)
    trusted_client.py         poll-worker device (Phase 2)
    client_misbehaviour.py    misbehaving client (all attack modes)
  stress_test.py              orchestrator / primary test driver
  plot_contention.py          contention test-bed figures
  generate_graph.py           latency + throughput figures
  gen_fake_voters.py          generates the master voter dataset
data/                         canonical datasets (see below)
```

`clients/` is separated because those scripts are copied into the container
image and executed there; everything else runs on the host. The CMake target
`copy_python_files` in `apps/CMakeLists.txt` globs `tests/clients/*.py` into
`build/apps/`, which is why the harness launches them as `../../client.py`
relative to each container's working directory.

## Two deployment paths, on purpose

Ansible is for a fleet of clients. `ansible-configs/full_deploy.yml` prompts
for client counts, generates `compose.yaml`, mints the PKI, and provisions eve
container. Every measurement run uses this path.

```
cd ansible-configs
ansible-playbook full_deploy.yml             # create + start containers
ansible-playbook render_and_copy_config.yml  # render + copy configs in
```

Docker Compose is for running things by hand. Bring the stack up and drive the
C++ binaries interactively. Use it to watch the protocol work; measurement run
go through the ansible path.

```
docker compose exec checkin bash
../../server config.ini
```

## Datasets

Three CSVs in `data/`, which are one dataset plus two projections of it.
`gen_fake_voters.py` generates the master; the other two are column subsets:

| file | columns | consumer |
|---|---|---|
| `voters.csv` | `UID,PIN,Last Name,…` (9) | check-in server |
| `id_voters.csv` | `UID,Last Name,…` (8, no PIN) | ID server, Python clients
| `pins.csv` | `UID,PIN` | untrusted Python client |

The column difference matters:

- The check-in server reads *both* the voter roll and the PIN mappings from the
  single file named by `voter_list_file`, so it needs the 9-column file. A
  separate pins file would be redundant; it would not be read.
- The ID server parses positionally and treats field `[1]` as Last Name, so it
  must get the 8-column file. Handing it the PIN-bearing file silently corrupts
  name validation.

## Why the untrusted client has PINs

`client.py` reads `pins.csv`. That looks alarming, since an untrusted kiosk
should never hold voter PINs. The reason is mundane.

**This is test automation, not the protocol.** In the real flow the PIN is typed
by a person on the trusted device (`secure_client.cpp` prompts `Enter your pin
The Python client looks the PIN up only so automated runs don't block on console
input. The C++ clients read no CSV files at all; every value is entered at the
console. The trusted Python client never opens `pins.csv` either; it receives
the PIN over its socket from the untrusted client, mirroring the real handoff.

## Setup

Host-side dependencies for the harness and figure scripts:

```
pip install -r tests/requirements.txt
```

The container image installs only what the in-container Python clients need
(`tests/requirements-container.txt`, `cryptography` alone) so it stays lean.

## Running tests

`stress_test.py` is the primary driver. It brings the stack up, starts the
servers and trusted clients, then repeatedly executes an untrusted command
inside the untrusted containers, collecting per-request latency to CSV.

To run any other scenario, override `--untrusted-cmd` rather than driving a
client script by hand. The harness handles orchestration, timing, and metrics:

```
python3 tests/stress_test.py \
  --untrusted-cmd "python ../../client_misbehaviour.py testing_client_config.i
```

Rebuild the image after editing any client script (`--build-first`); containers
run the baked copy, not your working tree.

### Misbehaviour modes

`client_misbehaviour.py --mode` covers the attack scenarios:
`honest`, `simple-replay`, `stale-replay`, `delayed-replay`,
`ticket-substitution`, `race-condition`, `cross-identity`, `tampered-body`,
`spoofed-client-id`, `withhold-token`.

Contention test beds: `attacker-reaction-under-load`,
`honest-latency-under-attack`, `fleet-contention`. In `fleet-contention` every
kiosk runs the same command and branches on its own client id, so one real
container misbehaves while the rest behave honestly. That is closer to a real
precinct than simulating attacks from a single process. `--attack-mode mixed`
picks a random attack per request and tags each sample so results can be split
by attack afterwards.

## Known characteristics

The check-in service runs a single `io_context` thread and re-arms its accept
loop inside the handshake handler, so connection admission is serial. Beyond a
handful of concurrent full-rate clients, new connections are refused. This is a
property of the implementation, not a harness defect. Measurement runs are pac
(`--walk-delay`, `--untrusted-delay`) to reflect voters arriving at human speed
rather than to hide it.

The linearization point for check-in (find voter → verify eligible → mark
pending) is not lock-protected; the single service thread is what currently
serializes it. Multi-threading the service would reintroduce the double-check-
race that `--mode race-condition` exercises.

## Configuration filenames

| consumer | file |
|---|---|
| C++ servers and clients | `config.ini` |
| Python clients | `testing_client_config.ini` |

Both deployment paths install the C++ config as `config.ini` in each component's
working directory: `render_and_copy_config.yml` docker-cp's it there, and the
compose path ships one per component directory.

`config.ini` is *not* the binaries' built-in default — those are per-binary
(`server_config.ini`, `id_server_config.ini`, `client_config.ini`, set in
`apps/*.cpp`). So the config name is always passed explicitly, which is why
`stress_test.py` launches `../../server config.ini`.
