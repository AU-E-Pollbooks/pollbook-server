# E-Pollbook Ansible Automation

This repository (`ansible-configs`) contains all the playbooks, templates, and helper tasks to **deploy, iterate on, and reconfigure** the E-Pollbook system with Docker and Ansible.
It supports one-command deployment, **live rebuild/restart on backend code changes**, and quick switching between test configurations.

> **Network note:** the Docker network is `172.16.0.0/16` (set in `compose.yaml`).
> If that conflicts with your environment, update the subnet in the Compose file and the IPs under `host_vars/` accordingly.

---

## Directory Structure

`ansible-configs/`

```
├── README.md                     # ← You are here
├── host_vars/                    # Per-node configuration (YAML)
├── output/                       # Rendered config files (generated)
├── templates/                    # Jinja2 templates for all config INI files
├── full_deploy.yml               # Build keys, compose up, start all binaries
├── render_and_copy_config.yml    # Render *.ini and copy into running containers
├── rebuild_restart.yml           # Rebuild inside containers & restart binaries
├── restart_binaries.yml          # Restart binaries only (no rebuild)
└── setup_watcher.yml             # Install/enable background watchers (one time)
```

> The code-watcher script lives in the repo root at `../tools/epollbook-watch.sh` and is started for you by `setup_watcher.yml`.

---

## Prerequisites

* Docker & Docker Compose v2
* Python 3.x
* Ansible (`pip install --user ansible`)
* `inotify-tools` (for code watching)
* Your user is in the `docker` group (log out/in after adding)

Example (Ubuntu):

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin python3-pip inotify-tools
pip install --user ansible
sudo usermod -aG docker "$USER"
# log out/in or: newgrp docker
```

---

## Workflow Overview

1. **Deploy containers** with `full_deploy.yml` (build images, start the stack, launch the correct binaries).
2. **Enable live-reload for backend code** using `setup_watcher.yml`.
   When you edit C++ in `src/`, `include/`, `apps/` (or `CMakeLists.txt`), your changes are synced into containers and the system is **rebuilt + restarted automatically**.
3. **Change runtime configs** by editing files under `host_vars/` and running `render_and_copy_config.yml` (then `restart_binaries.yml` if you didn’t rebuild).

---

## How to Use

### 1) Clone the repo

```bash
git clone <your-private-git-url> pollbook-server
cd pollbook-server/ansible-configs
```

---

### 2) Initial Deployment (first time)

Build and start the full environment (check-in server, ID server, 4 clients) and launch the right binaries in each container:

```bash
ansible-playbook full_deploy.yml
```

This will:

1. Make the key/cert script executable and run it (creates CA and certs; distributes them).
2. `docker compose down` (best-effort clean up).
3. `docker compose up -d` (build & start all containers).
4. Start the correct **binary** in each container:

   * check-in server → `server`
   * ID server → `id_server`
   * clients → `client`
   * secure clients → `secure_client`

---

### 3) Enable live code watching (one time)

Installs two **systemd user services**:

* `epollbook-compose-watch` – runs `docker compose watch` so host edits are synced into containers.
* `epollbook-watcher` – watches **only backend code** (`src/`, `include/`, `apps/`, `CMakeLists.txt`) and runs `rebuild_restart.yml` when changes are detected.

```bash
ansible-playbook setup_watcher.yml
systemctl --user status epollbook-compose-watch --no-pager
systemctl --user status epollbook-watcher --no-pager
```

Tail watcher logs while you edit code:

```bash
journalctl --user -u epollbook-watcher -f
```

> Debounce is 2s by default. You can change it in `../tools/epollbook-watch.sh` or by exporting `DEBOUNCE=3` and restarting the service.

---

### 4) Change Configuration (any time)

When you need a different test scenario:

1. Edit the relevant file(s) in `host_vars/`
   e.g. `host_vars/checkin_server.yml`, `host_vars/id_server.yml`, `host_vars/client0.yml`, …

2. Render and copy configs into the running containers:

```bash
ansible-playbook render_and_copy_config.yml
```

3. If you changed only configs (not code), restart the binaries:

```bash
ansible-playbook restart_binaries.yml
```

**What happens:**

* Templates in `templates/*.ini.j2` are rendered into `output/`.
* The resulting `config.ini` files are copied into each container at:

  ```
  /epollbook/build/apps/docker-test-deployment/<component>/config.ini
  ```
* `restart_binaries.yml` restarts the running processes so changes take effect.

---

## Notes

* All rendered config files are written to `output/` (generated).
* The code watcher **only** tracks backend code (`src/`, `include/`, `apps/`, `CMakeLists.txt`). Changes to Ansible or templates do **not** trigger a rebuild (use the playbooks above).
* If you add/remove containers, update `compose.yaml` and the lists used in:

  * `full_deploy.yml`, `rebuild_restart.yml`, `restart_binaries.yml`
  * Any relevant template/host var files
* Use `docker compose down -v` to clean volumes if you want to reset completely.

### Handy commands

```bash
# Bring everything up from scratch
ansible-playbook full_deploy.yml

# Manually trigger a rebuild & restart (watcher usually does this for code changes)
ansible-playbook rebuild_restart.yml

# Push new configs and restart binaries
ansible-playbook render_and_copy_config.yml
ansible-playbook restart_binaries.yml

# Watcher & compose-watch logs
journalctl --user -u epollbook-watcher -f
journalctl --user -u epollbook-compose-watch -f

# Stop/disable background watchers if needed
systemctl --user stop epollbook-watcher epollbook-compose-watch
systemctl --user disable epollbook-watcher epollbook-compose-watch
```

### Troubleshooting

* **Edits aren’t reflected in containers**

  * Ensure compose watch is running:
    `systemctl --user status epollbook-compose-watch --no-pager`
* **Watcher complains about a missing playbook**

  * We standardized on `rebuild_restart.yml`. Confirm it exists and `../tools/epollbook-watch.sh` points to it.
* **Permission errors with Docker**

  * Add your user to the `docker` group and re-login:

    ```bash
    sudo usermod -aG docker "$USER"
    newgrp docker
    ```
* **`inotifywait` not found**

  * Install `inotify-tools`.

---

That’s it—clone → **`full_deploy.yml`** → **`setup_watcher.yml`** → edit backend code and see containers rebuild automatically → swap configs with **`render_and_copy_config.yml`**.

