#!/usr/bin/env python3
import argparse, asyncio, shlex, signal, time
from pathlib import Path
from typing import List, Optional

# ---------- shell helpers ----------
async def sh_capture(cmd: str, cwd: Optional[Path] = None, timeout: Optional[float] = None):
    p = await asyncio.create_subprocess_shell(
        cmd, cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try: p.send_signal(signal.SIGINT)
        except ProcessLookupError: pass
        return 124, b"", b"TIMEOUT"
    return p.returncode, out, err

async def sh(cmd: str, cwd: Optional[Path] = None):
    p = await asyncio.create_subprocess_shell(cmd, cwd=str(cwd) if cwd else None)
    return await p.wait()

async def compose_up(compose_dir: Path, compose_cmd: str, services: List[str]):
    if services:
        print(f"[up] {services}")
        rc = await sh(f"{compose_cmd} up -d " + " ".join(services), cwd=compose_dir)
        if rc != 0: raise RuntimeError(f"compose up failed for {services}")

async def compose_down(compose_dir: Path, compose_cmd: str):
    print("[down] stopping project (volumes, orphans)…")
    await sh(f"{compose_cmd} down --remove-orphans -v", cwd=compose_dir)

# ---------- log watch ----------
_watch_proc = None
_watch_task = None
async def start_watch_logs(compose_dir: Path, compose_cmd: str):
    global _watch_proc, _watch_task
    _watch_proc = await asyncio.create_subprocess_shell(
        f"{compose_cmd} logs -f --tail=20",
        cwd=str(compose_dir),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    async def pump():
        while True:
            line = await _watch_proc.stdout.readline()
            if not line: break
            print("[logs]", line.decode(errors="replace").rstrip())
    _watch_task = asyncio.create_task(pump())


# ---------- file logging & archiving ----------
def _ts_compact() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def service_dir(base: Path, service: str) -> Path:
    d = base / service
    d.mkdir(parents=True, exist_ok=True)
    return d

async def append_log(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(text)

async def start_forever(compose_dir: Path, compose_cmd: str, service: str, cmd: str, log_path: Path):
    """Exec a long-running process; stream its stdout/stderr to a log file."""
    full = f'{compose_cmd} exec -T {shlex.quote(service)} sh -lc {shlex.quote(cmd)}'
    proc = await asyncio.create_subprocess_shell(
        full, cwd=str(compose_dir),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    async def pump():
        await append_log(log_path, f"\n===== START {service} cmd=`{cmd}` at {_ts_compact()} =====\n")
        while True:
            line = await proc.stdout.readline()
            if not line: break
            await append_log(log_path, line.decode(errors="replace"))
        await append_log(log_path, f"\n===== STOP  {service} at {_ts_compact()} rc={proc.returncode} =====\n")
    task = asyncio.create_task(pump())
    return proc, task

def create_tar_gz(src_dir: Path, out_dir: Path, base_name: str = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = base_name or f"logs-{_ts_compact()}"
    archive_path = out_dir / f"{base}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(str(src_dir), arcname=base)
    return archive_path


async def stop_watch_logs():
    global _watch_proc, _watch_task
    if _watch_proc and _watch_proc.returncode is None:
        _watch_proc.terminate()
        try: await _watch_proc.wait()
        except Exception: pass
    if _watch_task:
        try: await _watch_task
        except Exception: pass
    _watch_proc = _watch_task = None


# replace exec_once with this version
async def exec_once(compose_dir: Path, compose_cmd: str, service: str, cmd: str,
                    timeout: float, idx: int, role: str, log_path: Path):
    a = getattr(exec_once, "_args", None)
    if a and a.fresh:
        full = f'{compose_cmd} run --rm {shlex.quote(service)} {cmd}'
    else:
        full = f'{compose_cmd} exec -T {shlex.quote(service)} {cmd}'

    t0 = time.time()
    rc, out_b, err_b = await sh_capture(full, cwd=compose_dir, timeout=timeout)
    elapsed_ms = int((time.time() - t0) * 1000)
    out = out_b.decode(errors="replace")
    err = err_b.decode(errors="replace")

    print(f"[{role}][{service}][{idx}] rc={rc} elapsed_ms={elapsed_ms}")
    if rc != 0 and err.strip():
        print(f"[{role}][{service}][{idx}] stderr: {err.strip()[:300]}")

    header = f"===== {role.upper()} service={service} run={idx} at {_ts_compact()} rc={rc} elapsed_ms={elapsed_ms} =====\n"
    body = out + ("\n[stderr]\n" + err if err.strip() else "") + "\n"
    await append_log(log_path, header + body)
    return {"svc": service, "idx": idx, "rc": rc, "elapsed_ms": elapsed_ms, "stdout": out, "stderr": err}

async def compose_build(compose_dir: Path, compose_cmd: str, services: List[str]):
    if services:
        print(f"[build] (once) {' '.join(services)}")
        rc = await sh(f"{compose_cmd} build --pull " + " ".join(services), cwd=compose_dir)
        if rc != 0:
            raise RuntimeError("compose build failed")

async def run_untrusted_round(a):
    # divide runs evenly across untrusted services
    per = [a.runs // len(a.untrusted) for _ in a.untrusted]
    for i in range(a.runs % len(a.untrusted)):
        per[i] += 1

    per_service_parallel = max(1, a.parallel // max(1, len(a.untrusted)))
    semaphores = {svc: asyncio.Semaphore(per_service_parallel) for svc in a.untrusted}
    tasks = []
    idx = 1
    for svc, n in zip(a.untrusted, per):
        svc_dir = service_dir(a.log_dir, svc)
        for _ in range(n):
            run_path = svc_dir / f"run-{idx:04d}.log"
            async def one(svc_=svc, idx_=idx, log_path_=run_path):
                async with semaphores[svc_]:
                    res = await exec_once(
                        a.compose_dir, a.compose_cmd,
                        svc_, a.untrusted_cmd,
                        a.timeout_per_run, idx_, "untrusted",
                        log_path_
                    )
                    if a.walk_delay > 0:
                        await asyncio.sleep(a.walk_delay)
                    return res
            tasks.append(asyncio.create_task(one()))
            idx += 1
            if a.untrusted_delay > 0:
                await asyncio.sleep(a.untrusted_delay)

    results = await asyncio.gather(*tasks)
    ok = sum(1 for r in results if r["rc"] == 0)
    print("==== ROUND REPORT ====")
    print(f"total={len(results)} ok={ok} ok%={round(100*ok/len(results),2) if results else 0.0}")
    print("======================")
    return results

# ---------- main flow ----------
async def main_async(a):
    # Bring up all containers so we can exec into them
        # Build once up-front if requested
    if getattr(a, "build_first", False):
        all_services = list(dict.fromkeys(a.servers + a.trusted + a.untrusted))  
        await compose_build(a.compose_dir, a.compose_cmd, all_services)

    await compose_up(a.compose_dir, a.compose_cmd, a.servers + a.trusted + a.untrusted)

    # Start server processes (checkin + id)
    server_cmds = {
        "checkin": a.checkin_cmd,
        "dummy-id": a.id_cmd,
    }
    server_procs = []
    for svc, cmd in server_cmds.items():
        print(f"[server] starting {svc}: `{cmd}`")
        server_procs.append(await start_forever(a.compose_dir, a.compose_cmd, svc, cmd))

    # Start trusted TCP servers
    trusted_procs = []
    for svc in a.trusted:
        print(f"[trusted] starting {svc}: `{a.trusted_cmd}`")
        trusted_procs.append(await start_forever(a.compose_dir, a.compose_cmd, svc, a.trusted_cmd))

    if a.watch_logs:
        await start_watch_logs(a.compose_dir, a.compose_cmd)
    
    try:
        rounds_left = None if a.until_interrupt else max(1, a.rounds)
        round_idx = 1
        while True:
            print(f"[orchestrator] ROUND {round_idx}: {a.runs} untrusted execs across {a.untrusted} (parallel={a.parallel})")
            await run_untrusted_round(a)
            round_idx += 1
            if not a.until_interrupt and round_idx > rounds_left:
                break
            if a.pause_between > 0:
                await asyncio.sleep(a.pause_between)
    finally:
        print("[orchestrator] interrupted — saving logs before shutdown…")

        if a.watch_logs:
            await stop_watch_logs()
        # terminate long-running execs and their pump tasks
        for proc, pump in server_procs_tasks + trusted_procs_tasks:
            try:
                proc.terminate()
            except Exception:
                pass
        for proc, pump in server_procs_tasks + trusted_procs_tasks:
            try:
                await proc.wait()
            except Exception:
                pass
            try:
                await pump
            except Exception:
                pass

        # archive logs unless disabled
        if not a.no_artifacts:
            artifact_dir = Path("artifacts")
            artifact_dir.mkdir(parents=True, exist_ok=True)
            base = artifact_dir / f"logs-{_ts_compact()}"
            archive_path = shutil.make_archive(str(base), "gztar", root_dir=a.log_dir)
            print(f"[orchestrator] logs archived -> {archive_path}")

# ---------- args ----------
def parse_args():
    ap = argparse.ArgumentParser("Pollbook stress harness (servers + trusted run forever; untrusted exec repeatedly)")
    ap.add_argument("--fresh", action="store_true",
    help="Run untrusted via `compose run --rm` instead of exec (new container every time)")

    ap.add_argument("--compose-dir", type=Path, default=Path("."))
    ap.add_argument("--compose-cmd", default="docker compose")
    ap.add_argument("--servers", nargs="*", default=["checkin", "dummy-id"])
    ap.add_argument("--trusted", nargs="*", default=["trusted-client-1", "trusted-client-3"])
    ap.add_argument("--untrusted", nargs="+", default=["untrusted-client-0", "untrusted-client-2"])
    # commands
    ap.add_argument("--build-first", action="store_true",
                help="docker compose build --pull (all services) once before starting")
    ap.add_argument("--untrusted-delay", type=float, default=0.0,
                help="Delay (seconds) before launching each untrusted exec")
    ap.add_argument("--rebuild-each", action="store_true",
                help="Run `docker compose build <service>` before every untrusted run (very slow)")
    ap.add_argument("--walk-delay", type=float, default=0.0,
                    help="Delay (seconds) after each untrusted run finishes to simulate walk time")
    ap.add_argument("--checkin-cmd", default="../../server server_config.ini")
    ap.add_argument("--id-cmd", default="../../id_server id_server_config.ini")
    ap.add_argument("--trusted-cmd", default="python ../../trusted_client.py testing_client_config.ini")
    ap.add_argument("--untrusted-cmd", default="python ../../client.py testing_client_config.ini")
    # artifacts store
    ap.add_argument("--artifact-format", choices=["gztar", "zip"], default="gztar")
    ap.add_argument("--artifact-name", type=str, default=None)
    ap.add_argument("--no-artifacts", action="store_true",
                help="Skip creating logs archive at the end (default: archive everything)")

    # untrusted controls
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--parallel", type=int, default=20)
    ap.add_argument("--timeout-per-run", type=float, default=60.0)
    ap.add_argument("--pause-between", type=float, default=0.0)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--until-interrupt", action="store_true")
    ap.add_argument("--watch-logs", action="store_true")
    return ap.parse_args()

def main():
    a = parse_args()
    exec_once._args = a
    def _sigint(_s,_f): raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _sigint)
    try:
        asyncio.run(main_async(a))
    except KeyboardInterrupt:
        print("\n[orchestrator] INTERRUPTED")
    finally:
        try: asyncio.run(compose_down(a.compose_dir, a.compose_cmd))
        except Exception as e: print(f"[orchestrator] cleanup failed: {e}")

if __name__ == "__main__":
    main()

