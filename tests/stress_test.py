#!/usr/bin/env python3
import argparse, asyncio, shlex, signal, time, datetime, tarfile, shutil, json
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

async def compose_cp(compose_dir: Path, compose_cmd: str, src: str, dest: Path) -> int:
    """
    Copy from SERVICE:PATH inside a compose service to a host path.
    Example: src="trusted-client-1:/app/metrics/trusted.csv"
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = f'{compose_cmd} cp {shlex.quote(src)} {shlex.quote(str(dest))}'
    return await sh(cmd, cwd=compose_dir)

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

# metrics logging for graphing with matplotlib at the end
def _read_latency_csv(csv_path: Path, schema: str):
    """
    schema: 'untrusted' or 'trusted'
    Returns { phase: {"latency_ms": [...], "flag": [...]} }
    """
    out = {}
    if not csv_path.exists():
        return out
    with open(csv_path, "r", encoding="utf-8") as f:
        header = f.readline()  # skip
        for line in f:
            if not line.strip():
                continue
            parts = line.rstrip("\n").split(",", 6)  # robust split
            try:
                if schema == "untrusted":
                    # ts,service,run_idx,phase,latency_ms,ok,meta_json
                    if len(parts) < 7: 
                        continue
                    _, service, run_idx, phase, lat_s, flag_s, meta = parts
                else:
                    # trusted: ts,service,phase,latency_ms,approved,meta_json
                    if len(parts) < 6:
                        continue
                    _, service, phase, lat_s, flag_s, meta = parts
                lat = float(lat_s)
                ok = flag_s.strip().lower() in ("true","1","yes")
            except Exception:
                continue
            bucket = out.setdefault(phase, {"latency_ms": [], "flag": []})
            bucket["latency_ms"].append(lat)
            bucket["flag"].append(ok)
    return out

def build_matplotlib_data(a, rounds_history, metrics_dir: Path):
    """
    Collate config, per-round throughput, and per-phase latencies into a single dict.
    """
    data = {
        "config": {
            "compose_dir": str(a.compose_dir),
            "untrusted_services": a.untrusted,
            "trusted_services": a.trusted,
            "servers": a.servers,
            "parallel_clients": a.parallel,                 # total concurrency slots
            "untrusted_service_count": len(a.untrusted),
            "trusted_service_count": len(a.trusted),
            "runs_per_round": a.runs,
            "walk_delay_s": a.walk_delay,
            "untrusted_delay_s": a.untrusted_delay,
            "fresh": bool(getattr(a, "fresh", False)),
        },
        "rounds": rounds_history,  # list of dicts we will append per round
        "latency": {
            "untrusted": _read_latency_csv(metrics_dir / "untrusted_latencies.csv", "untrusted"),
            "trusted":   _read_latency_csv(metrics_dir / "trusted_latencies.csv",   "trusted"),
        },
    }
    return data

def _concat_csv(files, dest: Path, header: str):
    dest.parent.mkdir(parents=True, exist_ok=True)
    wrote_header = False
    with open(dest, "w", encoding="utf-8", newline="") as out:
        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    first = f.readline()
                    if not wrote_header:
                        out.write(header + "\n")
                        wrote_header = True
                    for line in f:
                        if line.strip():
                            out.write(line if line.endswith("\n") else line + "\n")
            except FileNotFoundError:
                continue

def merge_container_metrics(a):
    """
    Gather any per-service container CSVs into central files:
      logs/metrics/untrusted_latencies.csv
      logs/metrics/trusted_latencies.csv
    """
    metrics_dir = a.log_dir / "metrics"
    # collect trusted
    trusted_files = []
    for svc in a.trusted:
        p = a.log_dir / svc / "container-metrics"
        # trusted client writes one file; adjust if you write more
        for name in ("trusted.csv",):
            fp = p / name
            if fp.exists():
                trusted_files.append(fp)
    # collect untrusted (note: nothing to copy when --fresh unless you bind-mount)
    untrusted_files = []
    for svc in a.untrusted:
        p = a.log_dir / svc / "container-metrics"
        for name in ("untrusted.csv",):
            fp = p / name
            if fp.exists():
                untrusted_files.append(fp)

    # write central CSVs (keep header the readers expect)
    _concat_csv(untrusted_files, metrics_dir / "untrusted_latencies.csv",
                "ts,service,run_idx,phase,latency_ms,ok,meta_json")
    _concat_csv(trusted_files, metrics_dir / "trusted_latencies.csv",
                "ts,service,phase,latency_ms,approved,meta_json")

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
    # measure wall time for the whole round
    round_t0 = time.perf_counter()

    # divide runs evenly across untrusted services
    per = [a.runs // len(a.untrusted) for _ in a.untrusted]
    for i in range(a.runs % len(a.untrusted)):
        per[i] += 1

    per_service_parallel = max(1, a.parallel // max(1, len(a.untrusted)))
    semaphores = {svc: asyncio.Semaphore(per_service_parallel) for svc in a.untrusted}
    tasks = []
    idx = 1
    # inside run_untrusted_round(a)
    for svc, n in zip(a.untrusted, per):
        svc_dir = (a.log_dir / svc)
        svc_dir.mkdir(parents=True, exist_ok=True)
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
                        await asyncio.sleep(a.walk_delay)  # human walk
                    return res
            tasks.append(asyncio.create_task(one()))
            idx += 1
            if a.untrusted_delay > 0:
                await asyncio.sleep(a.untrusted_delay)  # optional pre-launch throttle

    results = await asyncio.gather(*tasks)

    # round stats
    ok = sum(1 for r in results if r["rc"] == 0)
    total = len(results)
    round_sec = max(1e-9, time.perf_counter() - round_t0)
    tps = ok / round_sec

    print("==== ROUND REPORT ====")
    print(f"total={total} ok={ok} ok%={round(100*ok/total,2) if total else 0.0}")
    print(f"throughput: {tps:.2f} OK/s  (round wall={round_sec:.2f}s)")
    print("======================")
    return {"results": results, "round_ok": ok, "round_total": total, "round_sec": round_sec}

# ---------- main flow ----------
async def main_async(a):
    # Bring up all containers so we can exec into them
        # Build once up-front if requested
    if getattr(a, "build_first", False):
        all_services = list(dict.fromkeys(a.servers + a.trusted + a.untrusted))
        await compose_build(a.compose_dir, a.compose_cmd, all_services)

    await compose_up(a.compose_dir, a.compose_cmd, a.servers + a.trusted + a.untrusted)

    # Start server processes (checkin + id)
    # Start servers (log to logs/<service>/server.log)
    server_cmds = {"checkin": a.checkin_cmd, "dummy-id": a.id_cmd}
    server_procs_tasks = []
    for svc, cmd in server_cmds.items():
        logp = service_dir(a.log_dir, svc) / "server.log"
        print(f"[server] starting {svc}: `{cmd}` -> {logp}")
        proc, pump = await start_forever(a.compose_dir, a.compose_cmd, svc, cmd, logp)
        server_procs_tasks.append((proc, pump))

    # Give servers time to bind/listen before trusted clients connect
    # (avoids ConnectionRefusedError when trusted fetches checkin pubkey)
    await asyncio.sleep(3.0)

    # Start trusted TCP servers
    trusted_procs_tasks = []
    for svc in a.trusted:
        logp = service_dir(a.log_dir, svc) / "trusted.log"
        print(f"[trusted] starting {svc}: `{a.trusted_cmd}` -> {logp}")
        proc, pump = await start_forever(a.compose_dir, a.compose_cmd, svc, a.trusted_cmd, logp)
        trusted_procs_tasks.append((proc, pump))

    if a.watch_logs:
        await start_watch_logs(a.compose_dir, a.compose_cmd)
    

    # cumulative counters
    test_t0 = time.perf_counter()
    cum_ok = 0
    cum_total = 0
    rounds_history = []

    try:
        rounds_left = None if a.until_interrupt else max(1, a.rounds)
        round_idx = 1
        while True:
            print(f"[orchestrator] ROUND {round_idx}: {a.runs} untrusted execs across {a.untrusted} (parallel={a.parallel})")
            stats = await run_untrusted_round(a)
            cum_ok += stats["round_ok"]
            cum_total += stats["round_total"]

            # cumulative throughput
            elapsed = max(1e-9, time.perf_counter() - test_t0)
            cum_tps = cum_ok / elapsed
            ok_rate = (100 * cum_ok / cum_total) if cum_total else 0.0
            print(f"---- CUMULATIVE ----")
            print(f"runs={cum_total} ok={cum_ok} ok%={ok_rate:.2f}  elapsed={elapsed:.2f}s  throughput={cum_tps:.2f} OK/s")
            print("--------------------")
            # write/update a small summary file
            summary_path = (a.log_dir / "throughput-summary.txt")
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(
                    f"round={round_idx} "
                    f"round_ok={stats['round_ok']} round_total={stats['round_total']} "
                    f"round_sec={stats['round_sec']:.3f} round_tps={stats['round_ok']/max(1e-9,stats['round_sec']):.3f} "
                    f"cum_ok={cum_ok} cum_total={cum_total} "
                    f"elapsed={elapsed:.3f} cum_tps={cum_tps:.3f} "
                    f"parallel_clients={a.parallel} "
                    f"untrusted_service_count={len(a.untrusted)}\n"
                )

            # matplotlib-friendly row for this round
            rounds_history.append({
                "round_idx": round_idx,
                "ts": _ts_compact(),
                "round_ok": stats["round_ok"],
                "round_total": stats["round_total"],
                "round_sec": stats["round_sec"],
                "round_tps": stats["round_ok"] / max(1e-9, stats["round_sec"]),
                "cum_ok": cum_ok,
                "cum_total": cum_total,
                "elapsed_sec": elapsed,
                "cum_tps": cum_tps,
                "parallel_clients": a.parallel,
                "untrusted_service_count": len(a.untrusted),
            })


            round_idx += 1
            if not a.until_interrupt and round_idx > rounds_left:
                break
            if a.pause_between > 0:
                await asyncio.sleep(a.pause_between)
    finally:
        print("[orchestrator] interrupted — saving logs before shutdown…")
        if a.watch_logs:
            await stop_watch_logs()

        # terminate long-running execs and wait + flush pumps
        for proc, pump in server_procs_tasks + trusted_procs_tasks:
            try: proc.terminate()
            except Exception: pass
        for proc, pump in server_procs_tasks + trusted_procs_tasks:
            try: await proc.wait()
            except Exception: pass
            try: await pump
            except Exception: pass
        # final cumulative line
        elapsed_total = max(1e-9, time.perf_counter() - test_t0)
        final_tps = cum_ok / elapsed_total
        print(f"[final] runs={cum_total} ok={cum_ok} ok%={(100*cum_ok/max(1,cum_total)):.2f} "
            f"elapsed={elapsed_total:.2f}s throughput={final_tps:.2f} OK/s")

        # archive logs unless disabled
        if not a.no_artifacts:
            try:
                for svc in a.trusted:
                    dst_dir = service_dir(a.log_dir, svc) / "container-metrics"
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    # if it’s a file, composing cp into a dir puts file inside that dir
                    rc = await compose_cp(a.compose_dir, a.compose_cmd,
                                        f"{svc}:{a.trusted_metrics_path}",
                                        dst_dir)
                    if rc != 0:
                        print(f"[warn] could not copy trusted CSV from {svc}:{a.trusted_metrics_path}")

                if getattr(exec_once, "_args", None) and exec_once._args.fresh:
                    print("[warn] --fresh is enabled: untrusted runs are ephemeral; cannot docker cp their CSVs after exit. "
                        "Prefer printing latencies to stdout (already parsed) or bind-mount a volume for persistence.")
                else:
                    for svc in a.untrusted:
                        dst_dir = service_dir(a.log_dir, svc) / "container-metrics"
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        rc = await compose_cp(a.compose_dir, a.compose_cmd,
                                            f"{svc}:{a.untrusted_metrics_path}",
                                            dst_dir)
                        if rc != 0:
                            print(f"[warn] could not copy untrusted CSV from {svc}:{a.untrusted_metrics_path}")
                archive_path = create_tar_gz(a.log_dir, Path("artifacts"))
                print(f"[orchestrator] logs archived -> {archive_path}")

                merge_container_metrics(a)
                metrics_dir = a.log_dir / "metrics"
                matplot_json = metrics_dir / "matplotlib_data.json"
                matplot_py   = metrics_dir / "matplotlib_data.py"

                mat_data = build_matplotlib_data(a, rounds_history, metrics_dir)
                matplot_json.parent.mkdir(parents=True, exist_ok=True)
                with open(matplot_json, "w", encoding="utf-8") as f:
                    json.dump(mat_data, f, ensure_ascii=False, indent=2)

                # Optional: also emit a .py you can `import` in LaTeX pipelines
                with open(matplot_py, "w", encoding="utf-8") as f:
                    f.write("# Auto-generated metrics bundle for matplotlib consumers\n")
                    f.write("MATPLOTLIB_DATA = ")
                    json.dump(mat_data, f, ensure_ascii=False, indent=2)
                    f.write("\n")

                print(f"[orchestrator] matplotlib bundle -> {matplot_json}  (+ {matplot_py})")

            except Exception as e:
                print(f"[orchestrator] ERROR archiving logs: {e}")



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
    ap.add_argument("--trusted-metrics-path", type=str, default="/app/metrics/trusted.csv",
                help="Path inside trusted containers where their latency CSV is written")
    ap.add_argument("--untrusted-metrics-path", type=str, default="/app/metrics/untrusted.csv",
                    help="Path inside untrusted containers where their latency CSV is written")
    # logs
    ap.add_argument("--log-dir", type=Path, default=Path("logs"),
                help="Directory to write per-service logs")
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

