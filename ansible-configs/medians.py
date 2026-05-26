#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from statistics import median
from collections import defaultdict

def parse_args():
    ap = argparse.ArgumentParser(
        description="Quick median latency summary from merged metrics CSVs."
    )
    ap.add_argument(
        "--metrics-dir",
        type=Path,
        default=Path("logs/metrics"),
        help="Directory containing untrusted_latencies.csv and trusted_latencies.csv",
    )
    ap.add_argument(
        "--kind",
        choices=["untrusted", "trusted", "both"],
        default="both",
        help="Which CSV(s) to read",
    )
    ap.add_argument(
        "--phase",
        default=None,
        help="Optional phase filter (exact match); e.g., id_service, checkin_service, trusted_verify",
    )
    ap.add_argument(
        "--service",
        default=None,
        help="Optional service name filter (exact match)",
    )
    ap.add_argument(
        "--ok-only",
        action="store_true",
        help="Only include rows where ok/approved is true",
    )
    return ap.parse_args()

def read_untrusted_csv(path: Path, phase_filter: str | None, svc_filter: str | None, ok_only: bool):
    """
    untrusted_latencies.csv schema:
      ts,service,run_idx,phase,latency_ms,ok,meta_json
    """
    per_phase = defaultdict(list)
    if not path.exists():
        return per_phase

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            phase = row.get("phase", "").strip()
            svc   = row.get("service", "").strip()
            if phase_filter and phase != phase_filter:
                continue
            if svc_filter and svc != svc_filter:
                continue

            flag = row.get("ok", "").strip().lower() in ("1", "true", "yes")
            if ok_only and not flag:
                continue

            try:
                lat = float(row.get("latency_ms", "nan"))
            except ValueError:
                continue
            per_phase[phase].append(lat)
    return per_phase

def read_trusted_csv(path: Path, phase_filter: str | None, svc_filter: str | None, ok_only: bool):
    """
    trusted_latencies.csv schema:
      ts,service,phase,latency_ms,approved,meta_json
    """
    per_phase = defaultdict(list)
    if not path.exists():
        return per_phase

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            phase = row.get("phase", "").strip()
            svc   = row.get("service", "").strip()
            if phase_filter and phase != phase_filter:
                continue
            if svc_filter and svc != svc_filter:
                continue

            flag = row.get("approved", "").strip().lower() in ("1", "true", "yes")
            if ok_only and not flag:
                continue

            try:
                lat = float(row.get("latency_ms", "nan"))
            except ValueError:
                continue
            per_phase[phase].append(lat)
    return per_phase

def print_summary(title: str, per_phase: dict[str, list[float]]):
    if not per_phase:
        print(f"{title}: (no data)")
        return
    print(f"\n=== {title} ===")
    for phase, vals in sorted(per_phase.items()):
        if not vals:
            continue
        vals_sorted = sorted(vals)
        med = median(vals_sorted)
        n = len(vals_sorted)
        p10 = vals_sorted[int(0.10 * (n - 1))]
        p90 = vals_sorted[int(0.90 * (n - 1))]
        print(f"phase={phase:20s} n={n:5d} median={med:8.3f} ms  p10={p10:8.3f} ms  p90={p90:8.3f} ms")

def main():
    args = parse_args()
    metrics_dir = args.metrics_dir

    if args.kind in ("untrusted", "both"):
        u_path = metrics_dir / "untrusted_latencies.csv"
        u_data = read_untrusted_csv(u_path, args.phase, args.service, args.ok_only)
        print_summary("UNTRUSTED", u_data)

    if args.kind in ("trusted", "both"):
        t_path = metrics_dir / "trusted_latencies.csv"
        t_data = read_trusted_csv(t_path, args.phase, args.service, args.ok_only)
        print_summary("TRUSTED", t_data)

if __name__ == "__main__":
    main()

