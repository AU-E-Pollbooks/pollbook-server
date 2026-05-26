#!/usr/bin/env python3
import argparse, math, statistics, re, sys, json, ast, runpy
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

def dbg(*a): print("[DBG]", *a)

def percentile(xs: List[float], p: float) -> float:
    if not xs: return float("nan")
    ys = sorted(xs)
    if p <= 0:  return ys[0]
    if p >= 100: return ys[-1]
    r = (p/100)*(len(ys)-1); lo = int(r); hi = math.ceil(r)
    if lo == hi: return ys[lo]
    f = r - lo;  return ys[lo]*(1-f) + ys[hi]*f

def discover_units(paths: List[Path], recursive: bool) -> List[Path]:
    units: List[Path] = []
    def consider(mp: Path):
        if mp.name != "matplotlib_data.py": return
        if mp.parent.name == "metrics":
            unit = mp.parent.parent
            units.append(unit)
            dbg("found unit", {"unit": str(unit), "py": str(mp)})
    for p in paths:
        if p.is_file():
            consider(p)
        elif p.exists():
            if recursive:
                for mp in p.rglob("matplotlib_data.py"): consider(mp)
            else:
                for sub in p.iterdir():
                    mp = sub / "metrics" / "matplotlib_data.py"
                    if mp.exists(): consider(mp)
    out, seen = [], set()
    for u in sorted(map(str, units)):
        if u not in seen:
            seen.add(u); out.append(Path(u))
    dbg("units_discovered", [str(x) for x in out])
    return out

def _extract_first_dict_blob(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1: return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0: return text[start:i+1]
    return None

def load_metrics(unit_dir: Path) -> Optional[Dict]:
    pyfile = unit_dir / "metrics" / "matplotlib_data.py"
    if not pyfile.exists():
        dbg("metrics missing", str(pyfile))
        return None
    txt = pyfile.read_text()
    try:
        d = runpy.run_path(str(pyfile))
        for k in ("data","metrics","matplotlib_data","METRICS"):
            if k in d and isinstance(d[k], dict):
                return d[k]
        for vname, v in d.items():
            if isinstance(v, dict) and "config" in v and "latency" in v:
                return v
    except Exception: pass
    blob = _extract_first_dict_blob(txt)
    if not blob: return None
    try:
        j = json.loads(blob)
        if isinstance(j, dict): return j
    except Exception: pass
    blob2 = re.sub(r"\btrue\b","True",blob)
    blob2 = re.sub(r"\bfalse\b","False",blob2)
    blob2 = re.sub(r"\bnull\b","None",blob2)
    try:
        j = ast.literal_eval(blob2)
        if isinstance(j, dict): return j
    except Exception: pass
    return None

KV_RE = re.compile(r"(\w+)=([^\s]+)")
def parse_throughput(unit_dir: Path) -> Dict[str, float|int|str]:
    out: Dict[str, float|int|str] = {}
    tf = unit_dir / "throughput-summary.txt"
    if not tf.exists(): return out
    line = tf.read_text().strip()
    for m in KV_RE.finditer(line):
        k,v = m.group(1), m.group(2)
        try: out[k] = int(v)
        except ValueError:
            try: out[k] = float(v)
            except ValueError: out[k] = v
    return out

DIR_CLIENTS_RES = [
    re.compile(r"(?<!\d)(\d+)[-_ ]*clients?(?!\d)", re.IGNORECASE),
    re.compile(r"clients?[-_ ]*(\d+)", re.IGNORECASE),
]
def parse_total_clients_from_dirname(unit_dir: Path) -> Optional[int]:
    for cand in [unit_dir.name, unit_dir.parent.name]:
        for rx in DIR_CLIENTS_RES:
            m = rx.search(cand)
            if m: return int(m.group(1))
    return None

def filter_latency(lat: List[float], flags: Optional[List[bool]]) -> List[float]:
    if isinstance(flags, list) and len(flags)==len(lat):
        return [v for v,ok in zip(lat,flags) if ok]
    return lat

def _get_walk_delay_ms(j: Dict) -> float:
    paths = [
        ("latency","trusted","walk_delay_ms"),
        ("latency","walk_delay_ms"),
        ("config","walk_delay_ms"),
    ]
    for p in paths:
        cur = j; ok = True
        for k in p:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False; break
        if ok and isinstance(cur, (int, float)): return float(cur)
    return 0.0

def extract_latency_stats(j: Dict, unit_dir: Path
) -> List[Tuple[str,int,float,float,float]]:
    cfg = j.get("config", {})
    pc  = cfg.get("parallel_clients")
    uc  = cfg.get("untrusted_service_count")
    tc  = cfg.get("trusted_service_count")
    total = parse_total_clients_from_dirname(unit_dir)
    if uc is None: uc = pc if isinstance(pc,int) else total
    if tc is None:
        if isinstance(total,int) and isinstance(uc,int): tc = max(total - uc, 0)
        else: tc = pc
    out: List[Tuple[str,int,float,float,float]] = []
    walk_delay = _get_walk_delay_ms(j)

    try:
        node = j["latency"]["untrusted"]["id_service"]
        l = filter_latency(node["latency_ms"], node.get("flag"))
        if l: out.append(("Untrusted: id_service", int(uc), statistics.median(l), percentile(l,5), percentile(l,90)))
    except Exception: pass
    try:
        node = j["latency"]["untrusted"]["checkin_service"]
        l = filter_latency(node["latency_ms"], node.get("flag"))
        if l: out.append(("Untrusted: checkin_service", int(uc), statistics.median(l), percentile(l,5), percentile(l,90)))
    except Exception: pass
    try:
        node = j["latency"]["trusted"]["trusted_verify"]
        l = filter_latency(node["latency_ms"], node.get("flag"))
        if l:
            if walk_delay > 0: l = [max(0.0, float(x) - walk_delay) for x in l]
            out.append(("Trusted: trusted_verify", int(tc), statistics.median(l), percentile(l,5), percentile(l,90)))
    except Exception: pass
    return out

def extract_throughput_point(kv: Dict, unit_dir: Path, x_field: str) -> Optional[Tuple[int,float]]:
    y = None
    for k in ("cum_tps","round_tps"):
        v = kv.get(k)
        if isinstance(v,(int,float)): y = float(v); break
    if y is None or math.isnan(y): return None
    x = kv.get(x_field)
    if x is None and x_field == "parallel_clients": x = parse_total_clients_from_dirname(unit_dir)
    if isinstance(x,(int,float)): x = int(x)
    else: return None
    return (x, y)

def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_").lower()

def _title_for_label(label: str) -> str:
    """
    Map internal label to the requested figure title text.
    """
    if label.lower().startswith("trusted"):
        return "Median latency for Trusted client"
    if "checkin_service" in label:
        return "Median latency for checkin service in Untrusted client"
    if "id_service" in label:
        return "Median latency for id service in Untrusted client"
    # fallback
    return f"Median Latency for {label}"

def _plot_label_errorbars(label: str, rows: List[Tuple[int,float,float,float]]):
    if not rows: return
    rows.sort(key=lambda t: t[0])
    xs   = [r[0] for r in rows]
    med  = [r[1] for r in rows]
    p5   = [r[2] for r in rows]
    p90  = [r[3] for r in rows]
    lower = [max(0.0, m - q5)  for m, q5  in zip(med, p5)]
    upper = [max(0.0, q90 - m) for m, q90 in zip(med, p90)]
    plt.figure(figsize=(8,5))
    ax = plt.gca()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.errorbar(xs, med, yerr=[lower, upper], fmt="-o", capsize=4)
    ax.set_xlabel("Number of clients")
    ax.set_ylabel("Latency (ms)")
    ax.set_title(_title_for_label(label))
    ax.set_xticks(xs)
    ax.grid(True, linestyle="--", linewidth=0.5)
    plt.tight_layout()
    out_path = Path(f"latency_{_slug(label)}.png")
    plt.savefig(out_path, dpi=150)
    print(f"[OK] Wrote {out_path}")
    plt.close()

def plot_latency(points: Dict[str, List[Tuple[int,float,float,float]]]):
    for label, rows in sorted(points.items()):
        _plot_label_errorbars(label, rows)

def plot_throughput(pts: List[Tuple[int,float]], out_path: Path, x_field: str):
    if not pts:
        print("[WARN] no throughput data"); return
    pts.sort(key=lambda t: t[0])
    xs=[x for x,_ in pts]; ys=[y for _,y in pts]
    plt.figure(figsize=(8,5))
    ax = plt.gca()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.plot(xs, ys, marker="o", label="Throughput")
    plt.xlabel(f"Number of clients")
    plt.ylabel("Throughput (txn/s)")
    plt.title("Throughput vs Clients")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.xlim(0, 20)  # fixed x-axis range 0–20
    y_min, y_max = min(ys), max(ys)
    if y_min == y_max:
        plt.ylim(-1 if y_min == 0 else y_min*0.9, 1 if y_min == 0 else y_max*1.1)
    else:
        plt.ylim(bottom=0)
    plt.legend(); plt.tight_layout(); plt.savefig(out_path, dpi=150)
    print(f"[OK] Wrote {out_path}")
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="Roots or unit dirs containing */metrics/matplotlib_data.py")
    ap.add_argument("--recursive", action="store_true", help="Recurse to find units")
    ap.add_argument("--out-throughput", default="throughput_vs_clients.png")
    ap.add_argument("--x-throughput", default="parallel_clients",
                    choices=["parallel_clients","untrusted_service_count","trusted_service_count"])
    args = ap.parse_args()
    units = discover_units([Path(p) for p in args.paths], args.recursive)
    if not units:
        print("[ERR] no */metrics/matplotlib_data.py found", file=sys.stderr); sys.exit(2)
    lat_points: Dict[str, List[Tuple[int,float,float,float]]] = {}
    thr_points: List[Tuple[int,float]] = []
    for u in units:
        j = load_metrics(u)
        if j:
            for label, x, median, p5, p90 in extract_latency_stats(j, u):
                lat_points.setdefault(label, []).append((x, median, p5, p90))
        kv = parse_throughput(u)
        p = extract_throughput_point(kv, u, args.x_throughput)
        if p: thr_points.append(p)
    plot_latency(lat_points)
    plot_throughput(thr_points, Path(args.out_throughput), args.x_throughput)

if __name__ == "__main__":
    main()

